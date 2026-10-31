package authflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Realm is one Keycloak realm, reached through its admin API with a token the
// product supplies. Each product already holds admin credentials of its own (PKI's
// provisioner, CAMP's kcadmin, QryptoScan's service client), so this takes a token
// function rather than credentials of its own. CAMP and QryptoScan have one realm;
// PKI builds a Realm per tenant.
type Realm struct {
	BaseURL  string // Keycloak as the product reaches it, e.g. http://pki-iam:8080
	Name     string
	ClientID string // the public client the portal signs in with (direct grant)
	HTTP     *http.Client
	Token    func(ctx context.Context) (string, error)
}

// User is the part of a Keycloak user the flows need.
type User struct {
	ID              string
	Username        string
	Email           string
	Federated       bool   // password lives in a directory or an identity provider
	Provider        string // what to call that place in an email
	RequiredActions []string
}

// PolicyError is Keycloak refusing a password under the realm's password policy.
// Reason is Keycloak's own sentence ("Invalid password: must contain at least 1
// special characters."), shown to the person so they know what to change.
type PolicyError struct{ Reason string }

func (e *PolicyError) Error() string { return e.Reason }

// Check is the outcome of trying a password (and code) at the token endpoint.
type Check int

const (
	// CheckInvalid: wrong password, or a code was needed and missing or wrong.
	// Keycloak's answer is the same for both, deliberately.
	CheckInvalid Check = iota
	// CheckOK: the password (and code) are right and nothing is pending.
	CheckOK
	// CheckChangeRequired: the password is right but a required action — a
	// temporary password's forced change — blocks the sign-in.
	CheckChangeRequired
)

const actionUpdatePassword = "UPDATE_PASSWORD"

func (r Realm) client() *http.Client {
	if r.HTTP != nil {
		return r.HTTP
	}
	return &http.Client{Timeout: 20 * time.Second}
}

// admin calls the realm's admin API. path is relative to /admin/realms/{name}.
func (r Realm) admin(ctx context.Context, method, path string, body any) (int, []byte, error) {
	tok, err := r.Token(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("keycloak admin token: %w", err)
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method,
		strings.TrimRight(r.BaseURL, "/")+"/admin/realms/"+url.PathEscape(r.Name)+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.client().Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, out, nil
}

func (r Realm) adminOK(ctx context.Context, method, path string, body any) ([]byte, error) {
	code, out, err := r.admin(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	if code/100 != 2 {
		return nil, fmt.Errorf("keycloak %s %s: %d %s", method, path, code, firstLine(out))
	}
	return out, nil
}

type kcUser struct {
	ID              string   `json:"id"`
	Username        string   `json:"username"`
	Email           string   `json:"email"`
	FederationLink  string   `json:"federationLink"`
	RequiredActions []string `json:"requiredActions"`
}

// FindUser finds the account someone signs in as — by exact username, then by exact
// email. Not found is (User{}, false, nil): callers turn that into the same answer
// as found, so the response never says whether an account exists.
func (r Realm) FindUser(ctx context.Context, login string) (User, bool, error) {
	login = strings.TrimSpace(login)
	if login == "" {
		return User{}, false, nil
	}
	for _, q := range []string{"username", "email"} {
		out, err := r.adminOK(ctx, http.MethodGet, "/users?exact=true&"+q+"="+url.QueryEscape(login), nil)
		if err != nil {
			return User{}, false, err
		}
		var us []kcUser
		if err := json.Unmarshal(out, &us); err != nil {
			return User{}, false, err
		}
		if len(us) > 0 {
			u, err := r.complete(ctx, us[0])
			return u, err == nil, err
		}
	}
	return User{}, false, nil
}

// UserByID loads one user by id.
func (r Realm) UserByID(ctx context.Context, id string) (User, error) {
	out, err := r.adminOK(ctx, http.MethodGet, "/users/"+url.PathEscape(id), nil)
	if err != nil {
		return User{}, err
	}
	var u kcUser
	if err := json.Unmarshal(out, &u); err != nil {
		return User{}, err
	}
	return r.complete(ctx, u)
}

// complete works out whether the account's password lives somewhere else: an LDAP
// or AD directory (federationLink) or an identity provider it signs in through.
func (r Realm) complete(ctx context.Context, k kcUser) (User, error) {
	u := User{ID: k.ID, Username: k.Username, Email: k.Email, RequiredActions: k.RequiredActions}
	if k.FederationLink != "" {
		u.Federated, u.Provider = true, "your organisation's directory"
		return u, nil
	}
	out, err := r.adminOK(ctx, http.MethodGet, "/users/"+url.PathEscape(k.ID)+"/federated-identity", nil)
	if err != nil {
		return User{}, err
	}
	var links []struct {
		IdentityProvider string `json:"identityProvider"`
	}
	_ = json.Unmarshal(out, &links)
	if len(links) > 0 {
		u.Federated, u.Provider = true, providerName(links[0].IdentityProvider)
	}
	return u, nil
}

func providerName(alias string) string {
	switch strings.ToLower(alias) {
	case "github":
		return "GitHub"
	case "gitlab":
		return "GitLab"
	case "google":
		return "Google"
	case "microsoft", "azure", "entra":
		return "Microsoft"
	}
	if alias == "" {
		return "your identity provider"
	}
	return alias
}

func (u User) pending(action string) bool {
	for _, a := range u.RequiredActions {
		if a == action {
			return true
		}
	}
	return false
}

// SetPassword sets the user's password. temporary=true is an administrator's reset:
// Keycloak adds the UPDATE_PASSWORD required action, which the portal's first-login
// step completes. A policy refusal comes back as *PolicyError, and so does a
// password under MinPasswordLength, which never reaches Keycloak.
func (r Realm) SetPassword(ctx context.Context, id, password string, temporary bool) error {
	if err := checkLength(password); err != nil {
		return err
	}
	code, out, err := r.admin(ctx, http.MethodPut, "/users/"+url.PathEscape(id)+"/reset-password",
		map[string]any{"type": "password", "value": password, "temporary": temporary})
	if err != nil {
		return err
	}
	if code == http.StatusBadRequest {
		var e struct {
			ErrorDescription string `json:"error_description"`
			ErrorMessage     string `json:"errorMessage"`
		}
		_ = json.Unmarshal(out, &e)
		if reason := firstNonEmpty(e.ErrorDescription, e.ErrorMessage); reason != "" {
			return &PolicyError{Reason: reason}
		}
	}
	if code/100 != 2 {
		// The body is not echoed: a policy message is the one place a realm will
		// quote a password back.
		return fmt.Errorf("keycloak set password: %d", code)
	}
	return nil
}

// clearUpdatePassword removes a pending forced change, if there is one.
//
// The update is MINIMAL — requiredActions only. Reading the whole user and writing
// it back re-sends computed fields that a realm with a strict user profile rejects
// with 400, which left PKI accounts with a new password and a change prompt that
// never went away (2026-07).
func (r Realm) clearUpdatePassword(ctx context.Context, u User) error {
	if !u.pending(actionUpdatePassword) {
		return nil
	}
	rest := []string{}
	for _, a := range u.RequiredActions {
		if a != actionUpdatePassword {
			rest = append(rest, a)
		}
	}
	_, err := r.adminOK(ctx, http.MethodPut, "/users/"+url.PathEscape(u.ID), map[string]any{"requiredActions": rest})
	return err
}

// SignOutEverywhere ends every session the user has. Used after any password change
// and after an administrator's reset, so a session opened with the old password
// does not outlive it.
func (r Realm) SignOutEverywhere(ctx context.Context, id string) error {
	_, err := r.adminOK(ctx, http.MethodPost, "/users/"+url.PathEscape(id)+"/logout", nil)
	return err
}

// SignOutOthers ends every session the user has except keep — a password changed
// from inside the portal leaves the person signed in where they made the change,
// and nowhere else. Signing that session out too would force a fresh sign-in, and
// for someone with an authenticator app the code they just typed is already spent:
// Keycloak refuses a code it has seen. With keep empty it signs out everything.
func (r Realm) SignOutOthers(ctx context.Context, id, keep string) error {
	if keep == "" {
		return r.SignOutEverywhere(ctx, id)
	}
	out, err := r.adminOK(ctx, http.MethodGet, "/users/"+url.PathEscape(id)+"/sessions", nil)
	if err != nil {
		return err
	}
	var sessions []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(out, &sessions); err != nil {
		return err
	}
	for _, s := range sessions {
		if s.ID == keep {
			continue
		}
		if _, err := r.adminOK(ctx, http.MethodDelete, "/sessions/"+url.PathEscape(s.ID), nil); err != nil {
			return err
		}
	}
	return nil
}

type kcCredential struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	CreatedDate int64  `json:"createdDate"` // milliseconds
}

func (r Realm) credentials(ctx context.Context, id string) ([]kcCredential, error) {
	out, err := r.adminOK(ctx, http.MethodGet, "/users/"+url.PathEscape(id)+"/credentials", nil)
	if err != nil {
		return nil, err
	}
	var cs []kcCredential
	return cs, json.Unmarshal(out, &cs)
}

// PasswordSetAt is when the user's current password was set. For a temporary
// password that is when the administrator issued it, which is what its expiry is
// measured from — no attribute of our own to keep in step.
func (r Realm) PasswordSetAt(ctx context.Context, id string) (time.Time, error) {
	cs, err := r.credentials(ctx, id)
	if err != nil {
		return time.Time{}, err
	}
	for _, c := range cs {
		if c.Type == "password" {
			return time.UnixMilli(c.CreatedDate), nil
		}
	}
	return time.Time{}, errors.New("keycloak: user has no password")
}

// HasOTP reports whether the user has an authenticator app registered.
func (r Realm) HasOTP(ctx context.Context, id string) (bool, error) {
	cs, err := r.credentials(ctx, id)
	if err != nil {
		return false, err
	}
	for _, c := range cs {
		if c.Type == "otp" {
			return true, nil
		}
	}
	return false, nil
}

// SetOTP registers secret as the user's authenticator app, replacing any other.
// Credentials sent in a user update are ADDED beside the password, and the update
// carries nothing else (see clearUpdatePassword for why).
func (r Realm) SetOTP(ctx context.Context, id, secret string) error {
	if !validOTPSecret(secret) {
		return errors.New("authflow: malformed authenticator secret")
	}
	if err := r.RemoveOTP(ctx, id); err != nil {
		return err
	}
	secretData, _ := json.Marshal(map[string]string{"value": secret})
	credData, _ := json.Marshal(map[string]any{
		"subType": "totp", "digits": otpDigits, "counter": 0, "period": otpPeriod, "algorithm": "HmacSHA1",
	})
	_, err := r.adminOK(ctx, http.MethodPut, "/users/"+url.PathEscape(id), map[string]any{
		"credentials": []map[string]any{{
			"type":           "otp",
			"userLabel":      "Authenticator app",
			"secretData":     string(secretData),
			"credentialData": string(credData),
		}},
	})
	return err
}

// RemoveOTP deletes the user's authenticator app, if they have one.
func (r Realm) RemoveOTP(ctx context.Context, id string) error {
	cs, err := r.credentials(ctx, id)
	if err != nil {
		return err
	}
	for _, c := range cs {
		if c.Type != "otp" {
			continue
		}
		if _, err := r.adminOK(ctx, http.MethodDelete, "/users/"+url.PathEscape(id)+"/credentials/"+url.PathEscape(c.ID), nil); err != nil {
			return err
		}
	}
	return nil
}

// MFARequired reads the organisation's "require an authenticator app" setting, the
// realm attribute PKI has used since 2026-07. It is enforced by the portal (members
// without one are sent to set it up right after sign-in), not by Keycloak: making
// it a Keycloak required action breaks the direct-grant sign-in the portals use.
func (r Realm) MFARequired(ctx context.Context) (bool, error) {
	out, err := r.adminOK(ctx, http.MethodGet, "", nil)
	if err != nil {
		return false, err
	}
	var rep struct {
		Attributes map[string]string `json:"attributes"`
	}
	if err := json.Unmarshal(out, &rep); err != nil {
		return false, err
	}
	return rep.Attributes["mfaRequired"] == "true", nil
}

// SetMFARequired writes that setting. The realm's other attributes are sent back
// with it because a realm update replaces the attribute map it is given.
func (r Realm) SetMFARequired(ctx context.Context, on bool) error {
	out, err := r.adminOK(ctx, http.MethodGet, "", nil)
	if err != nil {
		return err
	}
	var rep struct {
		Attributes map[string]string `json:"attributes"`
	}
	if err := json.Unmarshal(out, &rep); err != nil {
		return err
	}
	if rep.Attributes == nil {
		rep.Attributes = map[string]string{}
	}
	rep.Attributes["mfaRequired"] = fmt.Sprint(on)
	_, err = r.adminOK(ctx, http.MethodPut, "", map[string]any{"attributes": rep.Attributes})
	return err
}

// EnsureNamesOptional makes first and last name optional in the realm's user
// profile. Keycloak requires both by default, and an account missing either can
// NEVER complete a password sign-in: the token endpoint answers "Account is not
// fully set up" even with the right password. Administrators add people by email
// alone, so without this every flow here ends at a sign-in that cannot succeed.
// PKI found this in 2026-07; QryptoScan's realm setup does the same. Idempotent —
// call it at startup.
func (r Realm) EnsureNamesOptional(ctx context.Context) error {
	out, err := r.adminOK(ctx, http.MethodGet, "/users/profile", nil)
	if err != nil {
		return err
	}
	var cfg map[string]any
	if err := json.Unmarshal(out, &cfg); err != nil {
		return err
	}
	changed := false
	attrs, _ := cfg["attributes"].([]any)
	for _, a := range attrs {
		m, _ := a.(map[string]any)
		if n, _ := m["name"].(string); n == "firstName" || n == "lastName" {
			if _, req := m["required"]; req {
				delete(m, "required")
				changed = true
			}
		}
	}
	if !changed {
		return nil
	}
	_, err = r.adminOK(ctx, http.MethodPut, "/users/profile", cfg)
	return err
}

// CheckPassword tries login/password (and code, if given) at the realm's token
// endpoint, exactly as the portal's sign-in does. A successful check opens a
// Keycloak session; it is closed again straight away so checks do not pile up as
// sessions the person never started.
func (r Realm) CheckPassword(ctx context.Context, login, password, code string) (Check, error) {
	form := url.Values{
		"grant_type": {"password"}, "client_id": {r.ClientID},
		"username": {login}, "password": {password},
	}
	if code != "" {
		form.Set("otp", code)
	}
	base := strings.TrimRight(r.BaseURL, "/") + "/realms/" + url.PathEscape(r.Name) + "/protocol/openid-connect"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return CheckInvalid, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := r.client().Do(req)
	if err != nil {
		return CheckInvalid, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusOK:
		var t struct {
			RefreshToken string `json:"refresh_token"`
		}
		if json.Unmarshal(body, &t) == nil && t.RefreshToken != "" {
			lf := url.Values{"client_id": {r.ClientID}, "refresh_token": {t.RefreshToken}}
			if lr, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/logout", strings.NewReader(lf.Encode())); err == nil {
				lr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if resp, err := r.client().Do(lr); err == nil {
					resp.Body.Close()
				}
			}
		}
		return CheckOK, nil
	case resp.StatusCode == http.StatusBadRequest:
		// "Account is not fully set up": Keycloak validated the password (and code)
		// FIRST, then stopped on a required action. So this answer also means the
		// password was right.
		var e struct {
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &e)
		if strings.Contains(strings.ToLower(e.ErrorDescription), "not fully set up") {
			return CheckChangeRequired, nil
		}
		return CheckInvalid, nil
	case resp.StatusCode == http.StatusUnauthorized:
		return CheckInvalid, nil
	}
	return CheckInvalid, fmt.Errorf("keycloak token endpoint: %d %s", resp.StatusCode, firstLine(body))
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
