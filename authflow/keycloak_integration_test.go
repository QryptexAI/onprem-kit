package authflow

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// These run every flow against a REAL Keycloak, because the failures that matter
// are Keycloak's: a whole-user write a strict profile rejects, an update that
// silently drops a credential, a required action that blocks a direct grant. A
// fake accepts whatever it is sent and proves none of that.
//
// Point them at any Keycloak you can make throwaway realms in:
//
//	docker run -d --rm -p 127.0.0.1:18180:8080 \
//	  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=… \
//	  <keycloak image> start-dev
//	AUTHFLOW_KEYCLOAK_URL=http://127.0.0.1:18180 AUTHFLOW_KEYCLOAK_ADMIN=admin \
//	  AUTHFLOW_KEYCLOAK_PASSWORD=… go test ./authflow/
//
// Each run makes its own realm and deletes it afterwards.

type master struct{ base, user, pass string }

func (m master) token(ctx context.Context) (string, error) {
	form := url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {m.user}, "password": {m.pass}}
	resp, err := http.PostForm(m.base+"/realms/master/protocol/openid-connect/token", form)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var t struct {
		AccessToken string `json:"access_token"`
	}
	return t.AccessToken, json.NewDecoder(resp.Body).Decode(&t)
}

func (m master) call(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	tok, err := m.token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, m.base+path, rd)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

type sent struct{ to, subject, body string }

type outbox struct {
	mu   sync.Mutex
	msgs []sent
}

func (o *outbox) send(_ context.Context, to, subject, body string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.msgs = append(o.msgs, sent{to, subject, body})
	return nil
}

func (o *outbox) count() int { o.mu.Lock(); defer o.mu.Unlock(); return len(o.msgs) }

func (o *outbox) last(t *testing.T, to string) sent {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	for i := len(o.msgs) - 1; i >= 0; i-- {
		if o.msgs[i].to == to {
			return o.msgs[i]
		}
	}
	t.Fatalf("no email to %s", to)
	return sent{}
}

type harness struct {
	t     *testing.T
	m     master
	realm Realm
	svc   *Service
	mail  *outbox
	srv   *httptest.Server
	step  int64 // the TOTP step the test started in; codes are taken relative to it
}

func newHarness(t *testing.T) *harness {
	base := os.Getenv("AUTHFLOW_KEYCLOAK_URL")
	if base == "" {
		t.Skip("set AUTHFLOW_KEYCLOAK_URL (and _ADMIN, _PASSWORD) to run against a real Keycloak")
	}
	m := master{base: strings.TrimRight(base, "/"), user: os.Getenv("AUTHFLOW_KEYCLOAK_ADMIN"), pass: os.Getenv("AUTHFLOW_KEYCLOAK_PASSWORD")}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	name := "authflow-it-" + hex.EncodeToString(b)
	code, out := m.call(t, http.MethodPost, "/admin/realms", map[string]any{
		"realm": name, "enabled": true, "displayName": "Kept",
		"passwordPolicy": "length(12)",
		// Codes from several steps around "now" are accepted, so the test can use a
		// fresh one for every check — Keycloak refuses a code it has already seen.
		// The window only applies when the policy TYPE is sent with it; on its own
		// it is silently ignored and stays 1.
		"otpPolicyType": "totp", "otpPolicyAlgorithm": "HmacSHA1", "otpPolicyDigits": 6,
		"otpPolicyPeriod": 30, "otpPolicyLookAheadWindow": 5,
		"attributes": map[string]string{"keepMe": "yes"},
		"clients": []map[string]any{{"clientId": "portal", "publicClient": true,
			"directAccessGrantsEnabled": true, "standardFlowEnabled": false}},
	})
	if code != http.StatusCreated {
		t.Fatalf("create realm: %d %s", code, out)
	}
	t.Cleanup(func() { m.call(t, http.MethodDelete, "/admin/realms/"+name, nil) })

	h := &harness{t: t, m: m, mail: &outbox{}, step: time.Now().Unix() / otpPeriod}
	h.realm = Realm{BaseURL: m.base, Name: name, ClientID: "portal", Token: m.token}
	h.svc = NewService("QryptexAI Test", NewMemTokens(), h.mail.send)
	h.srv = httptest.NewServer(h.mux(h.svc))
	t.Cleanup(h.srv.Close)
	return h
}

// mux mounts the routes as a product would, with an admin route of its own.
func (h *harness) mux(svc *Service) http.Handler {
	hd := &Handlers{
		S:           svc,
		RealmFor:    func(context.Context, string) (Realm, bool) { return h.realm, true },
		RealmByName: func(n string) (Realm, bool) { return h.realm, n == h.realm.Name },
		Caller: func(r *http.Request) (Caller, bool) {
			login := r.Header.Get("X-Test-User")
			u, ok, err := h.realm.FindUser(r.Context(), login)
			if err != nil || !ok {
				return Caller{}, false
			}
			return Caller{Realm: h.realm, UserID: u.ID, Login: u.Username, Email: u.Email, SessionID: r.Header.Get("X-Test-Session")}, true
		},
		PortalURL: func(string) string { return "https://portal.test" },
		ClientIP:  func(*http.Request) string { return "198.51.100.7" },
		Issuer:    "QryptexAI Test",
	}
	mux := http.NewServeMux()
	hd.Mount(mux, "/api/v1")
	mux.HandleFunc("POST /api/v1/admin/users/{login}/reset-password", func(w http.ResponseWriter, r *http.Request) {
		u, _, _ := h.realm.FindUser(r.Context(), r.PathValue("login"))
		hd.AdminResetPassword(w, r, h.realm, u.ID, false)
	})
	mux.HandleFunc("/api/v1/admin/mfa-required", func(w http.ResponseWriter, r *http.Request) {
		hd.AdminMFARequired(w, r, h.realm)
	})
	mux.HandleFunc("POST /api/v1/admin/users/{login}/reset-mfa", func(w http.ResponseWriter, r *http.Request) {
		u, _, _ := h.realm.FindUser(r.Context(), r.PathValue("login"))
		hd.AdminResetMFA(w, r, h.realm, u.ID)
	})
	return mux
}

func (h *harness) user(login, password string) {
	h.t.Helper()
	code, out := h.m.call(h.t, http.MethodPost, "/admin/realms/"+h.realm.Name+"/users", map[string]any{
		"username": login, "email": login + "@acme.test", "firstName": "Test", "lastName": strings.ToUpper(login[:1]) + login[1:],
		"enabled": true, "emailVerified": true,
		"credentials": []map[string]any{{"type": "password", "value": password, "temporary": false}},
	})
	if code != http.StatusCreated {
		h.t.Fatalf("create user %s: %d %s", login, code, out)
	}
}

func (h *harness) post(path, as string, body any) (int, map[string]any) {
	h.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+path, bytes.NewReader(b))
	if as != "" {
		req.Header.Set("X-Test-User", as)
	}
	return h.do(req)
}

func (h *harness) get(path, as string) (int, map[string]any) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+path, nil)
	req.Header.Set("X-Test-User", as)
	return h.do(req)
}

func (h *harness) do(req *http.Request) (int, map[string]any) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (h *harness) check(login, password, code string) Check {
	h.t.Helper()
	c, err := h.realm.CheckPassword(context.Background(), login, password, code)
	if err != nil {
		h.t.Fatal(err)
	}
	return c
}

// code is the authenticator code offset steps from the step the test began in.
func (h *harness) code(secret string, offset int64) string {
	return hotp([]byte(secret), uint64(h.step+offset))
}

func (h *harness) refreshToken(login, password string) string {
	h.t.Helper()
	form := url.Values{"grant_type": {"password"}, "client_id": {"portal"}, "username": {login}, "password": {password}}
	resp, err := http.PostForm(h.realm.BaseURL+"/realms/"+h.realm.Name+"/protocol/openid-connect/token", form)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var t struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&t)
	return t.RefreshToken
}

// session signs in and returns the refresh token and the session id ("sid") from
// the access token, as a product's token validation would read it.
func (h *harness) session(login, password string) (refresh, sid string) {
	h.t.Helper()
	form := url.Values{"grant_type": {"password"}, "client_id": {"portal"}, "username": {login}, "password": {password}}
	resp, err := http.PostForm(h.realm.BaseURL+"/realms/"+h.realm.Name+"/protocol/openid-connect/token", form)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var t struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&t)
	parts := strings.Split(t.AccessToken, ".")
	if len(parts) != 3 {
		h.t.Fatalf("no access token for %s", login)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct {
		SID string `json:"sid"`
	}
	_ = json.Unmarshal(payload, &claims)
	return t.RefreshToken, claims.SID
}

func (h *harness) refreshWorks(rt string) bool {
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"portal"}, "refresh_token": {rt}}
	resp, err := http.PostForm(h.realm.BaseURL+"/realms/"+h.realm.Name+"/protocol/openid-connect/token", form)
	if err != nil {
		h.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

var (
	linkToken = regexp.MustCompile(`#reset=([A-Za-z0-9_-]+)`)
	tempLine  = regexp.MustCompile(`Temporary password: (\S+)`)
)

func want(t *testing.T, what string, gotCode int, got map[string]any, wantCode int, wantErr string) {
	t.Helper()
	if gotCode != wantCode || (wantErr != "" && got["error"] != wantErr) {
		t.Fatalf("%s: got %d %v, want %d %s", what, gotCode, got, wantCode, wantErr)
	}
}

// Flow A + C: the link, the unchanged password until it is used, the policy
// refusal that keeps the link, sign-out everywhere, the changed email, one use.
func TestKeycloak_ForgotPasswordLink(t *testing.T) {
	h := newHarness(t)
	h.user("ana", "Original-pass-123")
	session := h.refreshToken("ana", "Original-pass-123")

	code, out := h.post("/api/v1/password/forgot", "", map[string]string{"email": "ANA@acme.test "})
	want(t, "forgot", code, out, http.StatusOK, "")
	m := h.mail.last(t, "ana@acme.test")
	tok := linkToken.FindStringSubmatch(m.body)
	if tok == nil || !strings.Contains(m.body, "https://portal.test/#reset=") {
		t.Fatalf("no reset link in:\n%s", m.body)
	}
	if h.check("ana", "Original-pass-123", "") != CheckOK {
		t.Fatal("asking for a link changed the password; it must not")
	}

	code, out = h.post("/api/v1/password/reset", "", map[string]string{"token": tok[1], "password": "too-short"})
	want(t, "weak password", code, out, http.StatusBadRequest, "WEAK_PASSWORD")
	code, out = h.post("/api/v1/password/reset", "", map[string]string{"token": tok[1], "password": "Brand-new-pass-456"})
	want(t, "reset after a refusal (link kept)", code, out, http.StatusOK, "")

	if h.check("ana", "Original-pass-123", "") != CheckInvalid || h.check("ana", "Brand-new-pass-456", "") != CheckOK {
		t.Fatal("old password still works or new one does not")
	}
	if h.refreshWorks(session) {
		t.Error("a session opened with the old password survived the reset")
	}
	if c := h.mail.last(t, "ana@acme.test"); !strings.Contains(c.subject, "was changed") || !strings.Contains(c.body, "198.51.100.7") {
		t.Errorf("no changed email: %+v", c)
	}
	code, out = h.post("/api/v1/password/reset", "", map[string]string{"token": tok[1], "password": "Another-pass-789"})
	want(t, "link reused", code, out, http.StatusBadRequest, "LINK_INVALID")
}

// The form answers the same for an unknown address, and caps one address.
func TestKeycloak_ForgotRevealsNothingAndIsCapped(t *testing.T) {
	h := newHarness(t)
	h.user("bea", "Original-pass-123")
	before := h.mail.count()
	code, out := h.post("/api/v1/password/forgot", "", map[string]string{"email": "nobody@acme.test"})
	want(t, "unknown address", code, out, http.StatusOK, "")
	if h.mail.count() != before {
		t.Fatal("an email went out for an address with no account")
	}
	for i := 0; i < 5; i++ {
		code, out = h.post("/api/v1/password/forgot", "", map[string]string{"email": "bea@acme.test"})
		want(t, "repeat request", code, out, http.StatusOK, "")
	}
	if n := h.mail.count() - before; n != resetsPerHour {
		t.Errorf("%d emails for 5 requests, want %d", n, resetsPerHour)
	}
}

// Flow D: emailed temporary password, forced change, expiry after 72 hours.
func TestKeycloak_AdminTemporaryPassword(t *testing.T) {
	h := newHarness(t)
	h.user("ben", "Original-pass-123")
	session := h.refreshToken("ben", "Original-pass-123")

	code, out := h.post("/api/v1/admin/users/ben/reset-password", "", nil)
	want(t, "admin reset", code, out, http.StatusOK, "")
	if out["emailed"] != true || out["temporaryPassword"] != nil {
		t.Fatalf("the administrator must not see an emailed password: %v", out)
	}
	temp := tempLine.FindStringSubmatch(h.mail.last(t, "ben@acme.test").body)
	if temp == nil {
		t.Fatal("no temporary password in the email")
	}
	if h.refreshWorks(session) {
		t.Error("the user's session survived an administrator's reset")
	}
	if h.check("ben", temp[1], "") != CheckChangeRequired {
		t.Fatal("the temporary password does not force a change")
	}
	code, out = h.post("/api/v1/password/first-login", "", map[string]string{"login": "ben", "temporaryPassword": "wrong", "password": "Bens-own-pass-789"})
	want(t, "wrong temporary password", code, out, http.StatusUnauthorized, "BAD_CREDENTIALS")
	code, out = h.post("/api/v1/password/first-login", "", map[string]string{"login": "ben", "temporaryPassword": temp[1], "password": "Bens-own-pass-789"})
	want(t, "first login", code, out, http.StatusOK, "")
	if h.check("ben", "Bens-own-pass-789", "") != CheckOK {
		t.Fatal("the chosen password does not sign in cleanly")
	}
	code, out = h.post("/api/v1/password/first-login", "", map[string]string{"login": "ben", "temporaryPassword": "Bens-own-pass-789", "password": "Yet-another-pass-1"})
	want(t, "nothing pending", code, out, http.StatusConflict, "NO_CHANGE_PENDING")

	// Expiry: the same reset, read 73 hours later.
	h.post("/api/v1/admin/users/ben/reset-password", "", nil)
	temp = tempLine.FindStringSubmatch(h.mail.last(t, "ben@acme.test").body)
	h.svc.Now = func() time.Time { return time.Now().Add(73 * time.Hour) }
	code, out = h.post("/api/v1/password/first-login", "", map[string]string{"login": "ben", "temporaryPassword": temp[1], "password": "Bens-later-pass-1"})
	h.svc.Now = time.Now
	want(t, "expired temporary password", code, out, http.StatusBadRequest, "TEMP_EXPIRED")
}

// With no mail, the form says so and the administrator is shown the password once.
func TestKeycloak_NoMailFallbacks(t *testing.T) {
	h := newHarness(t)
	h.user("cal", "Original-pass-123")
	h.srv.Config.Handler = h.mux(NewService("QryptexAI Test", NewMemTokens(), nil))
	code, out := h.post("/api/v1/password/forgot", "", map[string]string{"email": "cal@acme.test"})
	want(t, "forgot without mail", code, out, http.StatusServiceUnavailable, "MAIL_OFF")
	code, out = h.post("/api/v1/admin/users/cal/reset-password", "", nil)
	if code != http.StatusOK || out["emailed"] != false || out["temporaryPassword"] == "" {
		t.Fatalf("without mail the administrator must get the password: %d %v", code, out)
	}
}

// Flow B + E: enrolment, sign-in needing the code, change with the code, an
// administrator's reset of an MFA user (first login needs the code too), removal.
func TestKeycloak_AuthenticatorApp(t *testing.T) {
	h := newHarness(t)
	h.user("dan", "Original-pass-123")

	code, out := h.post("/api/v1/mfa/begin", "dan", nil)
	want(t, "begin", code, out, http.StatusOK, "")
	secret, _ := out["secret"].(string)
	if !strings.HasPrefix(out["uri"].(string), "otpauth://totp/") {
		t.Fatalf("uri %v", out["uri"])
	}
	code, out = h.post("/api/v1/mfa/enroll", "dan", map[string]string{"secret": secret, "code": "000000"})
	want(t, "wrong code", code, out, http.StatusBadRequest, "CODE_INVALID")
	code, out = h.post("/api/v1/mfa/enroll", "dan", map[string]string{"secret": secret, "code": hotp([]byte(secret), uint64(time.Now().Unix()/otpPeriod))})
	want(t, "enroll", code, out, http.StatusOK, "")
	code, out = h.get("/api/v1/mfa", "dan")
	if code != http.StatusOK || out["enabled"] != true || out["required"] != false {
		t.Fatalf("status %d %v", code, out)
	}
	if h.check("dan", "Original-pass-123", "") != CheckInvalid {
		t.Fatal("sign-in without a code succeeded after enrolment")
	}
	if h.check("dan", "Original-pass-123", h.code(secret, 1)) != CheckOK {
		t.Fatal("password + code refused: the minimal update lost the password or the secret is wrong")
	}

	code, out = h.post("/api/v1/password/change", "dan", map[string]string{"currentPassword": "Original-pass-123", "code": h.code(secret, 2), "password": "Dans-new-pass-456"})
	want(t, "change", code, out, http.StatusOK, "")
	code, out = h.post("/api/v1/password/change", "dan", map[string]string{"currentPassword": "Original-pass-123", "code": h.code(secret, 3), "password": "Whatever-pass-1"})
	want(t, "change with the old password", code, out, http.StatusUnauthorized, "BAD_CREDENTIALS")

	// An administrator's reset keeps the authenticator, so first login needs a code.
	h.post("/api/v1/admin/users/dan/reset-password", "", nil)
	temp := tempLine.FindStringSubmatch(h.mail.last(t, "dan@acme.test").body)
	code, out = h.post("/api/v1/password/first-login", "", map[string]string{"login": "dan", "temporaryPassword": temp[1], "password": "Dans-third-pass-1"})
	want(t, "first login without the code", code, out, http.StatusUnauthorized, "BAD_CREDENTIALS")
	code, out = h.post("/api/v1/password/first-login", "", map[string]string{"login": "dan", "temporaryPassword": temp[1], "code": h.code(secret, -1), "password": "Dans-third-pass-1"})
	want(t, "first login with the code", code, out, http.StatusOK, "")

	code, out = h.post("/api/v1/mfa/remove", "dan", map[string]string{"password": "Dans-third-pass-1", "code": h.code(secret, 4)})
	want(t, "remove", code, out, http.StatusOK, "")
	if h.check("dan", "Dans-third-pass-1", "") != CheckOK {
		t.Fatal("still asks for a code after removal")
	}
	if !strings.Contains(h.mail.last(t, "dan@acme.test").subject, "removed") {
		t.Error("no removal email")
	}

	// Lost phone: the administrator removes it.
	_, out = h.post("/api/v1/mfa/begin", "dan", nil)
	s2 := out["secret"].(string)
	h.post("/api/v1/mfa/enroll", "dan", map[string]string{"secret": s2, "code": hotp([]byte(s2), uint64(time.Now().Unix()/otpPeriod))})
	code, out = h.post("/api/v1/admin/users/dan/reset-mfa", "", nil)
	want(t, "admin reset MFA", code, out, http.StatusOK, "")
	if has, _ := h.realm.HasOTP(context.Background(), mustID(t, h, "dan")); has {
		t.Fatal("authenticator still registered after the administrator removed it")
	}
	if b := h.mail.last(t, "dan@acme.test").body; !strings.Contains(b, "An administrator removed") {
		t.Errorf("admin removal email:\n%s", b)
	}
}

// Changing a password in the portal keeps the session it was changed from and
// ends every other one.
func TestKeycloak_ChangeKeepsThisSessionOnly(t *testing.T) {
	h := newHarness(t)
	h.user("gus", "Original-pass-123")
	here, hereSID := h.session("gus", "Original-pass-123")
	elsewhere, _ := h.session("gus", "Original-pass-123")

	b, _ := json.Marshal(map[string]string{"currentPassword": "Original-pass-123", "password": "Gus-new-pass-456"})
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/api/v1/password/change", bytes.NewReader(b))
	req.Header.Set("X-Test-User", "gus")
	req.Header.Set("X-Test-Session", hereSID)
	code, out := h.do(req)
	want(t, "change", code, out, http.StatusOK, "")
	if !h.refreshWorks(here) {
		t.Error("the session the change was made from was signed out")
	}
	if h.refreshWorks(elsewhere) {
		t.Error("another session survived the change")
	}
}

// The organisation's "require" flag is written without disturbing anything else.
func TestKeycloak_RequireMFAKeepsTheRealm(t *testing.T) {
	h := newHarness(t)
	h.user("fay", "Original-pass-123")
	code, out := h.post("/api/v1/admin/mfa-required", "", map[string]bool{"required": true})
	want(t, "require MFA", code, out, http.StatusOK, "")
	if code, out = h.get("/api/v1/admin/mfa-required", ""); out["required"] != true {
		t.Fatalf("flag not set: %d %v", code, out)
	}
	if _, out = h.get("/api/v1/mfa", "fay"); out["required"] != true || out["enabled"] != false {
		t.Fatalf("a member does not see the requirement: %v", out)
	}
	_, raw := h.m.call(t, http.MethodGet, "/admin/realms/"+h.realm.Name, nil)
	var rep struct {
		DisplayName    string            `json:"displayName"`
		PasswordPolicy string            `json:"passwordPolicy"`
		Attributes     map[string]string `json:"attributes"`
		OTPLookAhead   int               `json:"otpPolicyLookAheadWindow"`
	}
	_ = json.Unmarshal(raw, &rep)
	if rep.DisplayName != "Kept" || rep.PasswordPolicy != "length(12)" || rep.Attributes["keepMe"] != "yes" || rep.OTPLookAhead != 5 {
		t.Fatalf("writing the flag disturbed the realm: %+v", rep)
	}
}

// An account added by email alone cannot sign in under Keycloak's default profile;
// after EnsureNamesOptional it can, and a second call changes nothing.
func TestKeycloak_NamelessAccountCanSignIn(t *testing.T) {
	h := newHarness(t)
	code, out := h.m.call(t, http.MethodPost, "/admin/realms/"+h.realm.Name+"/users", map[string]any{
		"username": "nina", "email": "nina@acme.test", "enabled": true, "emailVerified": true,
		"credentials": []map[string]any{{"type": "password", "value": "Original-pass-123", "temporary": false}},
	})
	if code != http.StatusCreated {
		t.Fatalf("create user: %d %s", code, out)
	}
	if h.check("nina", "Original-pass-123", "") != CheckChangeRequired {
		t.Skip("this Keycloak does not require names by default; nothing to prove")
	}
	for i := 0; i < 2; i++ {
		if err := h.realm.EnsureNamesOptional(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if h.check("nina", "Original-pass-123", "") != CheckOK {
		t.Fatal("a nameless account still cannot sign in")
	}
}

// A GitHub-linked account is told where its password lives, gets no link, and
// cannot be given a temporary password.
func TestKeycloak_FederatedAccount(t *testing.T) {
	h := newHarness(t)
	code, out := h.m.call(t, http.MethodPost, "/admin/realms/"+h.realm.Name+"/identity-provider/instances", map[string]any{
		"alias": "github", "providerId": "github", "enabled": true,
		"config": map[string]string{"clientId": "x", "clientSecret": "y"},
	})
	if code != http.StatusCreated {
		t.Fatalf("create idp: %d %s", code, out)
	}
	h.user("eve", "Original-pass-123")
	code, out = h.m.call(t, http.MethodPost, "/admin/realms/"+h.realm.Name+"/users/"+mustID(t, h, "eve")+"/federated-identity/github",
		map[string]string{"identityProvider": "github", "userId": "4242", "userName": "eve-gh"})
	if code/100 != 2 {
		t.Fatalf("link identity: %d %s", code, out)
	}
	c, body := h.post("/api/v1/password/forgot", "", map[string]string{"email": "eve@acme.test"})
	want(t, "forgot (federated)", c, body, http.StatusOK, "")
	if m := h.mail.last(t, "eve@acme.test"); !strings.Contains(m.body, "signs in through GitHub") || strings.Contains(m.body, "#reset=") {
		t.Fatalf("federated email:\n%s", m.body)
	}
	c, body = h.post("/api/v1/admin/users/eve/reset-password", "", nil)
	want(t, "admin reset (federated)", c, body, http.StatusConflict, "FEDERATED")
}

func mustID(t *testing.T, h *harness, login string) string {
	t.Helper()
	u, ok, err := h.realm.FindUser(context.Background(), login)
	if err != nil || !ok {
		t.Fatalf("find %s: %v", login, err)
	}
	return u.ID
}
