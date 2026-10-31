package authflow

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

// Handlers is the HTTP contract the portal-kit account screens call. Every product
// mounts the same routes, so the screens are the same code everywhere.
//
// Public (no session; rate-limit them with Public):
//
//	POST {prefix}/password/forgot       {email}
//	POST {prefix}/password/reset        {token, password}
//	POST {prefix}/password/first-login  {login, temporaryPassword, code, password}
//
// Signed in (Caller must identify the person):
//
//	POST {prefix}/password/change       {currentPassword, code, password}
//	GET  {prefix}/mfa                   → {enabled, required}
//	POST {prefix}/mfa/begin             → {secret, uri}
//	POST {prefix}/mfa/enroll            {secret, code}
//	POST {prefix}/mfa/remove            {password, code}
//
// Administrator actions (AdminResetPassword, AdminResetMFA) are methods the product
// calls from its own routes, behind its own permission checks, because who may
// reset whom is a product decision.
//
// Errors are {"error": CODE, "message": text}; the message is written for the
// person at the screen.
type Handlers struct {
	S *Service
	// RealmFor finds the realm an address or username signs in to. CAMP and
	// QryptoScan have one realm; PKI looks the address up across its tenants.
	RealmFor func(ctx context.Context, login string) (Realm, bool)
	// RealmByName turns the realm recorded with a reset link back into a Realm.
	RealmByName func(name string) (Realm, bool)
	// Caller identifies the signed-in person from a request the product has
	// already authenticated.
	Caller func(r *http.Request) (Caller, bool)
	// PortalURL is the product's CONFIGURED public address for a realm — never
	// derived from the request, or a reset link could be pointed elsewhere.
	PortalURL func(realm string) string
	// Issuer is the name an authenticator app shows beside the codes.
	Issuer string
	// ClientIP is the address recorded in "your password was changed" emails.
	ClientIP func(r *http.Request) string
	// Public wraps the routes anyone can reach — the product's per-IP rate limit.
	Public func(http.HandlerFunc) http.HandlerFunc
	Log    *slog.Logger
}

// Mount registers the routes on mux under prefix (e.g. "/api/v1").
func (h *Handlers) Mount(mux *http.ServeMux, prefix string) {
	pub := h.Public
	if pub == nil {
		pub = func(f http.HandlerFunc) http.HandlerFunc { return f }
	}
	mux.HandleFunc("POST "+prefix+"/password/forgot", pub(h.forgot))
	mux.HandleFunc("POST "+prefix+"/password/reset", pub(h.reset))
	mux.HandleFunc("POST "+prefix+"/password/first-login", pub(h.firstLogin))
	mux.HandleFunc("POST "+prefix+"/password/change", h.self(h.change))
	mux.HandleFunc("GET "+prefix+"/mfa", h.self(h.mfaStatus))
	mux.HandleFunc("POST "+prefix+"/mfa/begin", h.self(h.mfaBegin))
	mux.HandleFunc("POST "+prefix+"/mfa/enroll", h.self(h.mfaEnroll))
	mux.HandleFunc("POST "+prefix+"/mfa/remove", h.self(h.mfaRemove))
}

func (h *Handlers) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

func (h *Handlers) ip(r *http.Request) string {
	if h.ClientIP != nil {
		return h.ClientIP(r)
	}
	return ""
}

func (h *Handlers) self(f func(http.ResponseWriter, *http.Request, Caller)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := h.Caller(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "UNAUTHENTICATED", "Sign in again to continue.")
			return
		}
		f(w, r, c)
	}
}

func (h *Handlers) forgot(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &in) {
		return
	}
	realm, ok := h.RealmFor(r.Context(), in.Email)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	err := h.S.RequestReset(r.Context(), realm, in.Email, h.PortalURL(realm.Name))
	if errors.Is(err, ErrMailOff) {
		writeErr(w, http.StatusServiceUnavailable, "MAIL_OFF", "Email isn't set up here, so we can't send a reset link. Ask your administrator to reset your password.")
		return
	}
	if err != nil {
		h.log().Warn("password reset request failed", "err", err)
	}
	// The same answer whatever happened: the form must not reveal who has an account.
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handlers) reset(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	err := h.S.CompleteReset(r.Context(), in.Token, in.Password, h.ip(r), h.RealmByName, h.PortalURL)
	h.answer(w, err)
}

func (h *Handlers) firstLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Login             string `json:"login"`
		TemporaryPassword string `json:"temporaryPassword"`
		Code              string `json:"code"`
		Password          string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	realm, ok := h.RealmFor(r.Context(), in.Login)
	if !ok {
		h.answer(w, ErrBadCredentials)
		return
	}
	err := h.S.CompleteFirstLogin(r.Context(), realm, in.Login, in.TemporaryPassword, in.Code, in.Password, h.ip(r), h.PortalURL(realm.Name))
	h.answer(w, err)
}

func (h *Handlers) change(w http.ResponseWriter, r *http.Request, c Caller) {
	var in struct {
		CurrentPassword string `json:"currentPassword"`
		Code            string `json:"code"`
		Password        string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	h.answer(w, h.S.ChangePassword(r.Context(), c, in.CurrentPassword, in.Code, in.Password, h.ip(r), h.PortalURL(c.Realm.Name)))
}

func (h *Handlers) mfaStatus(w http.ResponseWriter, r *http.Request, c Caller) {
	st, err := h.S.MFAStatus(r.Context(), c)
	if err != nil {
		h.answer(w, err)
		return
	}
	out := map[string]any{"enabled": st.Enabled, "required": st.Required}
	if st.ManagedBy != "" {
		out["managedBy"] = st.ManagedBy
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handlers) mfaBegin(w http.ResponseWriter, _ *http.Request, c Caller) {
	account := c.Email
	if account == "" {
		account = c.Login
	}
	secret, uri, err := h.S.BeginMFA(h.Issuer, account)
	if err != nil {
		h.answer(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "uri": uri})
}

func (h *Handlers) mfaEnroll(w http.ResponseWriter, r *http.Request, c Caller) {
	var in struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	h.answer(w, h.S.EnrollMFA(r.Context(), c, in.Secret, in.Code, h.PortalURL(c.Realm.Name)))
}

func (h *Handlers) mfaRemove(w http.ResponseWriter, r *http.Request, c Caller) {
	var in struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	h.answer(w, h.S.RemoveMFA(r.Context(), c, in.Password, in.Code, h.PortalURL(c.Realm.Name)))
}

// AdminResetPassword issues userID a temporary password (flow D). Call it from the
// product's own route after its permission check. The answer is
// {"emailed": true}, or {"emailed": false, "temporaryPassword": …} when there was
// no way to email it and the administrator has to pass it on.
func (h *Handlers) AdminResetPassword(w http.ResponseWriter, r *http.Request, realm Realm, userID string, newAccount bool) {
	temp, emailed, err := h.S.IssueTempPassword(r.Context(), realm, userID, h.PortalURL(realm.Name), newAccount)
	if err != nil {
		h.answer(w, err)
		return
	}
	out := map[string]any{"emailed": emailed}
	if !emailed {
		out["temporaryPassword"] = temp
	}
	writeJSON(w, http.StatusOK, out)
}

// AdminResetMFA removes userID's authenticator. Same arrangement as above.
func (h *Handlers) AdminResetMFA(w http.ResponseWriter, r *http.Request, realm Realm, userID string) {
	h.answer(w, h.S.AdminResetMFA(r.Context(), realm, userID, h.PortalURL(realm.Name)))
}

// AdminMFARequired reads (GET → {"required": bool}) or sets ({"required": bool})
// the organisation's "require an authenticator app" setting — the toggle in the
// portal-kit Security panel. Behind the product's own permission check.
func (h *Handlers) AdminMFARequired(w http.ResponseWriter, r *http.Request, realm Realm) {
	if r.Method == http.MethodGet {
		on, err := realm.MFARequired(r.Context())
		if err != nil {
			h.answer(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"required": on})
		return
	}
	var in struct {
		Required bool `json:"required"`
	}
	if !decode(w, r, &in) {
		return
	}
	h.answer(w, realm.SetMFARequired(r.Context(), in.Required))
}

// answer writes {"ok": true} or the error as the person at the screen should read it.
func (h *Handlers) answer(w http.ResponseWriter, err error) {
	var pe *PolicyError
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case errors.As(err, &pe):
		writeErr(w, http.StatusBadRequest, "WEAK_PASSWORD", pe.Reason)
	case errors.Is(err, ErrBadCredentials):
		writeErr(w, http.StatusUnauthorized, "BAD_CREDENTIALS", "The password or code is incorrect.")
	case errors.Is(err, ErrLinkInvalid):
		writeErr(w, http.StatusBadRequest, "LINK_INVALID", "This reset link isn't valid or has already been used. Ask for a new one.")
	case errors.Is(err, ErrLinkExpired):
		writeErr(w, http.StatusBadRequest, "LINK_EXPIRED", "This reset link has expired. Ask for a new one.")
	case errors.Is(err, ErrTempExpired):
		writeErr(w, http.StatusBadRequest, "TEMP_EXPIRED", "This temporary password has expired. Ask your administrator to reset it again.")
	case errors.Is(err, ErrNoChangePending):
		writeErr(w, http.StatusConflict, "NO_CHANGE_PENDING", "No password change is waiting for this account. Sign in as usual.")
	case errors.Is(err, ErrCodeInvalid):
		writeErr(w, http.StatusBadRequest, "CODE_INVALID", "That code isn't right. Check the time on your phone and try again.")
	case errors.Is(err, ErrMFAAlreadyOn):
		writeErr(w, http.StatusConflict, "MFA_ON", "An authenticator app is already set up. Remove it first to set up a new one.")
	case errors.Is(err, ErrMFAManaged):
		writeErr(w, http.StatusConflict, "MFA_MANAGED", "You sign in through your identity provider. Set up two-step sign-in there.")
	case errors.Is(err, ErrFederated):
		writeErr(w, http.StatusConflict, "FEDERATED", "This account's password is managed by its directory or identity provider, not here.")
	default:
		h.log().Error("account flow failed", "err", err)
		writeErr(w, http.StatusInternalServerError, "INTERNAL", "Something went wrong. Try again in a moment.")
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "The request couldn't be read.")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, errCode, msg string) {
	writeJSON(w, code, map[string]string{"error": errCode, "message": msg})
}
