package authflow

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Lifetimes agreed on 2026-10-30. A reset link is self-service, so it is short; a
// temporary password was issued by an administrator to someone who may not read
// the email the same day.
const (
	ResetLinkTTL    = 30 * time.Minute
	TempPasswordTTL = 72 * time.Hour
	resetsPerHour   = 3
)

// MinPasswordLength is the floor under every password a person chooses. No product
// ships a realm password policy, so without it a fresh install accepted a
// five-character password at every step until an administrator set one (found
// 2026-10-31). A realm policy can raise it, never lower it.
const MinPasswordLength = 12

// checkLength refuses a password under the floor, worded as Keycloak words its
// own length refusal, so the person sees one message whichever rule caught it.
func checkLength(password string) error {
	if utf8.RuneCountInString(password) < MinPasswordLength {
		return &PolicyError{Reason: fmt.Sprintf("Invalid password: minimum length %d.", MinPasswordLength)}
	}
	return nil
}

var (
	ErrBadCredentials  = errors.New("the password or code is incorrect")
	ErrLinkInvalid     = errors.New("this reset link is not valid or has already been used; ask for a new one")
	ErrLinkExpired     = errors.New("this reset link has expired; ask for a new one")
	ErrTempExpired     = errors.New("this temporary password has expired; ask your administrator to reset it again")
	ErrNoChangePending = errors.New("no password change is waiting for this account; sign in as usual")
	ErrCodeInvalid     = errors.New("that code is not right; check the time on your phone and try again")
	ErrMailOff         = errors.New("email is not set up here, so a reset link cannot be sent; ask your administrator to reset your password")
	ErrFederated       = errors.New("this account's password is managed by its directory or identity provider")
	ErrMFAAlreadyOn    = errors.New("an authenticator app is already set up; remove it first to set up a new one")
)

// SendFunc delivers one plain-text email.
type SendFunc func(ctx context.Context, to, subject, body string) error

// Service runs the flows. Send is nil when the product has no working mail
// settings; flows that need email then say so rather than pretending. Ready, when
// set, is asked at the moment of sending, for a product whose administrator can
// set up email while it runs (CAMP, QryptoScan): false means "not set up".
type Service struct {
	Product string // as it appears in emails: "QryptexAI PKI", "QryptexAI CAMP", "QryptoScan"
	Tokens  TokenStore
	Send    SendFunc
	Ready   func() bool
	Now     func() time.Time

	perAddress *Limiter
}

func NewService(product string, tokens TokenStore, send SendFunc) *Service {
	return &Service{Product: product, Tokens: tokens, Send: send, Now: time.Now,
		perAddress: NewLimiter(resetsPerHour, time.Hour)}
}

// canMail reports whether email can go out right now.
func (s *Service) canMail() bool { return s.Send != nil && (s.Ready == nil || s.Ready()) }

func (s *Service) mail(ctx context.Context, to string, subject, body string) error {
	if !s.canMail() || to == "" {
		return nil
	}
	return s.Send(ctx, to, subject, body)
}

// RequestReset is flow A's first half: "Forgot password?". The caller answers the
// same way whatever happens here — found or not, local or federated, rate-limited
// or not — so the form never tells anyone whether an address has an account. The
// error is for the log, except ErrMailOff, which the person may be told.
//
// Nothing about the account changes. The current password keeps working until the
// emailed link is used, so typing someone's address into the form costs them
// nothing but an email.
func (s *Service) RequestReset(ctx context.Context, realm Realm, email, portalURL string) error {
	if !s.canMail() {
		return ErrMailOff
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || !s.perAddress.Allow(realm.Name+"\x00"+email, s.Now()) {
		return nil
	}
	u, found, err := realm.FindUser(ctx, email)
	if err != nil || !found || u.Email == "" {
		return err
	}
	if u.Federated {
		subj, body := federatedResetEmail(s.Product, u.Provider)
		return s.mail(ctx, u.Email, subj, body)
	}
	raw, hash, err := NewResetToken()
	if err != nil {
		return err
	}
	if err := s.Tokens.Save(ctx, ResetToken{Hash: hash, Realm: realm.Name, UserID: u.ID, Email: u.Email,
		Expires: s.Now().Add(ResetLinkTTL)}); err != nil {
		return err
	}
	subj, body := resetLinkEmail(s.Product, ResetLink(portalURL, raw), ResetLinkTTL)
	return s.mail(ctx, u.Email, subj, body)
}

// CompleteReset is flow A's second half: the link was opened and a new password
// chosen. The link is used up, every session is signed out, and the person is told
// by email. A pending forced change (an administrator's temporary password) is
// cleared too — choosing a password through the link satisfies it.
func (s *Service) CompleteReset(ctx context.Context, raw, newPassword, ip string,
	realmByName func(string) (Realm, bool), portalURL func(realm string) string) error {
	// Before the link is taken, so a short password does not touch it.
	if err := checkLength(newPassword); err != nil {
		return err
	}
	t, ok, err := s.Tokens.Take(ctx, HashResetToken(strings.TrimSpace(raw)))
	if err != nil {
		return err
	}
	if !ok {
		return ErrLinkInvalid
	}
	if s.Now().After(t.Expires) {
		return ErrLinkExpired
	}
	realm, ok := realmByName(t.Realm)
	if !ok {
		return ErrLinkInvalid
	}
	u, err := realm.UserByID(ctx, t.UserID)
	if err != nil {
		return ErrLinkInvalid
	}
	if err := realm.SetPassword(ctx, u.ID, newPassword, false); err != nil {
		var pe *PolicyError
		if errors.As(err, &pe) {
			// The link was taken to make it single-use. A password the policy
			// refuses must not cost the person their link, so it goes back.
			_ = s.Tokens.Save(ctx, t)
		}
		return err
	}
	if err := realm.clearUpdatePassword(ctx, u); err != nil {
		return err
	}
	if err := realm.SignOutEverywhere(ctx, u.ID); err != nil {
		return err
	}
	s.changed(ctx, t.Email, ip, portalURL(realm.Name))
	return nil
}

// CompleteFirstLogin is flow D's second half: someone signing in with an
// administrator's temporary password chooses their own. The temporary password
// (and their authenticator code, if they have one — an administrator's reset does
// not remove it) is checked exactly as sign-in checks it; Keycloak's "not fully set
// up" answer is the proof it was right.
func (s *Service) CompleteFirstLogin(ctx context.Context, realm Realm, login, temp, code, newPassword, ip, portalURL string) error {
	// Before the check below, which spends the person's code.
	if err := checkLength(newPassword); err != nil {
		return err
	}
	switch c, err := realm.CheckPassword(ctx, login, temp, code); {
	case err != nil:
		return err
	case c == CheckOK:
		return ErrNoChangePending
	case c != CheckChangeRequired:
		return ErrBadCredentials
	}
	u, found, err := realm.FindUser(ctx, login)
	if err != nil {
		return err
	}
	if !found || !u.pending(actionUpdatePassword) {
		// Blocked by some other required action: not this flow's to complete.
		return ErrNoChangePending
	}
	set, err := realm.PasswordSetAt(ctx, u.ID)
	if err != nil {
		return err
	}
	// The only way to use a temporary password is through here (Keycloak will not
	// issue a token while the change is pending), so this is where it expires.
	if s.Now().Sub(set) > TempPasswordTTL {
		return ErrTempExpired
	}
	if err := realm.SetPassword(ctx, u.ID, newPassword, false); err != nil {
		return err
	}
	if err := realm.clearUpdatePassword(ctx, u); err != nil {
		return err
	}
	s.changed(ctx, u.Email, ip, portalURL)
	return nil
}

// Caller is the signed-in person a self-service request is for, as the product's
// own authentication established it.
type Caller struct {
	Realm     Realm
	UserID    string
	Login     string // the name they sign in with
	Email     string
	SessionID string // the token's "sid" claim: the session the request came from
}

// ChangePassword is flow B: signed in, they change their own password. The current
// password (and code) are checked the way sign-in checks them, then every OTHER
// session is signed out; the one they made the change from carries on.
func (s *Service) ChangePassword(ctx context.Context, c Caller, current, code, newPassword, ip, portalURL string) error {
	if err := checkLength(newPassword); err != nil {
		return err
	}
	switch chk, err := c.Realm.CheckPassword(ctx, c.Login, current, code); {
	case err != nil:
		return err
	case chk != CheckOK:
		return ErrBadCredentials
	}
	if err := c.Realm.SetPassword(ctx, c.UserID, newPassword, false); err != nil {
		return err
	}
	if err := c.Realm.SignOutOthers(ctx, c.UserID, c.SessionID); err != nil {
		return err
	}
	s.changed(ctx, c.Email, ip, portalURL)
	return nil
}

// changed is flow C, the "your password was changed" email. A failure to send is
// not a failure of the change, which has already happened.
func (s *Service) changed(ctx context.Context, to, ip, portalURL string) {
	subj, body := passwordChangedEmail(s.Product, s.Now(), ip, portalURL)
	_ = s.mail(ctx, to, subj, body)
}

// IssueTempPassword is flow D's first half, for an administrator's "Reset password"
// and for a newly added user. The person is signed out everywhere and emailed the
// temporary password; the administrator is NOT shown it. Only when email is not
// set up, or the send fails, does it come back to be shown once on the
// administrator's screen — the one fallback, said plainly by emailed=false.
func (s *Service) IssueTempPassword(ctx context.Context, realm Realm, userID, portalURL string, newAccount bool) (temp string, emailed bool, err error) {
	u, err := realm.UserByID(ctx, userID)
	if err != nil {
		return "", false, err
	}
	if u.Federated {
		return "", false, ErrFederated
	}
	temp, err = TempPassword()
	if err != nil {
		return "", false, err
	}
	if err := realm.SetPassword(ctx, u.ID, temp, true); err != nil {
		return "", false, err
	}
	if err := realm.SignOutEverywhere(ctx, u.ID); err != nil {
		return "", false, err
	}
	if s.canMail() && u.Email != "" {
		subj, body := tempPasswordEmail(s.Product, u.Username, temp, portalURL, TempPasswordTTL, newAccount)
		if err := s.Send(ctx, u.Email, subj, body); err == nil {
			return "", true, nil
		}
	}
	return temp, false, nil
}

// MFAStatus is the caller's own authenticator state and the organisation's rule.
func (s *Service) MFAStatus(ctx context.Context, c Caller) (enabled, required bool, err error) {
	if enabled, err = c.Realm.HasOTP(ctx, c.UserID); err != nil {
		return false, false, err
	}
	required, err = c.Realm.MFARequired(ctx)
	return enabled, required, err
}

// BeginMFA starts enrolment: a new secret and the URI for its QR code. Nothing is
// stored until EnrollMFA proves the app produces the right codes.
func (s *Service) BeginMFA(issuer, account string) (secret, uri string, err error) {
	if secret, err = NewOTPSecret(); err != nil {
		return "", "", err
	}
	return secret, OTPAuthURI(issuer, account, secret), nil
}

// EnrollMFA saves the authenticator once a code from it checks out. It will not
// REPLACE one: a session left open on a shared screen would otherwise be enough to
// swap someone's authenticator for the intruder's. Replacing goes through
// RemoveMFA, which needs the password and a current code.
func (s *Service) EnrollMFA(ctx context.Context, c Caller, secret, code, portalURL string) error {
	if !validOTPSecret(secret) || !VerifyCode(secret, code, s.Now()) {
		return ErrCodeInvalid
	}
	if on, err := c.Realm.HasOTP(ctx, c.UserID); err != nil {
		return err
	} else if on {
		return ErrMFAAlreadyOn
	}
	if err := c.Realm.SetOTP(ctx, c.UserID, secret); err != nil {
		return err
	}
	subj, body := mfaAddedEmail(s.Product, s.Now(), portalURL)
	_ = s.mail(ctx, c.Email, subj, body)
	return nil
}

// RemoveMFA takes the caller's own authenticator off, which needs their password
// and a current code: a session left open on a shared screen must not be enough.
func (s *Service) RemoveMFA(ctx context.Context, c Caller, password, code, portalURL string) error {
	switch chk, err := c.Realm.CheckPassword(ctx, c.Login, password, code); {
	case err != nil:
		return err
	case chk != CheckOK:
		return ErrBadCredentials
	}
	if err := c.Realm.RemoveOTP(ctx, c.UserID); err != nil {
		return err
	}
	subj, body := mfaRemovedEmail(s.Product, s.Now(), portalURL, false)
	_ = s.mail(ctx, c.Email, subj, body)
	return nil
}

// AdminResetMFA is an administrator removing a member's authenticator — the lost
// phone. The member is signed out; if the organisation requires an authenticator
// they set up a new one at their next sign-in.
func (s *Service) AdminResetMFA(ctx context.Context, realm Realm, userID, portalURL string) error {
	u, err := realm.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	if err := realm.RemoveOTP(ctx, u.ID); err != nil {
		return err
	}
	if err := realm.SignOutEverywhere(ctx, u.ID); err != nil {
		return fmt.Errorf("authenticator removed, but signing the user out failed: %w", err)
	}
	subj, body := mfaRemovedEmail(s.Product, s.Now(), portalURL, true)
	_ = s.mail(ctx, u.Email, subj, body)
	return nil
}
