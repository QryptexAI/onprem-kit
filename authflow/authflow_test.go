package authflow

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode"
)

// RFC 6238 Appendix B, SHA-1 rows, truncated to six digits. The RFC's key is the
// ASCII string "12345678901234567890" — its BYTES are the HMAC key, which is
// exactly how Keycloak treats a stored secret.
func TestCodes_RFC6238Vectors(t *testing.T) {
	key := []byte("12345678901234567890")
	for _, v := range []struct {
		unix int64
		want string
	}{
		{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"},
		{1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"},
	} {
		if got := hotp(key, uint64(v.unix/otpPeriod)); got != v.want {
			t.Errorf("T=%d: got %s, want %s", v.unix, got, v.want)
		}
	}
}

func TestVerifyCode_AllowsOneStepOfSkew(t *testing.T) {
	secret, err := NewOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	at := func(d time.Duration) string { return hotp([]byte(secret), uint64(now.Add(d).Unix()/otpPeriod)) }
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		if !VerifyCode(secret, at(d), now) {
			t.Errorf("code from %v away was refused", d)
		}
	}
	if VerifyCode(secret, at(90*time.Second), now) {
		t.Error("a code three steps ahead was accepted")
	}
	if VerifyCode(secret, "12345", now) || VerifyCode(secret, "", now) {
		t.Error("a malformed code was accepted")
	}
	if !VerifyCode(secret, " "+at(0)[:3]+" "+at(0)[3:]+" ", now) {
		t.Error("a code typed with spaces was refused")
	}
}

func TestOTPSecret_IsWhatKeycloakAndTheAppBothRead(t *testing.T) {
	s, err := NewOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if !validOTPSecret(s) {
		t.Fatalf("generated secret %q fails validation", s)
	}
	for _, bad := range []string{"", s[:19], s + "A", strings.Replace(s, s[:1], `"`, 1), strings.ToLower(s)} {
		if validOTPSecret(bad) {
			t.Errorf("accepted malformed secret %q", bad)
		}
	}
	uri := OTPAuthURI("QryptexAI PKI", "ana@acme.test", s)
	if !strings.HasPrefix(uri, "otpauth://totp/QryptexAI%20PKI:ana@acme.test?") || !strings.Contains(uri, "digits=6") {
		t.Errorf("unexpected URI %s", uri)
	}
}

func TestResetToken_OnlyTheHashIsStoredAndTheLinkCarriesItInTheFragment(t *testing.T) {
	raw, hash, err := NewResetToken()
	if err != nil {
		t.Fatal(err)
	}
	if raw == hash || HashResetToken(raw) != hash || len(raw) < 40 {
		t.Fatalf("raw %q hash %q", raw, hash)
	}
	if got := ResetLink("https://acme.example/app/", raw); got != "https://acme.example/app/#reset="+raw {
		t.Errorf("link = %s", got)
	}
}

func TestTempPassword_MeetsEveryClassAndAvoidsLookalikes(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		p, err := TempPassword()
		if err != nil {
			t.Fatal(err)
		}
		if len(p) != 20 || seen[p] {
			t.Fatalf("length %d or repeat: %q", len(p), p)
		}
		seen[p] = true
		var up, lo, dg, sp bool
		for _, r := range p {
			up = up || unicode.IsUpper(r)
			lo = lo || unicode.IsLower(r)
			dg = dg || unicode.IsDigit(r)
			sp = sp || strings.ContainsRune("!@#$%*-_+=?", r)
		}
		if !up || !lo || !dg || !sp || strings.ContainsAny(p, "0O1lI") {
			t.Fatalf("%q is missing a class or has a lookalike", p)
		}
	}
}

func TestLimiter_CapsPerKeyWithinTheWindow(t *testing.T) {
	l := NewLimiter(3, time.Hour)
	now := time.Unix(0, 0)
	for i := 0; i < 3; i++ {
		if !l.Allow("a", now) {
			t.Fatalf("request %d refused", i+1)
		}
	}
	if l.Allow("a", now.Add(59*time.Minute)) {
		t.Error("fourth request inside the hour was allowed")
	}
	if !l.Allow("b", now) {
		t.Error("another address was limited by the first")
	}
	if !l.Allow("a", now.Add(61*time.Minute)) {
		t.Error("still limited after the window passed")
	}
}

func TestMemTokens_NewLinkCancelsOldAndEachWorksOnce(t *testing.T) {
	ctx := context.Background()
	m := NewMemTokens()
	exp := time.Now().Add(time.Hour)
	_ = m.Save(ctx, ResetToken{Hash: "h1", Realm: "r", UserID: "u", Expires: exp})
	_ = m.Save(ctx, ResetToken{Hash: "h2", Realm: "r", UserID: "u", Expires: exp})
	_ = m.Save(ctx, ResetToken{Hash: "h3", Realm: "r", UserID: "other", Expires: exp})
	if _, ok, _ := m.Take(ctx, "h1"); ok {
		t.Error("the earlier link still worked after a new one was issued")
	}
	if _, ok, _ := m.Take(ctx, "h2"); !ok {
		t.Error("the newest link did not work")
	}
	if _, ok, _ := m.Take(ctx, "h2"); ok {
		t.Error("a link worked twice")
	}
	if _, ok, _ := m.Take(ctx, "h3"); !ok {
		t.Error("another user's link was cancelled")
	}
}

// The reset email must not claim the password is unchanged-until-used AFTER
// changing it (PKI's old wording), and must say how long the link lasts.
func TestEmails_SayWhatIsTrue(t *testing.T) {
	_, body := resetLinkEmail("QryptexAI CAMP", "https://camp.example/#reset=x", ResetLinkTTL)
	if !strings.Contains(body, "expires in 30 minutes") || !strings.Contains(body, "Your password has not changed.") {
		t.Errorf("reset email:\n%s", body)
	}
	_, body = tempPasswordEmail("QryptoScan", "admin", "T3mp!pass", "https://qs.example", TempPasswordTTL, false)
	if !strings.Contains(body, "T3mp!pass") || !strings.Contains(body, "expires\nin 72 hours") {
		t.Errorf("temp email:\n%s", body)
	}
	_, body = passwordChangedEmail("QryptexAI PKI", time.Date(2026, 10, 30, 21, 5, 0, 0, time.UTC), "203.0.113.9", "https://qryptex.ai/app")
	if !strings.Contains(body, "Fri 30 Oct 2026 at 21:05 UTC from 203.0.113.9") || strings.Contains(strings.ToLower(body), "password:") {
		t.Errorf("changed email:\n%s", body)
	}
}
