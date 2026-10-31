package authflow

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Authenticator-app codes (TOTP, RFC 6238), in the form Keycloak stores them.
//
// Keycloak keeps an OTP secret as a string in secretData.value and uses that
// string's BYTES as the HMAC key. An authenticator app is given Base32 of the same
// bytes. So the secret is drawn from the Base32 alphabet, stored verbatim, and
// Base32-encoded once more for the QR code — the scheme PKI's org portal has used
// since 2026-07, which is why existing enrolments keep working.

const (
	otpAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	otpLength   = 20
	otpDigits   = 6
	otpPeriod   = 30 // seconds
)

// NewOTPSecret returns a fresh secret, stored as-is in Keycloak. 256 is a multiple
// of 32, so mapping a random byte onto the alphabet is uniform.
func NewOTPSecret() (string, error) {
	b := make([]byte, otpLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i, x := range b {
		b[i] = otpAlphabet[int(x)%len(otpAlphabet)]
	}
	return string(b), nil
}

// validOTPSecret reports whether s is a secret NewOTPSecret could have produced.
// The portal sends the secret back at enrolment, so this is untrusted input that
// ends up inside Keycloak's secretData.
func validOTPSecret(s string) bool {
	if len(s) != otpLength {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !strings.ContainsRune(otpAlphabet, rune(s[i])) {
			return false
		}
	}
	return true
}

// OTPAuthURI is the otpauth:// URI an authenticator app reads from the QR code.
func OTPAuthURI(issuer, account, secret string) string {
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(secret))
	q := url.Values{
		"secret":    {b32},
		"issuer":    {issuer},
		"algorithm": {"SHA1"},
		"digits":    {fmt.Sprint(otpDigits)},
		"period":    {fmt.Sprint(otpPeriod)},
	}
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + q.Encode()
}

// VerifyCode checks a six-digit code against the secret at now, allowing one step
// (30 s) of clock difference either way — a phone a little fast or slow still works.
func VerifyCode(secret, code string, now time.Time) bool {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != otpDigits {
		return false
	}
	step := now.Unix() / otpPeriod
	ok := 0
	for _, d := range []int64{-1, 0, 1} {
		ok |= subtle.ConstantTimeCompare([]byte(hotp([]byte(secret), uint64(step+d))), []byte(code))
	}
	return ok == 1
}

func hotp(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(buf[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", otpDigits, v%1_000_000)
}
