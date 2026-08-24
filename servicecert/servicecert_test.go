package servicecert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

// pair builds a self-signed certificate and its key, in PEM.
func pair(t *testing.T, cn string, sans []string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     sans,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}

func good(t *testing.T, cn string, sans ...string) ([]byte, []byte) {
	t.Helper()
	return pair(t, cn, sans, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
}

func TestValidate_Accepts(t *testing.T) {
	c, k := good(t, "prod.company.com", "prod.company.com")
	d, err := Validate(c, k, "https://prod.company.com")
	if err != nil {
		t.Fatalf("a matching certificate was refused: %v", err)
	}
	if d.Subject != "prod.company.com" {
		t.Errorf("subject = %q", d.Subject)
	}
	if !d.SelfSigned {
		t.Error("a self-signed certificate should be reported as such")
	}
	if d.DaysLeft < 360 {
		t.Errorf("daysLeft = %d", d.DaysLeft)
	}
}

// The case that started all of this. A wildcard certificate must be accepted for
// the concrete host it covers.
func TestValidate_AcceptsWildcard(t *testing.T) {
	c, k := good(t, "*.company.com", "*.company.com")
	if _, err := Validate(c, k, "https://prod.company.com"); err != nil {
		t.Fatalf("a wildcard certificate was refused for a host it covers: %v", err)
	}
	// But it still must not cover a host it does not.
	if _, err := Validate(c, k, "https://a.b.company.com"); err == nil {
		t.Error("a wildcard was accepted for a two-label subdomain")
	}
}

// The certificate is fine and the key belongs to a different one. nginx would
// not say so until it refused to start, with the product already off the air.
func TestValidate_MismatchedKey(t *testing.T) {
	c, _ := good(t, "prod.company.com", "prod.company.com")
	_, otherKey := good(t, "prod.company.com", "prod.company.com")
	if _, err := Validate(c, otherKey, "https://prod.company.com"); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("want ErrKeyMismatch, got %v", err)
	}
}

func TestValidate_WrongHost(t *testing.T) {
	c, k := good(t, "prod.company.com", "prod.company.com")
	_, err := Validate(c, k, "https://staging.company.com")
	if err == nil {
		t.Fatal("a certificate for another host was accepted")
	}
	// The message has to name both, or the administrator is left guessing which
	// of the two things they typed is wrong.
	if !containsAll(err.Error(), "prod.company.com", "staging.company.com") {
		t.Errorf("the error should name both names, got: %v", err)
	}
}

func TestValidate_Expired(t *testing.T) {
	c, k := pair(t, "prod.company.com", []string{"prod.company.com"},
		time.Now().Add(-72*time.Hour), time.Now().Add(-24*time.Hour))
	d, err := Validate(c, k, "https://prod.company.com")
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
	// Still described, so the screen can say WHICH certificate expired and when.
	if d == nil || d.DaysLeft >= 0 {
		t.Error("an expired certificate should still be described, with a negative daysLeft")
	}
}

func TestValidate_NotYetValid(t *testing.T) {
	c, k := pair(t, "prod.company.com", []string{"prod.company.com"},
		time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour))
	if _, err := Validate(c, k, "https://prod.company.com"); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("want ErrNotYetValid, got %v", err)
	}
}

func TestValidate_Junk(t *testing.T) {
	c, k := good(t, "prod.company.com", "prod.company.com")
	for _, tc := range []struct {
		name      string
		cert, key []byte
		want      error
	}{
		{"no cert", nil, k, ErrNoCert},
		{"no key", c, nil, ErrNoKey},
		{"cert is not PEM", []byte("hello"), k, ErrBadPEM},
		{"key is not PEM", c, []byte("hello"), ErrBadKeyPEM},
	} {
		if _, err := Validate(tc.cert, tc.key, "https://prod.company.com"); !errors.Is(err, tc.want) {
			t.Errorf("%s: want %v, got %v", tc.name, tc.want, err)
		}
	}
}

// A certificate can be inspected before a hostname is settled.
func TestValidate_NoHostSkipsCoverageOnly(t *testing.T) {
	c, k := good(t, "prod.company.com", "prod.company.com")
	if _, err := Validate(c, k, ""); err != nil {
		t.Fatalf("with no host, only coverage should be skipped: %v", err)
	}
	// Expiry is still enforced without a host.
	ec, ek := pair(t, "x", []string{"x.company.com"},
		time.Now().Add(-72*time.Hour), time.Now().Add(-time.Hour))
	if _, err := Validate(ec, ek, ""); !errors.Is(err, ErrExpired) {
		t.Errorf("expiry must be checked even with no host, got %v", err)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
