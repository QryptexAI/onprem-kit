package hostmatch

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestHost(t *testing.T) {
	for _, c := range []struct {
		in, want string
		wantErr  bool
	}{
		{in: "https://pki.acme.com", want: "pki.acme.com"},
		{in: "https://pki.acme.com:8443", want: "pki.acme.com"}, // port is not part of the binding
		{in: "http://PKI.Acme.COM", want: "pki.acme.com"},       // DNS is case-insensitive
		{in: "https://pki.acme.com.", want: "pki.acme.com"},     // trailing dot is the same name
		{in: "pki.acme.com", want: "pki.acme.com"},              // no scheme: accepted
		{in: "https://pki.acme.com/app/", want: "pki.acme.com"}, // path ignored
		{in: "http://[::1]:8443", want: "::1"},                  // IPv6 literal unwrapped
		{in: "http://192.168.1.20:8446", want: "192.168.1.20"},
		{in: "", wantErr: true},
		{in: "   ", wantErr: true},
		{in: "https://", wantErr: true},
	} {
		got, err := Host(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("Host(%q) = %q, wanted an error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("Host(%q) errored: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("Host(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A licence minted for one form of an address must match the other form, or
// customers get "wrong address" errors for addresses that are the same.
func TestEqual(t *testing.T) {
	for _, c := range []struct {
		lic, pub string
		want     bool
	}{
		{"https://pki.acme.com", "https://pki.acme.com", true},
		{"https://pki.acme.com", "https://pki.acme.com:8443", true}, // port differs
		{"https://PKI.acme.com", "https://pki.acme.com", true},      // case differs
		{"http://pki.acme.com", "https://pki.acme.com", true},       // scheme differs
		{"https://pki.acme.com", "https://staging.acme.com", false},
		{"https://pki.acme.com", "https://acme.com", false},
	} {
		ok, lh, ph, err := Equal(c.lic, c.pub)
		if err != nil {
			t.Fatalf("Equal(%q,%q): %v", c.lic, c.pub, err)
		}
		if ok != c.want {
			t.Errorf("Equal(%q,%q) = %v (%s vs %s), want %v", c.lic, c.pub, ok, lh, ph, c.want)
		}
	}
}

func TestIsLocal(t *testing.T) {
	local := []string{
		"localhost", "app.localhost", "pki.local", "box.internal", "x.home.arpa",
		"127.0.0.1", "::1", "10.1.2.3", "172.16.5.4", "192.168.1.20",
		"169.254.10.1", "pki-box", // single label
	}
	public := []string{
		"pki.acme.com", "acme.com", "8.8.8.8", "2606:4700::1111",
		"localhost.acme.com", // a real public name that merely starts with localhost
	}
	for _, h := range local {
		if !IsLocal(h) {
			t.Errorf("IsLocal(%q) = false, want true", h)
		}
	}
	for _, h := range public {
		if IsLocal(h) {
			t.Errorf("IsLocal(%q) = true, want false", h)
		}
	}
}

// makeCert builds a self-signed certificate carrying the given SANs. cn is used
// as the Common Name; pass sans=nil to produce the CN-only certificate an older
// internal CA would issue.
func makeCert(t *testing.T, cn string, sans []string, ips []net.IP) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     sans,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// The case that started this: a wildcard certificate serving a specific host.
func TestCertCovers_Wildcard(t *testing.T) {
	cert := makeCert(t, "*.company.com", []string{"*.company.com"}, nil)

	if err := CertCovers(cert, "https://prod.company.com"); err != nil {
		t.Errorf("wildcard should cover prod.company.com: %v", err)
	}
	// One label only, and not the bare domain — RFC 6125.
	for _, bad := range []string{"https://a.b.company.com", "https://company.com", "https://company.co"} {
		if err := CertCovers(cert, bad); err == nil {
			t.Errorf("wildcard must NOT cover %s", bad)
		}
	}
}

func TestCertCovers_Exact(t *testing.T) {
	cert := makeCert(t, "prod.company.com", []string{"prod.company.com"}, nil)
	if err := CertCovers(cert, "https://prod.company.com:8443"); err != nil {
		t.Errorf("exact match should cover, port and all: %v", err)
	}
	if err := CertCovers(cert, "https://other.company.com"); err == nil {
		t.Error("must not cover a different host")
	}
}

// Internal CAs still issue certificates with no SANs. Go ignores CN since 1.15,
// which would tell an administrator their valid certificate does not cover their
// own hostname.
func TestCertCovers_CNFallbackOnlyWithoutSANs(t *testing.T) {
	cnOnly := makeCert(t, "prod.company.com", nil, nil)
	if err := CertCovers(cnOnly, "https://prod.company.com"); err != nil {
		t.Errorf("CN-only certificate should be accepted for its CN: %v", err)
	}

	cnWildcard := makeCert(t, "*.company.com", nil, nil)
	if err := CertCovers(cnWildcard, "https://prod.company.com"); err != nil {
		t.Errorf("CN-only wildcard should cover one label: %v", err)
	}
	// The CN fallback is hand-rolled, so it needs the same adversarial cases as
	// the SAN path — a wildcard consumes EXACTLY one label. Without these, a
	// fallback that spans "a.b.company.com" passes every other test here.
	for _, bad := range []string{
		"https://a.b.company.com", // two labels
		"https://company.com",     // the bare domain
		"https://notcompany.com",  // suffix present but not on a label boundary
	} {
		if err := CertCovers(cnWildcard, bad); err == nil {
			t.Errorf("CN-only wildcard must NOT cover %s", bad)
		}
	}

	// With SANs present, CN must NOT be consulted — that is the rule Go tightened
	// for good reason, and the fallback must not quietly undo it.
	withSANs := makeCert(t, "prod.company.com", []string{"other.company.com"}, nil)
	if err := CertCovers(withSANs, "https://prod.company.com"); err == nil {
		t.Error("CN must be ignored when SANs are present")
	}
}

// A wildcard spanning a whole TLD would let one certificate claim the internet.
func TestCertCovers_RefusesTLDWildcard(t *testing.T) {
	for _, cn := range []string{"*.com", "*.local"} {
		cert := makeCert(t, cn, nil, nil)
		if err := CertCovers(cert, "https://anything"+cn[1:]); err == nil {
			t.Errorf("%q must not be accepted as covering a host", cn)
		}
	}
}

// Partial wildcards are not wildcards.
func TestCertCovers_RefusesPartialWildcard(t *testing.T) {
	cert := makeCert(t, "pr*.company.com", nil, nil)
	if err := CertCovers(cert, "https://prod.company.com"); err == nil {
		t.Error("partial wildcard must not match")
	}
}

func TestCertCovers_IPCertificate(t *testing.T) {
	cert := makeCert(t, "", nil, []net.IP{net.ParseIP("192.168.1.20")})
	if err := CertCovers(cert, "https://192.168.1.20:8443"); err != nil {
		t.Errorf("IP SAN should cover the IP: %v", err)
	}
}

func TestCertCovers_NilAndJunk(t *testing.T) {
	if err := CertCovers(nil, "https://x.com"); err == nil {
		t.Error("nil certificate must error")
	}
	cert := makeCert(t, "prod.company.com", []string{"prod.company.com"}, nil)
	if err := CertCovers(cert, ""); err == nil {
		t.Error("empty host must error")
	}
}
