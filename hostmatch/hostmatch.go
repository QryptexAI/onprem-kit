// Package hostmatch answers the two hostname questions the on-prem products
// keep asking: is this licence for the address we are actually served on, and
// does this certificate cover that address?
//
// Both used to be answered by pulling a name out of the TLS certificate. That is
// why wildcards were refused — `*.company.com` gives you no single hostname to
// hash into a node-lock. Taking the hostname from the configured service URL
// instead makes the certificate's own subject irrelevant to licensing, which
// both removes the wildcard restriction and stops two sources of truth
// disagreeing.
package hostmatch

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

var (
	// ErrNoHost: the URL has no host at all — usually a bare hostname pasted
	// without a scheme, which url.Parse reads as a path rather than a host.
	ErrNoHost = errors.New("no hostname in the URL")
	// ErrNotCovered: the certificate is valid, but not for this hostname.
	ErrNotCovered = errors.New("the certificate does not cover this hostname")
)

// Host extracts the comparable hostname from a service URL.
//
// The port is deliberately dropped. A licence is bound to a name, not to a
// socket: moving the service from :8443 to :443 is a deployment detail and must
// not invalidate the licence. Case is normalised because DNS is case-insensitive
// while string comparison is not, and a licence minted for "PKI.Acme.com" must
// match a PUBLIC_URL of "pki.acme.com".
//
// A trailing dot is stripped too: "host." and "host" are the same name to DNS,
// and only one of them will have been typed into the licence.
func Host(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", ErrNoHost
	}
	// Without a scheme, url.Parse puts everything in Path and leaves Host empty.
	// Accepting a bare hostname is friendlier than rejecting it, and the scheme
	// is not part of what we compare.
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("could not read the URL %q: %w", raw, err)
	}
	h := u.Hostname() // strips the port and the [] around an IPv6 literal
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	if h == "" {
		return "", ErrNoHost
	}
	return h, nil
}

// Equal reports whether a licence's URL claim and the configured service URL
// name the same host.
//
// Returns the two normalised hosts alongside, because the caller's error message
// should show what was compared. "This licence is for a different address" sends
// an administrator hunting; naming both values ends the question.
func Equal(licenceURL, publicURL string) (ok bool, licenceHost, publicHost string, err error) {
	licenceHost, err = Host(licenceURL)
	if err != nil {
		return false, "", "", fmt.Errorf("licence URL: %w", err)
	}
	publicHost, err = Host(publicURL)
	if err != nil {
		return false, licenceHost, "", fmt.Errorf("service URL: %w", err)
	}
	return licenceHost == publicHost, licenceHost, publicHost, nil
}

// IsLocal reports whether a host is one nobody can get a public certificate for
// and nobody outside the machine can reach.
//
// This is what lets an evaluation run on a laptop. A trial on
// http://localhost:8446 or http://192.168.1.20:8446 is the normal way somebody
// first sees the product, and refusing it because the hostname is not a real
// FQDN would make the strict URL check unusable exactly where it matters least.
func IsLocal(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if h == "" {
		return false
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") ||
		h == "local" || strings.HasSuffix(h, ".local") ||
		strings.HasSuffix(h, ".internal") || strings.HasSuffix(h, ".home.arpa") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		// Link-local covers 169.254/16 and fe80::/10 — a machine that came up
		// without DHCP, which is a real state for an appliance on a bench.
		return ip.IsLoopback() || ip.IsPrivate() ||
			ip.IsLinkLocalUnicast() || ip.IsUnspecified()
	}
	// A single-label name — "pki-box", a Docker service name, a Kubernetes
	// service — is not resolvable outside its own network and cannot hold a
	// public certificate.
	return !strings.Contains(h, ".")
}

// CertCovers reports whether cert is valid for host, wildcards included.
//
// The matching itself is x509.Certificate.VerifyHostname, deliberately rather
// than a hand-rolled comparison: RFC 6125 has sharp edges — the wildcard must be
// the whole leftmost label, it matches exactly one label so `*.company.com` does
// not cover `a.b.company.com`, and it must not be allowed to span a public
// suffix. Go's implementation already has those right, and a bug here is a
// certificate accepted for a name it was never issued for.
//
// The one thing added on top is a Common Name fallback, used ONLY when the
// certificate carries no SANs at all. Go stopped honouring CN in 1.15, which is
// correct for the public web and wrong for on-prem: internal CAs still issue
// CN-only certificates, and an administrator whose corporate PKI produced one
// would otherwise be told their valid certificate does not cover their own host,
// with nothing in the message explaining why.
func CertCovers(cert *x509.Certificate, host string) error {
	if cert == nil {
		return errors.New("no certificate")
	}
	h, err := Host(host)
	if err != nil {
		return err
	}
	if err := cert.VerifyHostname(h); err == nil {
		return nil
	}
	if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 && cert.Subject.CommonName != "" {
		if matchCN(cert.Subject.CommonName, h) {
			return nil
		}
	}
	return fmt.Errorf("%w: certificate is for %s, service is %s",
		ErrNotCovered, strings.Join(names(cert), ", "), h)
}

// matchCN applies the same wildcard rule Go applies to SANs, to a lone CN.
func matchCN(cn, host string) bool {
	cn = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cn)), ".")
	if cn == host {
		return true
	}
	if !strings.HasPrefix(cn, "*.") {
		return false
	}
	// The wildcard is the ENTIRE leftmost label. "f*.company.com" is a partial
	// wildcard, which RFC 6125 discourages and browsers reject.
	suffix := cn[1:] // ".company.com"
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	// Exactly one label may be consumed: `*.company.com` covers
	// `prod.company.com` but not `a.b.company.com`, and not the bare domain.
	label := strings.TrimSuffix(host, suffix)
	if label == "" || strings.Contains(label, ".") {
		return false
	}
	// Refuse a wildcard that would span a whole top-level domain. Not a full
	// public-suffix list — just enough that "*.com" cannot be presented as
	// covering every host on the internet.
	return strings.Count(suffix, ".") >= 2
}

// names lists what a certificate actually claims, for the error message.
func names(cert *x509.Certificate) []string {
	out := append([]string{}, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		out = append(out, ip.String())
	}
	if len(out) == 0 && cert.Subject.CommonName != "" {
		out = append(out, cert.Subject.CommonName)
	}
	if len(out) == 0 {
		return []string{"(no names)"}
	}
	return out
}
