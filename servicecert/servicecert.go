// Package servicecert validates the TLS material an administrator uploads
// before anything is done with it.
//
// It exists because the cost of finding out late is unusually high. Turning on
// TLS recreates the stack, and a certificate that turns out to be unreadable, or
// expired, or for another hostname, is discovered when the gateway will not
// start — with the product off the network and the person who pressed the button
// unable to reach the screen they pressed it on.
//
// So every check that can be made from the bytes is made from the bytes, before
// a single file is written.
package servicecert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/QryptexAI/onprem-kit/hostmatch"
)

var (
	ErrNoCert      = errors.New("no certificate")
	ErrNoKey       = errors.New("no private key")
	ErrBadPEM      = errors.New("this does not look like a PEM certificate")
	ErrBadKeyPEM   = errors.New("this does not look like a PEM private key")
	ErrKeyMismatch = errors.New("the private key does not match the certificate")
	ErrExpired     = errors.New("this certificate has expired")
	ErrNotYetValid = errors.New("this certificate is not valid yet")
)

// Details are what the screen shows back, so an administrator can confirm they
// uploaded what they meant to before anything restarts.
type Details struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
	DNSNames  []string  `json:"dnsNames"`
	// SelfSigned is reported rather than refused. On-prem estates run internal
	// CAs and self-signed certificates routinely, and refusing them would refuse
	// the normal case; the browser warning is the admin's to accept.
	SelfSigned bool `json:"selfSigned"`
	// DaysLeft is negative once expired.
	DaysLeft int `json:"daysLeft"`
}

// Validate checks an uploaded certificate and key against the hostname the
// service is to be served on.
//
// host may be empty, which skips the coverage check only — every other check
// still runs, so a certificate can be inspected before a hostname is decided.
func Validate(certPEM, keyPEM []byte, host string) (*Details, error) {
	if len(strings.TrimSpace(string(certPEM))) == 0 {
		return nil, ErrNoCert
	}
	if len(strings.TrimSpace(string(keyPEM))) == 0 {
		return nil, ErrNoKey
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, ErrBadPEM
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadPEM, err)
	}

	// The key is checked by pairing it with the certificate rather than by
	// parsing it alone: tls.X509KeyPair proves the private key belongs to this
	// public key, which is the thing that matters. A key that merely parses can
	// still be the wrong key, and nginx will not say so until it refuses to
	// start.
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		if kb, _ := pem.Decode(keyPEM); kb == nil {
			return nil, ErrBadKeyPEM
		}
		return nil, ErrKeyMismatch
	}

	d := &Details{
		Subject:    cert.Subject.CommonName,
		Issuer:     cert.Issuer.CommonName,
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
		DNSNames:   cert.DNSNames,
		SelfSigned: cert.Subject.String() == cert.Issuer.String(),
		DaysLeft:   int(time.Until(cert.NotAfter).Hours() / 24),
	}

	now := time.Now()
	if now.Before(cert.NotBefore) {
		return d, fmt.Errorf("%w: valid from %s", ErrNotYetValid, cert.NotBefore.Format(time.DateOnly))
	}
	if now.After(cert.NotAfter) {
		return d, fmt.Errorf("%w: it expired on %s", ErrExpired, cert.NotAfter.Format(time.DateOnly))
	}

	if strings.TrimSpace(host) != "" {
		// Wildcards are fine here and always were. What the certificate must do
		// is COVER the address the service will answer on; which name is printed
		// inside it stopped mattering when the node-lock moved to the configured
		// URL.
		if err := hostmatch.CertCovers(cert, host); err != nil {
			return d, err
		}
	}
	return d, nil
}
