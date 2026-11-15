package pqc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"testing"
)

// THE PARITY THAT MAKES THE MERGE WORK. PKI builds certificate facts from the
// certificate; CAMP from what its probe recorded (issuer common name, decimal
// serial, Go's signature name, "<alg>-<bits>"). Both must reach one bom-ref, and
// the same signature component.
func TestCertificateIdentityMatchesCAMP(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, c := range []struct {
		cert *x509.Certificate
		bits int
	}{
		{selfSigned(t, rsaKey, x509.SHA256WithRSA), 2048},
		{selfSigned(t, p256, x509.ECDSAWithSHA256), 256},
	} {
		pki := CertificateFactsFor(c.cert)
		camp := CertificateFacts{ // as camp-core reads crypto_asset.detail
			Subject: c.cert.Subject.String(), IssuerCN: c.cert.Issuer.CommonName,
			Serial:  c.cert.SerialNumber.String(),
			KeyName: fmt.Sprintf("%s-%d", c.cert.PublicKeyAlgorithm, c.bits),
		}
		if s := SignatureNamesForGoName(c.cert.SignatureAlgorithm.String()); len(s) > 0 {
			camp.SignatureName = s[0]
		}
		a, b := NewCertificateComponent(pki), NewCertificateComponent(camp)
		if a.BOMRef != b.BOMRef {
			t.Errorf("PKI %s, CAMP %s", a.BOMRef, b.BOMRef)
		}
		if a.CryptoProps.CertProps.SignatureAlgorithmRef != b.CryptoProps.CertProps.SignatureAlgorithmRef ||
			a.CryptoProps.CertProps.SignatureAlgorithmRef == "" {
			t.Errorf("signature refs %q vs %q", a.CryptoProps.CertProps.SignatureAlgorithmRef, b.CryptoProps.CertProps.SignatureAlgorithmRef)
		}
		if prop(a, "qryptex:publicKeyAlgorithmRef") != prop(b, "qryptex:publicKeyAlgorithmRef") {
			t.Errorf("key refs %q vs %q", prop(a, "qryptex:publicKeyAlgorithmRef"), prop(b, "qryptex:publicKeyAlgorithmRef"))
		}
		// PKI knows the key hash; an older probe does not.
		if a.CryptoProps.CertProps.SubjectPublicKeyRef == "" || b.CryptoProps.CertProps.SubjectPublicKeyRef != "" {
			t.Error("subjectPublicKeyRef must be set exactly when the key hash is known")
		}
		if k := NewPublicKeyComponent(pki); k == nil || k.CryptoProps.MaterialProps.Size != c.bits ||
			k.CryptoProps.MaterialProps.AlgorithmRef != prop(a, "qryptex:publicKeyAlgorithmRef") {
			t.Errorf("public key component %+v", k)
		}
	}
}

// A post-quantum certificate: Go cannot name its signature, so the facts come from
// the OIDs, and the identity still does not depend on that.
func TestPQCCertificateFacts(t *testing.T) {
	der, err := os.ReadFile("testdata/certs/mldsa65.der")
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	comp := NewCertificateComponent(CertificateFactsFor(c))
	if comp.CryptoProps.CertProps.SignatureAlgorithmRef != "crypto/ml-dsa/mldsa65" ||
		prop(comp, "qryptex:publicKeyAlgorithmRef") != "crypto/ml-dsa/mldsa65" {
		t.Fatalf("%+v %v", comp.CryptoProps.CertProps, comp.Properties)
	}
	if comp.BOMRef != CertificateRef(c.Issuer.CommonName, c.SerialNumber.String()) {
		t.Fatal("identity")
	}
}

func TestCertificateRefNormalisesTheSerial(t *testing.T) {
	if CertificateRef("Acme CA", "0042") != CertificateRef(" Acme CA ", "42") ||
		CertificateRef("Acme CA", "42") == CertificateRef("Acme CA", "43") ||
		CertificateRef("Acme CA", "42") == CertificateRef("Other CA", "42") {
		t.Fatal("serial or issuer normalisation")
	}
	if !strings.HasPrefix(CertificateRef("x", "1"), "crypto/certificate/") {
		t.Fatal("prefix")
	}
}

func TestProtocolRefNormalisesTheVersion(t *testing.T) {
	for _, v := range []string{"TLSv1.3", "TLS 1.3", "1.3", "tls1.3"} {
		if got := ProtocolRef("TLS", v); got != "crypto/protocol/tls/1.3" {
			t.Errorf("%q -> %s", v, got)
		}
	}
	if ProtocolRef("ssh", "") != "crypto/protocol/ssh" {
		t.Error("ssh")
	}
}

func TestKeyStateMapsOrStaysEmpty(t *testing.T) {
	for in, want := range map[string]string{"ACTIVE": "active", "disabled": "suspended", "DESTROYED": "destroyed", "weird": ""} {
		if got := KeyState(in); got != want {
			t.Errorf("%s -> %q", in, got)
		}
	}
}

func prop(c Component, name string) string {
	for _, p := range c.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

// One curve, one component, whoever names it: a certificate key ("ECDSA-256"),
// a negotiated group ("secp256r1"), KMS ("ECDSA_P256"), OpenSSL ("prime256v1").
func TestEveryNameForACurveIsOneComponent(t *testing.T) {
	for want, names := range map[string][]string{
		"crypto/ec/secp256r1": {"ECDSA-256", "secp256r1", "ECDSA_P256", "prime256v1", "P-256", "EC-256"},
		"crypto/ec/secp384r1": {"ECDSA-384", "secp384r1", "ECDSA_P384", "P-384"},
		"crypto/ec/secp521r1": {"ECDSA-521", "secp521r1", "P-521"},
	} {
		for _, n := range names {
			if got := AlgorithmRefFor(n); got != want {
				t.Errorf("%s -> %s, want %s", n, got, want)
			}
		}
	}
	if AlgorithmRefFor("EC") != "crypto/ec" || AlgorithmRefFor("x25519") != "crypto/ec/x25519" {
		t.Errorf("EC %s, x25519 %s", AlgorithmRefFor("EC"), AlgorithmRefFor("x25519"))
	}
}
