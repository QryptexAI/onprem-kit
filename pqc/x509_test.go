package pqc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"testing"
	"time"
)

// Certificates OpenSSL 3.5 + oqs-provider made (the build PKI ships): the
// algorithms Go cannot parse. Their names come from the OID, and each must
// land in the right family, never "unknown".
func TestCertificateNamesFromOID(t *testing.T) {
	cases := []struct {
		file, key string
		family    Family
		ref       string
	}{
		{"mldsa44.der", "ML-DSA-44", FamilyMLDSA, "crypto/ml-dsa/mldsa44"},
		{"mldsa65.der", "ML-DSA-65", FamilyMLDSA, "crypto/ml-dsa/mldsa65"},
		{"mldsa87.der", "ML-DSA-87", FamilyMLDSA, "crypto/ml-dsa/mldsa87"},
		{"slh-dsa-sha2-128s.der", "SLH-DSA-SHA2-128s", FamilySLHDSA, "crypto/slh-dsa/slhdsasha2128s"},
		{"p256_mldsa44.der", "p256_mldsa44", FamilyHybridSig, "crypto/hybrid-sig/p256mldsa44"},
		{"p384_mldsa65.der", "p384_mldsa65", FamilyHybridSig, "crypto/hybrid-sig/p384mldsa65"},
		{"p521_mldsa87.der", "p521_mldsa87", FamilyHybridSig, "crypto/hybrid-sig/p521mldsa87"},
		{"ed448.der", "Ed448", FamilyEC, "crypto/ec/ed448"},
	}
	for _, c := range cases {
		der, err := os.ReadFile("testdata/certs/" + c.file)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		if got := CertificateKeyName(cert); got != c.key {
			t.Errorf("%s: key %q, want %q", c.file, got, c.key)
		}
		// Self-signed: the signature is the same algorithm as the key.
		if got := CertificateSignatureNames(cert); !reflect.DeepEqual(got, []string{c.key}) {
			t.Errorf("%s: signature %q, want [%q]", c.file, got, c.key)
		}
		a, _ := Normalise(c.key)
		if a.Family != c.family || BOMRef(a) != c.ref {
			t.Errorf("%s: %s %s, want %s %s", c.file, a.Family, BOMRef(a), c.family, c.ref)
		}
	}
}

// Classical keys must keep the exact names CAMP's scanner has always given them
// (Go's algorithm name and the key size), or PKI's components would not merge
// with what CAMP already reports for the same certificates.
func TestClassicalNamesMatchCAMP(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	cases := []struct {
		signer crypto.Signer
		sigAlg x509.SignatureAlgorithm
		key    string
		sig    []string
		ref    string
	}{
		{rsaKey, x509.SHA256WithRSA, "RSA-2048", []string{"SHA-256"}, "crypto/rsa/2048"},
		{p256, x509.ECDSAWithSHA256, "ECDSA-256", []string{"SHA-256"}, "crypto/ec/256"},
		{p384, x509.ECDSAWithSHA384, "ECDSA-384", []string{"SHA-384"}, "crypto/ec/384"},
		{edKey, x509.PureEd25519, "Ed25519-256", []string{"Ed25519"}, "crypto/ec/ed25519"},
	}
	for _, c := range cases {
		cert := selfSigned(t, c.signer, c.sigAlg)
		// What CAMP's scanner computes (camp-scanner tlsprobe.describeCert).
		var bits int
		switch k := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			bits = k.N.BitLen()
		case *ecdsa.PublicKey:
			bits = k.Curve.Params().BitSize
		case ed25519.PublicKey:
			bits = 256
		}
		camp := fmt.Sprintf("%s-%d", cert.PublicKeyAlgorithm.String(), bits)
		if got := CertificateKeyName(cert); got != c.key || got != camp {
			t.Errorf("key %q, want %q (CAMP says %q)", got, c.key, camp)
		}
		if got := CertificateSignatureNames(cert); !reflect.DeepEqual(got, c.sig) {
			t.Errorf("%s signature %q, want %q", c.key, got, c.sig)
		}
		if a, _ := Normalise(c.key); BOMRef(a) != c.ref {
			t.Errorf("%s ref %s, want %s", c.key, BOMRef(a), c.ref)
		}
	}
}

// The key and the signature of an EdDSA certificate are one component.
func TestEd25519KeyAndSignatureAgree(t *testing.T) {
	k, _ := Normalise("Ed25519-256")
	s, _ := Normalise("Ed25519")
	if BOMRef(k) != BOMRef(s) || BOMRef(k) == BOMRef(Algorithm{Family: FamilyEC, Parameter: "256"}) {
		t.Fatalf("key %s, signature %s", BOMRef(k), BOMRef(s))
	}
}

func TestHybridSignatureIsPQCReady(t *testing.T) {
	a, known := Normalise("p384_mldsa65")
	r, _ := Assess(a)
	if !known || r != PQCReady {
		t.Fatalf("p384_mldsa65: known=%v risk=%s", known, r)
	}
	if c := NewComponent(a, nil); c.CryptoProps.AlgProps.Primitive != "signature" {
		t.Fatalf("primitive %q", c.CryptoProps.AlgProps.Primitive)
	}
}

func selfSigned(t *testing.T, k crypto.Signer, alg x509.SignatureAlgorithm) *x509.Certificate {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), SignatureAlgorithm: alg,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
