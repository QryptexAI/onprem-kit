package cdxsign

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/QryptexAI/onprem-kit/cdxschema"
	"github.com/QryptexAI/onprem-kit/pqc"
)

// RFC 8785 §3.2.2, the example the RFC itself gives.
func TestCanonicalizeRFC8785Example(t *testing.T) {
	in := `{
	  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
	  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
	  "literals": [null, true, false]
	}`
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`
	got, err := Canonicalize([]byte(in))
	if err != nil || string(got) != want {
		t.Fatalf("got  %s\nwant %s (%v)", got, want, err)
	}
}

// ECMAScript number formatting at its edges (RFC 8785 Appendix B).
func TestCanonicalNumbers(t *testing.T) {
	for in, want := range map[string]string{
		"0": "0", "-0": "0", "1": "1", "-1.5": "-1.5", "1e21": "1e+21", "1e20": "100000000000000000000",
		"0.000001": "0.000001", "1e-7": "1e-7", "9007199254740992": "9007199254740992",
		"5e-324": "5e-324", "1.7976931348623157e308": "1.7976931348623157e+308",
	} {
		got, err := Canonicalize([]byte(in))
		if err != nil || string(got) != want {
			t.Errorf("%s -> %s, want %s (%v)", in, got, want, err)
		}
	}
	// Member order is by UTF-16 code units, not UTF-8 bytes.
	got, _ := Canonicalize([]byte(`{"\ud83d\ude00":1,"\ufb33":2}`))
	if string(got) != "{\"\U0001F600\":1,\"\uFB33\":2}" {
		t.Errorf("UTF-16 order: %s", got)
	}
}

func selfSigned(t *testing.T, key crypto.Signer) *x509.Certificate {
	t.Helper()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "camp.acme.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func document(t *testing.T) []byte {
	b := pqc.NewBOM(pqc.Tool{Vendor: "Qryptex", Name: "CAMP (aggregating)", Version: "v0"}, time.Now())
	a, _ := pqc.Normalise("RSA-2048")
	c := pqc.NewComponent(a, nil)
	c.Evidence = &pqc.Evidence{Occurrences: []pqc.Occurrence{{Location: "10.0.0.5:443",
		AdditionalContext: pqc.Context{{Name: "qryptex:feed", Value: "pki-london"}}}}}
	b.Components = append(b.Components, c)
	b.Metadata.Properties = []pqc.Property{{Name: "qryptex:feed/pki-london", Value: "CURRENT"}}
	doc, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestSignAndVerifyEveryKeyType(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	for name, key := range map[string]crypto.Signer{"ES256": p256, "ES384": p384, "ES512": p521, "PS256": rk, "Ed25519": ed} {
		cert := selfSigned(t, key)
		signed, err := Sign(document(t), key, []*x509.Certificate{cert})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(string(signed), `"algorithm": "`+name+`"`) {
			t.Errorf("%s: algorithm not named", name)
		}
		got, err := Verify(signed)
		if err != nil || !got.Equal(cert) {
			t.Fatalf("%s: verify %v", name, err)
		}
		// The signed document is still valid CycloneDX: JSF is its signature format.
		if err := cdxschema.Validate(signed); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// Formatting does not matter to the signature...
		var compact bytes.Buffer
		_ = json.Compact(&compact, signed)
		if _, err := Verify(compact.Bytes()); err != nil {
			t.Errorf("%s: compacted copy does not verify: %v", name, err)
		}
		// ...content does. Drop a source from the manifest, change an address.
		for _, tamper := range [][2]string{{"CURRENT", "STALE"}, {"10.0.0.5:443", "10.0.0.6:443"}} {
			bad := strings.Replace(string(signed), tamper[0], tamper[1], 1)
			if _, err := Verify([]byte(bad)); err == nil {
				t.Errorf("%s: a document with %q changed to %q still verifies", name, tamper[0], tamper[1])
			}
		}
		if _, err := Sign(signed, key, []*x509.Certificate{cert}); err == nil {
			t.Errorf("%s: signed twice", name)
		}
	}
}

func TestUnsignedAndUnsupported(t *testing.T) {
	if _, err := Verify(document(t)); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("unsigned: %v", err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := selfSigned(t, key)
	if _, err := Sign(document(t), odd{key}, []*x509.Certificate{cert}); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("unsupported key: %v", err)
	}
	// A signature claiming another algorithm than the certificate's key is refused.
	signed, _ := Sign(document(t), key, []*x509.Certificate{cert})
	if _, err := Verify([]byte(strings.Replace(string(signed), `"ES256"`, `"ES384"`, 1))); err == nil {
		t.Fatal("algorithm swap verified")
	}
}

// odd is a signer whose public key JSF cannot name.
type odd struct{ k *ecdsa.PrivateKey }

func (o odd) Public() crypto.PublicKey { return struct{}{} }
func (o odd) Sign(r io.Reader, d []byte, op crypto.SignerOpts) ([]byte, error) {
	return o.k.Sign(r, d, op)
}
