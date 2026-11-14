package cdxschema

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/QryptexAI/onprem-kit/pqc"
)

// A document built from pqc's types, with every part a product fills in, is valid.
// This is the test that keeps the kit's own types honest; each product's test
// then validates the document it actually exports.
func TestKitDocumentIsValid(t *testing.T) {
	b := pqc.NewBOM(pqc.Tool{Vendor: "Qryptex", Name: "test", Version: "v0"}, time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC))
	b.Metadata.Properties = []pqc.Property{{Name: "qryptex:coverage", Value: "1"}}
	for _, name := range []string{"RSA-2048", "ECDSA-256", "mldsa65", "slhdsasha2128s", "p384_mldsa65", "X25519MLKEM768", "AES-256-GCM", "SHA-256", "MD5", "made-up-cipher"} {
		a, _ := pqc.Normalise(name)
		c := pqc.NewComponent(a, []pqc.Function{pqc.Sign, pqc.Verify})
		c.Properties = []pqc.Property{{Name: "qryptex:pqcRisk", Value: "HIGH"}}
		c.Evidence = &pqc.Evidence{Occurrences: []pqc.Occurrence{{
			Location: "src/x.go", Line: 12,
			AdditionalContext: []pqc.Property{{Name: "agility", Value: "HARDCODED"}},
		}}}
		b.Components = append(b.Components, c)
	}
	doc, _ := json.Marshal(b)
	if err := Validate(doc); err != nil {
		t.Fatal(err)
	}
}

// Certificates, keys and protocols, as products emit them, are valid too.
func TestAssetDocumentIsValid(t *testing.T) {
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	b := pqc.NewBOM(pqc.Tool{Name: "test"}, now)
	f := pqc.CertificateFacts{Subject: "CN=www.acme.test", IssuerCN: "Acme Issuing", Issuer: "CN=Acme Issuing,O=Acme",
		Serial: "123456789", NotBefore: now, NotAfter: now.AddDate(1, 0, 0), KeyName: "RSA-2048", KeyBits: 2048,
		SignatureName: "SHA-256", Fingerprint: strings.Repeat("ab", 32), SPKI: strings.Repeat("cd", 32)}
	cert := pqc.NewCertificateComponent(f)
	cert.Evidence = &pqc.Evidence{Occurrences: []pqc.Occurrence{{Location: "10.0.0.5:443"}}}
	b.Components = append(b.Components, cert, *pqc.NewPublicKeyComponent(f))
	exp := now.AddDate(2, 0, 0)
	b.Components = append(b.Components, pqc.NewManagedKeyComponent(pqc.ManagedKey{Namespace: "kms", ID: "k-1", Name: "payments",
		Type: "private-key", State: pqc.KeyState("ACTIVE"), Algorithm: "mldsa65", Created: now, Expires: &exp}))
	b.Components = append(b.Components, pqc.NewProtocolComponent("tls", "TLSv1.3",
		[]pqc.CipherSuite{{Name: "TLS_AES_128_GCM_SHA256", Algorithms: []string{"crypto/aes/128"}, Identifiers: []string{"0x13,0x01"}}},
		[]string{pqc.AlgorithmRefFor("X25519MLKEM768")}))
	doc, _ := json.Marshal(b)
	if err := Validate(doc); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyDocumentIsValid(t *testing.T) {
	doc, _ := json.Marshal(pqc.NewBOM(pqc.Tool{Name: "test"}, time.Now()))
	if err := Validate(doc); err != nil {
		t.Fatal(err)
	}
}

// The validator must actually refuse things, or every test above proves nothing.
func TestInvalidDocumentsAreRefused(t *testing.T) {
	for name, doc := range map[string]string{
		"occurrence without a location": `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"cryptographic-asset","name":"x",
			"evidence":{"occurrences":[{"line":1}]}}]}`,
		"not CycloneDX": `{"bomFormat":"SPDX","specVersion":"1.6","version":1}`,
		"bad timestamp": `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"timestamp":"yesterday"}}`,
		"unknown primitive": `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"cryptographic-asset","name":"x",
			"cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"magic"}}}]}`,
		"not JSON": `{`,
	} {
		if err := Validate([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), "CycloneDX") && !strings.Contains(err.Error(), "JSON") {
			t.Errorf("%s: unhelpful error %v", name, err)
		}
	}
}
