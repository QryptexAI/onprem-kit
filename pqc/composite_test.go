package pqc

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

// RFC 10073 composites must name and classify as hybrid signatures, not as an
// unknown OID: CAMP reports an unknown key as unclassified, which would make
// every certificate PKI issues from v0.10.14 look worse than the OQS ones did.
func TestRFC10073Composites(t *testing.T) {
	for oid, want := range map[string]string{
		"1.3.6.1.5.5.7.6.40": "MLDSA44-ECDSA-P256-SHA256",
		"1.3.6.1.5.5.7.6.46": "MLDSA65-ECDSA-P384-SHA512",
		"1.3.6.1.5.5.7.6.54": "MLDSA87-ECDSA-P521-SHA512",
		"1.3.6.1.5.5.7.6.37": "MLDSA44-RSA2048-PSS-SHA256",
	} {
		var id asn1.ObjectIdentifier
		for _, n := range splitOID(oid) {
			id = append(id, n)
		}
		spki, err := asn1.Marshal(struct {
			Alg pkix.AlgorithmIdentifier
			Key asn1.BitString
		}{pkix.AlgorithmIdentifier{Algorithm: id}, asn1.BitString{Bytes: []byte{1, 2, 3}, BitLength: 24}})
		if err != nil {
			t.Fatal(err)
		}
		got := CertificateKeyName(&x509.Certificate{RawSubjectPublicKeyInfo: spki})
		if got != want {
			t.Errorf("%s named %q, want %q", oid, got, want)
		}
		a, ok := Normalise(got)
		if !ok || a.Family != FamilyHybridSig {
			t.Errorf("%s normalised to %+v (known=%v), want hybrid-sig", got, a, ok)
		}
	}
}

func splitOID(s string) []int {
	var out []int
	n := 0
	for _, c := range s + "." {
		if c == '.' {
			out = append(out, n)
			n = 0
			continue
		}
		n = n*10 + int(c-'0')
	}
	return out
}
