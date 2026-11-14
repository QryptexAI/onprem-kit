package pqc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

// Naming a certificate's algorithms, for every product that reads certificates.
//
// CAMP reads them off the wire and PKI issues them. For their CBOM components
// to merge, both must give the same certificate the same names, so the names
// are made here and nowhere else.
//
// CLASSICAL KEYS KEEP THE NAMES CAMP HAS ALWAYS USED: Go's algorithm name and
// the key size, "RSA-2048", "ECDSA-256", "Ed25519-256". They are what CAMP's
// inventory and its existing documents already hold, so changing them would
// split every CAMP estate's components in two.
//
// KEYS GO CANNOT PARSE ARE NAMED FROM THEIR OID. Go 1.27 parses an ML-DSA,
// SLH-DSA, Ed448 or composite certificate but reports its key algorithm as 0,
// so naming from the parsed key would call every post-quantum certificate
// "0-0". The OIDs below were read from certificates made by the OpenSSL 3.5 +
// oqs-provider build PKI ships, not copied from a specification.

// oidNames maps a SubjectPublicKeyInfo or signature OID to a name Normalise knows.
// For these algorithms the key and the signature share one OID.
var oidNames = map[string]string{
	"2.16.840.1.101.3.4.3.17": "ML-DSA-44",
	"2.16.840.1.101.3.4.3.18": "ML-DSA-65",
	"2.16.840.1.101.3.4.3.19": "ML-DSA-87",
	"2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
	"2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
	"2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s",
	"2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f",
	"2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s",
	"2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
	"2.16.840.1.101.3.4.3.26": "SLH-DSA-SHAKE-128s",
	"2.16.840.1.101.3.4.3.27": "SLH-DSA-SHAKE-128f",
	"2.16.840.1.101.3.4.3.28": "SLH-DSA-SHAKE-192s",
	"2.16.840.1.101.3.4.3.29": "SLH-DSA-SHAKE-192f",
	"2.16.840.1.101.3.4.3.30": "SLH-DSA-SHAKE-256s",
	"2.16.840.1.101.3.4.3.31": "SLH-DSA-SHAKE-256f",
	// oqs-provider's experimental arc, as PKI's composites carry it.
	"1.3.9999.7.5": "p256_mldsa44",
	"1.3.9999.7.7": "p384_mldsa65",
	"1.3.9999.7.8": "p521_mldsa87",
	"1.3.101.112":  "Ed25519",
	"1.3.101.113":  "Ed448",
}

// CertificateKeyName names the certificate's public key.
func CertificateKeyName(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA-%d", k.Curve.Params().BitSize)
	case ed25519.PublicKey:
		return "Ed25519-256"
	}
	oid := spkiOID(c.RawSubjectPublicKeyInfo)
	if n, ok := oidNames[oid]; ok {
		return n
	}
	// Never dropped: an unrecognised key is still a component, named by its OID
	// so two products that meet it still agree.
	return "OID " + oid
}

// CertificateSignatureNames names what the issuer's signature on the
// certificate depends on, beyond the issuer's own key.
//
// For a classical signature that is the hash: the key half is the issuing CA's
// key, which is its own component already. A post-quantum, EdDSA or composite
// signature has no separate hash to name, so it is named as itself.
func CertificateSignatureNames(c *x509.Certificate) []string {
	switch c.SignatureAlgorithm {
	case x509.MD5WithRSA:
		return []string{"MD5"}
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1:
		return []string{"SHA-1"}
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS, x509.ECDSAWithSHA256, x509.DSAWithSHA256:
		return []string{"SHA-256"}
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		return []string{"SHA-384"}
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		return []string{"SHA-512"}
	}
	oid := signatureOID(c.Raw)
	if n, ok := oidNames[oid]; ok {
		return []string{n}
	}
	if oid == "" {
		return nil
	}
	return []string{"OID " + oid}
}

func spkiOID(raw []byte) string {
	var spki struct {
		Algorithm struct {
			OID    asn1.ObjectIdentifier
			Params asn1.RawValue `asn1:"optional"`
		}
		Key asn1.BitString
	}
	if _, err := asn1.Unmarshal(raw, &spki); err != nil {
		return ""
	}
	return spki.Algorithm.OID.String()
}

// signatureOID reads the outer signatureAlgorithm, which Go leaves unnamed for
// the algorithms it does not know.
func signatureOID(raw []byte) string {
	var cert struct {
		TBS       asn1.RawValue
		Algorithm struct {
			OID    asn1.ObjectIdentifier
			Params asn1.RawValue `asn1:"optional"`
		}
		Signature asn1.BitString
	}
	if _, err := asn1.Unmarshal(raw, &cert); err != nil {
		return ""
	}
	return cert.Algorithm.OID.String()
}
