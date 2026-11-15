package pqc

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"strings"
	"time"
)

// Certificates, keys and protocols as CycloneDX 1.6 assets, beside algorithms.
//
// An algorithm component says "RSA-2048 is in use". These say what carries it:
// the certificate deployed at an address, the key in a KMS, the TLS version an
// endpoint accepts. Each one points at the algorithm components it uses
// (signatureAlgorithmRef, algorithmRef, a cipher suite's algorithms), so the
// algorithm view of version 1 stays exactly as it was.
//
// As with algorithms, IDENTITY IS DEFINED HERE AND NOWHERE ELSE: PKI and CAMP
// must give one certificate the same bom-ref, or the merge cannot say "PKI issued
// this and it is deployed at 10.0.0.5:443".

// CertificateProperties is CycloneDX's certificateProperties.
type CertificateProperties struct {
	SubjectName           string     `json:"subjectName,omitempty"`
	IssuerName            string     `json:"issuerName,omitempty"`
	NotValidBefore        *time.Time `json:"notValidBefore,omitempty"`
	NotValidAfter         *time.Time `json:"notValidAfter,omitempty"`
	SignatureAlgorithmRef string     `json:"signatureAlgorithmRef,omitempty"`
	SubjectPublicKeyRef   string     `json:"subjectPublicKeyRef,omitempty"`
	CertificateFormat     string     `json:"certificateFormat,omitempty"`
}

// RelatedCryptoMaterialProperties is CycloneDX's relatedCryptoMaterialProperties,
// used here for keys. Never the key material itself: Value is deliberately absent.
type RelatedCryptoMaterialProperties struct {
	// Type: public-key, private-key or secret-key.
	Type string `json:"type"`
	ID   string `json:"id,omitempty"`
	// State: pre-activation, active, suspended, deactivated, compromised, destroyed.
	State          string     `json:"state,omitempty"`
	AlgorithmRef   string     `json:"algorithmRef,omitempty"`
	CreationDate   *time.Time `json:"creationDate,omitempty"`
	ExpirationDate *time.Time `json:"expirationDate,omitempty"`
	Size           int        `json:"size,omitempty"`
}

// ProtocolProperties is CycloneDX's protocolProperties.
type ProtocolProperties struct {
	// Type: tls, ssh, ipsec, ike, ….
	Type         string        `json:"type"`
	Version      string        `json:"version,omitempty"`
	CipherSuites []CipherSuite `json:"cipherSuites,omitempty"`
	// CryptoRefArray holds what a protocol uses outside a suite: a TLS key
	// exchange group, an SSH key exchange or host key algorithm.
	CryptoRefArray []string `json:"cryptoRefArray,omitempty"`
}

// CipherSuite is one suite, with the algorithm components it uses.
type CipherSuite struct {
	Name        string   `json:"name,omitempty"`
	Algorithms  []string `json:"algorithms,omitempty"`
	Identifiers []string `json:"identifiers,omitempty"`
}

// ---- identity -------------------------------------------------------------

// CertificateRef is a certificate's bom-ref: the issuer's common name and the
// serial number, which is how X.509 identifies a certificate (an issuer must not
// reuse a serial).
//
// The common name and not the full issuer DN, because that is what CAMP's probes
// have always stored, and a probe that has not been upgraded must still merge.
// The serial is in decimal, normalised (leading zeros and a sign make no
// difference). Hashed, because a common name is free text.
func CertificateRef(issuerCN, serial string) string {
	s := strings.TrimSpace(serial)
	if n, ok := new(big.Int).SetString(s, 10); ok {
		s = n.Abs(n).String()
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(issuerCN) + "\n" + s))
	return "crypto/certificate/" + hex.EncodeToString(sum[:16])
}

// CertificateRefFor is CertificateRef for a parsed certificate.
func CertificateRefFor(c *x509.Certificate) string {
	return CertificateRef(c.Issuer.CommonName, c.SerialNumber.String())
}

// PublicKeyRef is a public key's bom-ref, from the SHA-256 of its
// SubjectPublicKeyInfo (hex). Two certificates carrying one key share it, which
// is how key reuse shows up.
func PublicKeyRef(spkiSHA256 string) string {
	return "crypto/key/public/" + strings.ToLower(strings.TrimSpace(spkiSHA256))
}

// ManagedKeyRef is the bom-ref of a key held by a key manager: namespace "kms"
// and the key's own id. Only the product holding the key reports it.
func ManagedKeyRef(namespace, id string) string {
	return "crypto/key/" + normaliseParam(namespace) + "/" + strings.ToLower(strings.TrimSpace(id))
}

// ProtocolRef is a protocol's bom-ref: "crypto/protocol/tls/1.3",
// "crypto/protocol/ssh/2.0". The version is normalised so "TLSv1.3", "TLS 1.3"
// and "1.3" agree.
func ProtocolRef(typ, version string) string {
	t := normaliseParam(typ)
	v := normaliseVersion(version)
	if v == "" {
		return "crypto/protocol/" + t
	}
	return "crypto/protocol/" + t + "/" + v
}

func normaliseVersion(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimLeft(v, "abcdefghijklmnopqrstuvwxyz _-")
	var b strings.Builder
	for _, r := range v {
		if (r >= '0' && r <= '9') || r == '.' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Fingerprints returns a certificate's SHA-256 fingerprint and the SHA-256 of
// its SubjectPublicKeyInfo, both lowercase hex.
func Fingerprints(c *x509.Certificate) (cert, spki string) {
	a := sha256.Sum256(c.Raw)
	b := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(a[:]), hex.EncodeToString(b[:])
}

// ---- components -----------------------------------------------------------

// CertificateFacts is what a product knows about one certificate. CAMP fills it
// from what a probe recorded, PKI from the certificate itself (CertificateFactsFor).
type CertificateFacts struct {
	Subject   string
	IssuerCN  string
	Issuer    string // the full DN when known; IssuerCN otherwise
	Serial    string // decimal
	NotBefore time.Time
	NotAfter  time.Time
	// KeyName is the key as CertificateKeyName names it ("RSA-2048", "mldsa65").
	KeyName string
	KeyBits int
	// SignatureName is the signature as CertificateSignatureNames names it.
	SignatureName string
	// Fingerprint and SPKI are SHA-256 hex, when known. Without SPKI there is no
	// public-key component and no subjectPublicKeyRef.
	Fingerprint string
	SPKI        string
}

// CertificateFactsFor reads the facts from a parsed certificate.
func CertificateFactsFor(c *x509.Certificate) CertificateFacts {
	f := CertificateFacts{
		Subject: c.Subject.String(), IssuerCN: c.Issuer.CommonName, Issuer: c.Issuer.String(),
		Serial: c.SerialNumber.String(), NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC(),
		KeyName: CertificateKeyName(c),
	}
	if s := CertificateSignatureNames(c); len(s) > 0 {
		f.SignatureName = s[0]
	}
	f.Fingerprint, f.SPKI = Fingerprints(c)
	if a, ok := Normalise(f.KeyName); ok {
		f.KeyBits = keyBits(a)
	}
	return f
}

func keyBits(a Algorithm) int {
	var n int
	for _, r := range a.Parameter {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	if a.Family == FamilyRSA || a.Family == FamilyEC {
		return n
	}
	return 0
}

// AlgorithmRefFor is the bom-ref of the algorithm component a name normalises to,
// the same component Normalise + NewComponent would produce for it.
func AlgorithmRefFor(name string) string {
	if strings.TrimSpace(name) == "" {
		return ""
	}
	a, _ := Normalise(name)
	return BOMRef(a)
}

// NewCertificateComponent builds a certificate component. Its signature points at
// the signature's algorithm component, and its key at a public-key component when
// the key's hash is known (NewPublicKeyComponent makes that one).
func NewCertificateComponent(f CertificateFacts) Component {
	issuer := f.Issuer
	if issuer == "" {
		issuer = f.IssuerCN
	}
	name := f.Subject
	if name == "" {
		name = "certificate " + f.Serial
	}
	cp := &CertificateProperties{
		SubjectName: f.Subject, IssuerName: issuer,
		SignatureAlgorithmRef: AlgorithmRefFor(f.SignatureName),
		CertificateFormat:     "X.509",
	}
	if !f.NotBefore.IsZero() {
		t := f.NotBefore.UTC()
		cp.NotValidBefore = &t
	}
	if !f.NotAfter.IsZero() {
		t := f.NotAfter.UTC()
		cp.NotValidAfter = &t
	}
	if f.SPKI != "" {
		cp.SubjectPublicKeyRef = PublicKeyRef(f.SPKI)
	}
	props := []Property{{Name: "qryptex:serialNumber", Value: f.Serial}}
	if r := AlgorithmRefFor(f.KeyName); r != "" {
		// CycloneDX reaches the key's algorithm through the public-key component.
		// Without one (an older probe), this is the only link, so it is kept on both.
		props = append(props, Property{Name: "qryptex:publicKeyAlgorithmRef", Value: r})
	}
	if f.Fingerprint != "" {
		props = append(props, Property{Name: "qryptex:fingerprintSHA256", Value: f.Fingerprint})
	}
	return Component{
		Type: compCrypto, BOMRef: CertificateRef(f.IssuerCN, f.Serial), Name: name,
		CryptoProps: &CryptoProperties{AssetType: "certificate", CertProps: cp},
		Properties:  props,
	}
}

// NewPublicKeyComponent builds the public-key component a certificate's
// subjectPublicKeyRef points at. Nil when the key's hash is unknown.
func NewPublicKeyComponent(f CertificateFacts) *Component {
	if f.SPKI == "" {
		return nil
	}
	return &Component{
		Type: compCrypto, BOMRef: PublicKeyRef(f.SPKI), Name: f.KeyName + " public key",
		CryptoProps: &CryptoProperties{AssetType: "related-crypto-material", MaterialProps: &RelatedCryptoMaterialProperties{
			Type: "public-key", ID: strings.ToLower(f.SPKI), AlgorithmRef: AlgorithmRefFor(f.KeyName), Size: f.KeyBits,
		}},
	}
}

// ManagedKey is a key a key manager holds, described by its metadata only.
type ManagedKey struct {
	Namespace string // "kms"
	ID        string
	Name      string
	// Type: private-key (an asymmetric key pair) or secret-key (symmetric).
	Type      string
	State     string // a CycloneDX state; see KeyState
	Algorithm string // a name Normalise knows
	Size      int
	Created   time.Time
	Expires   *time.Time
}

// NewManagedKeyComponent builds a key component from a key manager's metadata.
func NewManagedKeyComponent(k ManagedKey) Component {
	m := &RelatedCryptoMaterialProperties{
		Type: k.Type, ID: k.ID, State: k.State, AlgorithmRef: AlgorithmRefFor(k.Algorithm), Size: k.Size,
		ExpirationDate: k.Expires,
	}
	if !k.Created.IsZero() {
		t := k.Created.UTC()
		m.CreationDate = &t
	}
	name := k.Name
	if name == "" {
		name = k.ID
	}
	return Component{
		Type: compCrypto, BOMRef: ManagedKeyRef(k.Namespace, k.ID), Name: name,
		CryptoProps: &CryptoProperties{AssetType: "related-crypto-material", MaterialProps: m},
	}
}

// KeyState maps a product's key status onto CycloneDX's states. Anything
// unrecognised is left empty rather than guessed.
func KeyState(status string) string {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "PENDING", "PRE_ACTIVATION", "CREATED", "PENDING_APPROVAL":
		return "pre-activation"
	case "ACTIVE", "ENABLED", "ROTATING":
		return "active"
	case "SUSPENDED", "DISABLED":
		return "suspended"
	case "DEACTIVATED", "RETIRED", "ROTATED", "EXPIRED", "ARCHIVED", "PENDING_DESTROY":
		return "deactivated"
	case "COMPROMISED":
		return "compromised"
	case "DESTROYED", "DELETED", "LOST":
		return "destroyed"
	}
	return ""
}

// NewProtocolComponent builds a protocol component.
func NewProtocolComponent(typ, version string, suites []CipherSuite, refs []string) Component {
	t := strings.ToLower(strings.TrimSpace(typ))
	v := normaliseVersion(version)
	name := strings.ToUpper(t)
	if v != "" {
		name += " " + v
	}
	return Component{
		Type: compCrypto, BOMRef: ProtocolRef(t, v), Name: name,
		CryptoProps: &CryptoProperties{AssetType: "protocol", ProtoProps: &ProtocolProperties{
			Type: t, Version: v, CipherSuites: suites, CryptoRefArray: refs,
		}},
	}
}

// AssetType is a component's CycloneDX assetType ("algorithm" for a component
// without crypto properties, which is what version 1 readers assumed).
func (c Component) AssetType() string {
	if c.CryptoProps == nil || c.CryptoProps.AssetType == "" {
		return "algorithm"
	}
	return c.CryptoProps.AssetType
}
