package pqc

import "strings"

// BOMRef returns the stable identity of a cryptographic asset, for a CycloneDX
// component's bom-ref.
//
// THIS IS THE POINT OF THE PACKAGE. Both products call it; neither implements
// it. Everything else here exists to make its input well-defined.
//
// Three properties it has to have, and one it must not:
//
//	STABLE ACROSS SCANS. It must never be derived from a database id. CAMP's
//	crypto_asset.id is regenerated on every ingest — ClearScannedCryptoAssets
//	deletes an asset's rows immediately before they are re-recorded — so a
//	bom-ref built from it would change on every scan and every merge would see
//	a new component. Even after CAMP-1 makes the row stable, a subject can be
//	withdrawn and re-observed. The identity is derived from what the algorithm
//	IS, not from where we happened to store it.
//
//	IDENTICAL ACROSS PRODUCTS. QryptoScan finding "RSA" and CAMP crypto_asset
//	"RSA" are one component with two occurrences, not two components.
//
//	DIFFERENT WHEN ONE IS COARSER. "EC, curve unspecified" and "EC/secp256r1"
//	get different refs and stay separate components. They are related, not
//	identical, and the grouping belongs in the view. Merging them would assert
//	something unverifiable about a customer's estate — plausible, wrong, and
//	wrong inside a document an agency submits to OMB.
//
//	NOT HUMAN-FACING. It is an identifier, not a label. Show Algorithm.Native.
func BOMRef(a Algorithm) string {
	fam := string(a.Family)
	if fam == "" {
		fam = string(FamilyUnknown)
	}
	b := strings.Builder{}
	b.WriteString("crypto/")
	b.WriteString(fam)
	p := normaliseParam(a.Parameter)
	if a.Family == FamilyEC {
		p = canonicalCurve(p)
	}
	if p != "" {
		b.WriteString("/")
		b.WriteString(p)
	} else if a.Family == FamilyUnknown && a.Native != "" {
		// An unrecognised algorithm still needs to be ITSELF rather than
		// collapsing into one "unknown" bucket with everything else we could
		// not name. Two products seeing the same unknown name still agree.
		b.WriteString("/")
		b.WriteString(normaliseParam(a.Native))
	}
	return b.String()
}

// normaliseParam lowercases and strips the punctuation that differs between two
// products naming the same thing — "SHA-256" and "sha256", "ffdhe2048" and
// "FFDHE-2048". Anything outside [a-z0-9] is dropped rather than replaced, so
// the result stays a single path segment.
func normaliseParam(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// SameComponent reports whether two algorithms are one component.
//
// Provided so the answer is not re-derived — and re-derived differently — at
// each call site. It is exactly BOMRef equality, which is the definition.
func SameComponent(a, b Algorithm) bool { return BOMRef(a) == BOMRef(b) }

// canonicalCurve gives each NIST curve one name, the SECG one CAMP sees on the
// wire. Before v0.6.0 the same curve was three components: "ECDSA-256" from a
// certificate key (crypto/ec/256), "secp256r1" from a negotiated group and
// "ECDSA_P256" from KMS (crypto/ec/p256).
//
// A bare size is a NIST curve because it comes from Go's certificate key name
// (CertificateKeyName, and CAMP's "<alg>-<bits>"), and Go's ECDSA implements
// only the NIST curves. Brainpool and the other curves carry their own names and
// are left alone.
func canonicalCurve(p string) string {
	switch p {
	case "224", "p224", "secp224r1", "nistp224":
		return "secp224r1"
	case "256", "p256", "secp256r1", "prime256v1", "nistp256":
		return "secp256r1"
	case "384", "p384", "secp384r1", "nistp384":
		return "secp384r1"
	case "521", "p521", "secp521r1", "nistp521":
		return "secp521r1"
	}
	return p
}
