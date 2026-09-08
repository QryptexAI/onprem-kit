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
	if p := normaliseParam(a.Parameter); p != "" {
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
