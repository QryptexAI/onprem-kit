package pqc

import "testing"

// The gap this closed. A vendor's own CBOM names algorithms the way FIPS
// 203/204/205 do, so before these entries the one document in which a supplier
// states what its product supports produced FamilyUnknown for every line — and
// the fail-closed default would have read that as quantum-broken.
func TestNormalise_TheStandardsOwnSpellings(t *testing.T) {
	cases := map[string]Family{
		"ML-KEM-768":         FamilyMLKEM,
		"ML-KEM":             FamilyMLKEM,
		"ML-DSA-65":          FamilyMLDSA,
		"ML-DSA":             FamilyMLDSA,
		"SLH-DSA-SHA2-128s":  FamilySLHDSA,
		"SLH-DSA-SHAKE-256f": FamilySLHDSA,
	}
	for name, want := range cases {
		a, ok := Normalise(name)
		if !ok {
			t.Errorf("Normalise(%q) was not recognised", name)
			continue
		}
		if a.Family != want {
			t.Errorf("Normalise(%q) family = %q, want %q", name, a.Family, want)
		}
		if r, known := Assess(a); r != PQCReady || !known {
			t.Errorf("Assess(%q) = %q known=%v, want PQC_READY", name, r, known)
		}
	}
}

// One name, several spellings. CAMP's wire names and the FIPS spellings must
// resolve to the same identity, or a merged CBOM has two components where an
// agency has one algorithm.
func TestNormalise_SpellingsAgree(t *testing.T) {
	for _, pair := range [][2]string{
		{"ML-KEM-768", "mlkem768"},
		{"X25519MLKEM768", "x25519-mlkem-768"},
		{"SHA-256", "sha256"},
	} {
		a, okA := Normalise(pair[0])
		b, okB := Normalise(pair[1])
		if !okA || !okB {
			t.Errorf("%q/%q: recognised %v/%v", pair[0], pair[1], okA, okB)
			continue
		}
		if a.Family != b.Family || a.Parameter != b.Parameter {
			t.Errorf("%q gave %v, %q gave %v — the same algorithm must have one identity",
				pair[0], a, pair[1], b)
		}
	}
}

// The fallback is separator-insensitive, NOT fuzzy. An algorithm nobody
// standardised must still fail closed.
func TestNormalise_StillRefusesToGuess(t *testing.T) {
	for _, name := range []string{"ML-KEM-999", "SLH-DSA-SHA3-128s", "kyber", "post-quantum"} {
		if a, ok := Normalise(name); ok {
			t.Errorf("Normalise(%q) claimed to recognise it as %v", name, a)
		}
	}
}
