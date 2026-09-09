package pqc

import "testing"

// A network probe writes "<algorithm>-<bits>". CAMP's ingest builds exactly that
// with fmt.Sprintf("%s-%d", algorithm, bits), so every key it discovered used to
// miss the table and land as crypto/unknown/rsa3072 with no risk assessed — an
// agency's CBOM reporting "unclassified" for an estate of plain RSA.
func TestFamilyPlusParameterIsRecognised(t *testing.T) {
	for _, c := range []struct{ in, family, param string }{
		{"RSA-3072", "rsa", "3072"},
		{"RSA-2048", "rsa", "2048"},
		{"ECDSA-256", "ec", "256"},
		{"RSA 4096", "rsa", "4096"}, // a space is a separator too
		{"AES-256", "aes", "256"},
	} {
		a, ok := Normalise(c.in)
		if !ok {
			t.Errorf("Normalise(%q) not recognised", c.in)
			continue
		}
		if string(a.Family) != c.family || a.Parameter != c.param {
			t.Errorf("Normalise(%q) = family %q param %q, want %q/%q", c.in, a.Family, a.Parameter, c.family, c.param)
		}
	}
}

// The coarse and the specific stay DIFFERENT components, which is the property
// the whole merge rests on: QryptoScan sees "RSA" from a rule label, CAMP sees
// RSA-3072 on a wire, and asserting they are one component would make an
// agency's count wrong.
func TestCoarseAndSpecificRemainDistinctAfterSplitting(t *testing.T) {
	coarse, _ := Normalise("RSA")
	specific, _ := Normalise("RSA-3072")
	if BOMRef(coarse) == BOMRef(specific) {
		t.Fatalf("coarse and specific collapsed into one ref: %s", BOMRef(coarse))
	}
	if got := BOMRef(specific); got != "crypto/rsa/3072" {
		t.Errorf("BOMRef(RSA-3072) = %q, want crypto/rsa/3072", got)
	}
	// And the specific one is now ASSESSABLE, which it was not before.
	if _, ok := Assess(specific); !ok {
		t.Error("RSA-3072 still has no risk assessment")
	}
}

// Splitting must never invent a parameter set for a family whose sets are
// ENUMERATED by a standard. FIPS 205 defines SHA2 and SHAKE variants of SLH-DSA
// and no SHA3 one, so SLH-DSA-SHA3-128s names something that does not exist.
func TestEnumeratedFamiliesAreNeverSplit(t *testing.T) {
	for _, bad := range []string{"SLH-DSA-SHA3-128s", "ML-KEM-999", "ML-DSA-1"} {
		if a, ok := Normalise(bad); ok {
			t.Errorf("Normalise(%q) invented %v", bad, a)
		}
	}
	// The real ones still resolve exactly.
	for _, good := range []string{"ML-KEM-768", "ML-DSA-65", "SLH-DSA-SHA2-128s"} {
		if _, ok := Normalise(good); !ok {
			t.Errorf("Normalise(%q) stopped being recognised", good)
		}
	}
}
