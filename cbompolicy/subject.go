package cbompolicy

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/QryptexAI/onprem-kit/pqc"
)

// selectorRef turns a rule's algorithm into the bom-ref it selects. A name with
// no parameter selects its family's ref ("RSA" → crypto/rsa), which covers every
// parameter below it. False for a name the kit does not recognise: a rule about
// an algorithm nobody can identify would silently match nothing.
func selectorRef(sel string) (string, bool) {
	sel = strings.TrimSpace(sel)
	if sel == "" {
		return "", false
	}
	if strings.Contains(sel, "/") {
		ref := strings.ToLower(sel)
		if !strings.HasPrefix(ref, "crypto/") {
			ref = "crypto/" + ref
		}
		return ref, true
	}
	a, ok := pqc.Normalise(sel)
	if !ok {
		return "", false
	}
	return pqc.BOMRef(a), true
}

// refCovers reports whether a selector ref covers a component's ref: the same
// ref, or a family ref over one of its parameters.
func refCovers(sel, ref string) bool {
	return ref == sel || strings.HasPrefix(ref, sel+"/")
}

// algorithmOfRef reads the family and parameter back out of an algorithm ref.
func algorithmOfRef(ref string) (pqc.Algorithm, bool) {
	rest, ok := strings.CutPrefix(ref, "crypto/")
	if !ok {
		return pqc.Algorithm{}, false
	}
	fam, param, _ := strings.Cut(rest, "/")
	return pqc.Algorithm{Family: pqc.Family(fam), Parameter: param}, true
}

// riskOfRef is the kit's verdict on an algorithm ref. An unrecognised family is
// quantum-broken: the memo's fail-closed default, the same as pqc.Assess.
func riskOfRef(ref string) pqc.Risk {
	a, ok := algorithmOfRef(ref)
	if !ok {
		return pqc.QuantumBroken
	}
	r, _ := pqc.Assess(a)
	return r
}

// matchesRef reports whether a subject covers an algorithm ref.
func (s Subject) matchesRef(ref string) bool {
	switch {
	case s.Algorithm != "":
		sel, ok := selectorRef(s.Algorithm)
		return ok && refCovers(sel, ref)
	case s.Risk != "":
		return strings.EqualFold(string(riskOfRef(ref)), s.Risk)
	}
	return false
}

// Matches reports whether a subject covers an algorithm named the way a product
// names it ("RSA-2048", "mldsa65", "ECDSA_P256"). It is how an enforcement point
// that checks one thing at a time, such as PKI at issuance, uses the same
// vocabulary as a CBOM evaluation.
func (s Subject) Matches(algorithm string) bool {
	a, _ := pqc.Normalise(algorithm)
	return s.matchesRef(pqc.BOMRef(a))
}

var digits = regexp.MustCompile(`\d+`)

// KeyBits is the key size an algorithm ref carries, where it carries one:
// RSA-2048 → 2048, secp384r1 → 384, ffdhe3072 → 3072, Ed25519 → 256,
// AES-128 → 128. False when the ref has no size (a bare family, or a
// post-quantum parameter set, whose strength is its NIST level, not a bit
// count). A minimum-size rule never guesses: an unknown size is not a violation.
func KeyBits(ref string) (int, bool) {
	a, ok := algorithmOfRef(ref)
	if !ok || a.Parameter == "" {
		return 0, false
	}
	switch a.Family {
	case pqc.FamilyRSA, pqc.FamilyDSA, pqc.FamilyDH, pqc.FamilyAES:
	case pqc.FamilyEC:
		switch {
		case a.Parameter == "ed25519" || a.Parameter == "x25519":
			return 256, true
		case a.Parameter == "ed448" || a.Parameter == "x448":
			return 448, true
		}
	default:
		return 0, false
	}
	n, err := strconv.Atoi(digits.FindString(a.Parameter))
	if err != nil || n == 0 {
		return 0, false
	}
	return n, true
}
