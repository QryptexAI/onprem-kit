package pqc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The guarantee the whole package exists for: two products describing the same
// algorithm produce the same component, and two products describing DIFFERENT
// levels of detail do not.
func TestIdentityAcrossProducts(t *testing.T) {
	for _, c := range []struct {
		name       string
		qryptoscan string // what QryptoScan's rule pack calls it
		camp       string // what CAMP reads off the wire
		same       bool
	}{
		{"RSA is one component", "RSA", "rsa", true},
		{"DH is one component", "DH", "ffdhe2048", false},
		{"a named curve is not bare EC", "ECC", "secp256r1", false},
		{"ECDSA and ECDH share a family but neither names a curve", "ECDSA", "ecdh", true},
		{"two products seeing the same curve agree", "secp384r1", "SECP384R1", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			a, _ := Normalise(c.qryptoscan)
			b, _ := Normalise(c.camp)
			if got := SameComponent(a, b); got != c.same {
				t.Fatalf("SameComponent(%q=%s, %q=%s) = %v, want %v",
					c.qryptoscan, BOMRef(a), c.camp, BOMRef(b), got, c.same)
			}
		})
	}
}

// A coarse observation must never merge into a specific one. Asserting that
// "EC somewhere in code" IS "secp256r1 on db-04:443" is a fabrication, and it
// would make an agency's count wrong in a document they submit.
func TestCoarseNeverMergesIntoSpecific(t *testing.T) {
	coarse, _ := Normalise("ECC")
	specific, _ := Normalise("secp256r1")
	if SameComponent(coarse, specific) {
		t.Fatal("a curve-less EC observation merged into a named curve")
	}
	if !strings.HasPrefix(BOMRef(specific), BOMRef(coarse)) {
		t.Fatalf("the specific ref %q should still sit under the family ref %q so a view can group them",
			BOMRef(specific), BOMRef(coarse))
	}
}

// A bom-ref must never be derived from a database id — CAMP regenerates
// crypto_asset.id on every ingest. This asserts the property that matters:
// identity is a pure function of what the algorithm IS.
func TestBOMRefIsStableAndDerivedOnlyFromTheAlgorithm(t *testing.T) {
	a := Algorithm{Family: FamilyEC, Parameter: "secp256r1", Native: "secp256r1"}
	b := Algorithm{Family: FamilyEC, Parameter: "secp256r1", Native: "SECP256R1 (as seen on db-04)"}
	if BOMRef(a) != BOMRef(b) {
		t.Fatalf("the ref changed with the observed spelling: %q vs %q", BOMRef(a), BOMRef(b))
	}
	if strings.ContainsAny(BOMRef(a), " :") {
		t.Fatalf("a ref must be a single clean token, got %q", BOMRef(a))
	}
}

// The bug this caught in QS-1: RSA key transport IS key establishment, but its
// functions are encrypt/decrypt rather than keyderive. A predicate built only
// from the agreement functions silently omits it.
func TestPhaseOfRSAKeyTransportIsPhase3(t *testing.T) {
	got := PhaseOf(QuantumBroken, []Function{Encrypt, Decrypt})
	if got != PhaseKeyEstablishment {
		t.Fatalf("RSA key transport classified as %v, want key establishment", got)
	}
}

// …and the guard that keeps that from sweeping in every symmetric cipher.
func TestSymmetricCipherBelongsToNoDeadline(t *testing.T) {
	if got := PhaseOf(NotApplicable, []Function{Encrypt, Decrypt}); got != PhaseNone {
		t.Fatalf("a symmetric cipher classified as %v, want none", got)
	}
}

// A key generation site performs keygen and nothing more. Folding that into
// either deadline invents a denominator; folding it into "none" reports
// progress that was never measured.
func TestKeygenOnlyIsUndetermined(t *testing.T) {
	if got := PhaseOf(QuantumBroken, []Function{KeyGen}); got != PhaseUndetermined {
		t.Fatalf("a keygen-only site classified as %v, want undetermined", got)
	}
	if got := PhaseOf(QuantumBroken, nil); got != PhaseUndetermined {
		t.Fatalf("a site with no functions recorded classified as %v, want undetermined", got)
	}
}

// An RSA keypair feeding both a signer and a key exchange has two obligations
// under two dates, and it is one occurrence.
func TestAnAssetCanBeInBothPhases(t *testing.T) {
	ps := Phases(QuantumBroken, []Function{Sign, Verify, Encrypt, Decrypt})
	if len(ps) != 2 || ps[0] != PhaseKeyEstablishment || ps[1] != PhaseSignature {
		t.Fatalf("got %v, want the earlier deadline first then signatures", ps)
	}
}

// The memo's fail-closed default: treat as vulnerable anything not definitively
// known to be resistant — and tell the caller it is a default so the finding can
// be recorded at low confidence rather than beside a known break.
func TestUnknownAlgorithmFailsClosedAndSaysSo(t *testing.T) {
	a, known := Normalise("SomeVendorProprietaryKEX")
	if known {
		t.Fatal("an invented name was reported as recognised")
	}
	risk, confident := Assess(a)
	if risk != QuantumBroken {
		t.Fatalf("unknown algorithm assessed %v, want the fail-closed default", risk)
	}
	if confident {
		t.Fatal("the fail-closed default was reported as knowledge")
	}
}

// An unrecognised algorithm still has to be ITSELF. Collapsing everything we
// cannot name into one bucket would merge unrelated components.
func TestUnknownAlgorithmsStayDistinct(t *testing.T) {
	a, _ := Normalise("VendorAlgOne")
	b, _ := Normalise("VendorAlgTwo")
	if SameComponent(a, b) {
		t.Fatalf("two different unknown algorithms merged: %q", BOMRef(a))
	}
}

func TestHybridGroupsAreRecognisedAsReady(t *testing.T) {
	a, known := Normalise("X25519MLKEM768")
	if !known || a.Family != FamilyHybridKEM {
		t.Fatalf("the de-facto default PQC group was not recognised: %+v", a)
	}
	if risk, _ := Assess(a); risk != PQCReady {
		t.Fatalf("a hybrid ML-KEM group assessed %v, want ready", risk)
	}
}

func TestEveryProfileKeyMatchesItsFamily(t *testing.T) {
	for k, p := range profiles {
		if k != p.Family {
			t.Errorf("profile keyed %q carries family %q", k, p.Family)
		}
	}
}

// Every family a native name maps to must have a profile, or Assess silently
// fails closed on an algorithm we actually do know about.
func TestEveryMappedFamilyHasAProfile(t *testing.T) {
	for name, a := range native {
		if _, ok := profiles[a.Family]; !ok {
			t.Errorf("%q maps to family %q, which has no profile", name, a.Family)
		}
	}
}

func TestBOMSerialisesAsCycloneDX(t *testing.T) {
	a, _ := Normalise("secp256r1")
	b := NewBOM(Tool{Vendor: "Qryptex", Name: "CAMP", Version: "v0.9.40"}, time.Unix(0, 0))
	b.Components = append(b.Components, NewComponent(a, []Function{KeyDerive}))

	out, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"bomFormat":"CycloneDX"`, `"specVersion":"1.6"`,
		`"type":"cryptographic-asset"`, `"bom-ref":"crypto/ec/secp256r1"`,
		`"primitive":"key-agree"`, `"parameterSetIdentifier":"secp256r1"`,
		`"cryptoFunctions":["keyderive"]`,
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("emitted document is missing %s\n%s", want, out)
		}
	}
}

// An unparameterised component must not emit an empty parameterSetIdentifier —
// an empty string is a claim about the parameter, where absence is not.
func TestCoarseComponentOmitsTheParameter(t *testing.T) {
	a, _ := Normalise("ECC")
	out, err := json.Marshal(NewComponent(a, []Function{KeyGen}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "parameterSetIdentifier") {
		t.Fatalf("a curve-less component named a parameter set:\n%s", out)
	}
}
