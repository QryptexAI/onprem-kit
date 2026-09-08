// Package pqc is the vocabulary CAMP and QryptoScan have to share.
//
// M-26-15 Appendix A §6 asks for *a* central CBOM, not several. Both products
// will emit one and CAMP will merge them, and two independently written
// emitters produce documents that concatenate but do not merge.
//
// THE DELIVERABLE HERE IS THE IDENTITY FUNCTION, NOT THE TYPES. Types duplicate
// harmlessly: two products each declaring their own four-value risk enum emit
// identical JSON. Identity cannot. If CAMP decides a component is "RSA-2048 on
// db-04" and QryptoScan decides it is "RSA in payments/crypto.go:88", the merge
// has two components where an agency has one problem, and the estate is
// double-counted in a number somebody reports to OMB. See BOMRef in ref.go —
// everything else in this package exists to make its input well-defined.
//
// The vocabulary is not invented here. Risk restates the CHECK constraint that
// has been on QryptoScan's rule and finding tables since 0003, and Function is
// CycloneDX 1.6's cryptoFunctions, so the CBOM emits it without translation.
// Both products adopt these names rather than either owning them.
package pqc

// Risk is how a cryptographic asset stands against a cryptographically relevant
// quantum computer.
//
// The values are QryptoScan's, verbatim — its rule and finding tables have
// carried this CHECK constraint since migration 0003, which makes it the
// canonical spelling rather than one of two.
type Risk string

const (
	// QuantumBroken: Shor's algorithm defeats it outright. This is the
	// migration, not a warning.
	QuantumBroken Risk = "QUANTUM_BROKEN"
	// QuantumWeakened: Grover halves the effective strength. Survivable by
	// choosing larger parameters rather than a different algorithm.
	QuantumWeakened Risk = "QUANTUM_WEAKENED"
	// PQCReady: believed secure against a CRQC.
	PQCReady Risk = "PQC_READY"
	// NotApplicable: the quantum question does not arise. A broken hash or an
	// ECB mode is a real finding and belongs to neither deadline.
	NotApplicable Risk = "NOT_APPLICABLE"
)

// Quantum reports whether this risk puts an asset inside one of the memo's
// migration deadlines at all. NOT_APPLICABLE findings are real and are not
// migration work.
func (r Risk) Quantum() bool {
	return r == QuantumBroken || r == QuantumWeakened
}

// Function is CycloneDX 1.6's cryptoFunctions vocabulary.
//
// Deliberately not a coarse KEY_ESTABLISHMENT/SIGNATURE enum of our own. The
// CBOM emits these directly, and the coarse answer is always computable from
// the fine one where the reverse is not.
type Function string

const (
	KeyGen      Function = "keygen"
	Sign        Function = "sign"
	Verify      Function = "verify"
	Encrypt     Function = "encrypt"
	Decrypt     Function = "decrypt"
	Encapsulate Function = "encapsulate"
	Decapsulate Function = "decapsulate"
	Digest      Function = "digest"
	KeyDerive   Function = "keyderive"
	Tag         Function = "tag"
	Other       Function = "other"
)

// Phase is which of M-26-15's dated migration phases an asset belongs to.
type Phase int

const (
	// PhaseNone: not migration work. NOT_APPLICABLE risk, or PQC-ready already.
	PhaseNone Phase = iota
	// PhaseKeyEstablishment is Phase 3 — "all HVAs, high impact systems,
	// systems with highly sensitive data…" by 31 December 2030.
	PhaseKeyEstablishment
	// PhaseSignature is Phase 4 — the same population, during 2031.
	PhaseSignature
	// PhaseUndetermined: quantum-affected, but nothing observed says which
	// deadline. A key GENERATION site performs keygen and nothing more; what
	// the key is later used for is not knowable from that line.
	//
	// This is a real third answer, not a gap. A rollup that folds it into
	// PhaseNone reports progress it has not measured, and one that folds it
	// into either deadline invents a denominator.
	PhaseUndetermined
)

// keyEstablishment is the function set that puts an asset in Phase 3.
//
// ENCRYPT AND DECRYPT ARE IN IT, which is not obvious. Appendix A §2 lists "RSA
// Key Establishment" as its own row, and RSA key transport works by encrypting
// a symmetric key under a public key — so its functions are encrypt/decrypt,
// never keyderive. A set built only from the agreement functions silently omits
// every RSA key-transport site, which is a large share of what an agency has to
// migrate by 2030.
//
// Risk.Quantum() is what keeps this honest: without it, encrypt/decrypt would
// also match every symmetric cipher, which belongs to no deadline at all.
var keyEstablishment = map[Function]bool{
	Encapsulate: true, Decapsulate: true, KeyDerive: true,
	Encrypt: true, Decrypt: true,
}

var signature = map[Function]bool{Sign: true, Verify: true}

// PhaseOf classifies an asset against the memo's deadlines.
//
// An asset can carry both — an RSA key generated for a signer and a key
// exchange has two obligations under two dates. Phase 3 is returned first
// because it is the earlier deadline and the one that governs recorded traffic;
// callers needing both should use Phases.
func PhaseOf(r Risk, fs []Function) Phase {
	ps := Phases(r, fs)
	return ps[0]
}

// Phases returns every deadline an asset belongs to, earliest first. It always
// returns at least one element.
func Phases(r Risk, fs []Function) []Phase {
	if !r.Quantum() {
		return []Phase{PhaseNone}
	}
	var out []Phase
	for _, f := range fs {
		if keyEstablishment[f] {
			out = append(out, PhaseKeyEstablishment)
			break
		}
	}
	for _, f := range fs {
		if signature[f] {
			out = append(out, PhaseSignature)
			break
		}
	}
	if len(out) == 0 {
		// Quantum-affected and nothing says which deadline — keygen only, or no
		// functions recorded at all.
		return []Phase{PhaseUndetermined}
	}
	return out
}

func (p Phase) String() string {
	switch p {
	case PhaseKeyEstablishment:
		return "key establishment (Phase 3, 31 December 2030)"
	case PhaseSignature:
		return "signatures (Phase 4, 2031)"
	case PhaseUndetermined:
		return "undetermined"
	}
	return "not migration work"
}
