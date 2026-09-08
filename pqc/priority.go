package pqc

// The prioritised set, and why membership is not a boolean.
//
// M-26-15 Phase 3 scopes the 31 December 2030 key-establishment deadline to
// "all HVAs, high impact systems, systems with highly sensitive data, and
// systems that an agency determines are likely to be particularly vulnerable to
// CRQC-based attacks", and Phase 4 scopes 2031 to the same population.
//
// THAT IS FOUR ROUTES INTO ONE SET. An HVA flag plus an impact level covers two
// of them and leaves the other two homeless — and the fourth is explicitly a
// judgement the agency makes and has to defend, because Appendix B requires the
// plan to contain "a system prioritization strategy with risk-based
// justification". So membership carries its reason, and the reason is the
// column rather than a note beside it.
//
// It lives here because both products count against the same deadlines. CAMP
// prioritises assets and sites; QryptoScan prioritises scan targets and
// repositories. If the two spell the set differently, the dashboard that adds
// them up is adding two different things.

// Priority is a route into the prioritised set, or a considered exclusion.
type Priority string

const (
	// NotPrioritised means CONSIDERED AND EXCLUDED, which is not the same as
	// unclassified. The empty string is unclassified; this is an answer.
	NotPrioritised Priority = "NONE"
	// HVA — a designated High Value Asset.
	HVA Priority = "HVA"
	// HighImpact — FIPS 199 high.
	HighImpact Priority = "HIGH_IMPACT"
	// HighlySensitive — holds highly sensitive data.
	HighlySensitive Priority = "HIGHLY_SENSITIVE"
	// AgencyDetermined — the agency judges it particularly vulnerable. The route
	// that most needs a justification recorded with it, because it is the one
	// nothing else in the estate can corroborate.
	AgencyDetermined Priority = "AGENCY_DETERMINED"
)

// Priorities is every value the CHECK constraints in both products allow.
var Priorities = []Priority{NotPrioritised, HVA, HighImpact, HighlySensitive, AgencyDetermined}

// Valid reports whether p is one of the five. The empty string is NOT valid
// here: it means unclassified, and a caller storing it should store NULL.
func (p Priority) Valid() bool {
	for _, v := range Priorities {
		if p == v {
			return true
		}
	}
	return false
}

// In reports whether this class puts its subject inside the population Phase 3
// and Phase 4 are scoped to. Unclassified is OUTSIDE — an agency that has not
// classified a system has not asserted it is in scope.
func (p Priority) In() bool { return p != "" && p != NotPrioritised }

// EffectivePriority resolves membership through one level of inheritance.
//
// An operator wants to say "everything here is high impact" once rather than
// five hundred times, and still be able to say "except that one". So the
// subject's own class wins when it has one, the container's applies when it
// does not, and NONE is a real answer that overrides the container rather than
// falling through to it.
//
// COMPUTED, NOT MATERIALISED. A subject that moves container should inherit its
// new container's default rather than carry its old one, and a stored copy would
// have to be chased on every move.
func EffectivePriority(own, container Priority) (p Priority, inherited bool) {
	if own != "" {
		return own, false
	}
	if container != "" {
		return container, true
	}
	return NotPrioritised, true
}
