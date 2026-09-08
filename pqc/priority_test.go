package pqc

import "testing"

// The case the whole nullable-column design exists for: a container marked high
// impact, one subject inside it explicitly excluded.
func TestEffectivePriority_NoneOverridesTheContainer(t *testing.T) {
	got, inherited := EffectivePriority(NotPrioritised, HighImpact)
	if got != NotPrioritised || inherited {
		t.Fatalf("got %q inherited=%v, want NONE not inherited — an explicit exclusion "+
			"must beat the container default, or there is no way to say 'except that one'", got, inherited)
	}
}

func TestEffectivePriority_InheritsAndReportsIt(t *testing.T) {
	got, inherited := EffectivePriority("", HVA)
	if got != HVA || !inherited {
		t.Fatalf("got %q inherited=%v, want HVA inherited", got, inherited)
	}
	// Nothing set anywhere is outside the set, and that is also inherited: the
	// answer came from a default, not from anybody's judgement.
	got, inherited = EffectivePriority("", "")
	if got != NotPrioritised || !inherited {
		t.Fatalf("got %q inherited=%v, want NONE inherited", got, inherited)
	}
}

// Unclassified is not membership. Counting it in would inflate the denominator
// an agency reports against the 2030 deadline.
func TestIn_UnclassifiedIsOutside(t *testing.T) {
	for _, p := range []Priority{"", NotPrioritised} {
		if p.In() {
			t.Errorf("%q counted as prioritised", p)
		}
	}
	for _, p := range []Priority{HVA, HighImpact, HighlySensitive, AgencyDetermined} {
		if !p.In() {
			t.Errorf("%q not counted as prioritised", p)
		}
	}
}

// Valid backs the CHECK constraint. The empty string is unclassified and must be
// stored as NULL, so it is deliberately not valid here.
func TestValid_RejectsEmptyAndUnknown(t *testing.T) {
	for _, p := range []Priority{"", "HIGH", "hva", "MODERATE"} {
		if p.Valid() {
			t.Errorf("%q accepted", p)
		}
	}
	for _, p := range Priorities {
		if !p.Valid() {
			t.Errorf("%q rejected", p)
		}
	}
}
