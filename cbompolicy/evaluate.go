package cbompolicy

import (
	"fmt"
	"sort"
	"time"

	"github.com/QryptexAI/onprem-kit/pqc"
)

// Violation is one occurrence of one component against one rule. It is the unit
// a migration plan is made of: a thing, where it is, and when it is due.
type Violation struct {
	RuleID   string `json:"ruleId"`
	RuleName string `json:"ruleName"`
	Kind     Kind   `json:"kind"`
	Action   Action `json:"action"`
	Why      string `json:"why,omitempty"`

	Component     string `json:"component"` // bom-ref
	ComponentName string `json:"componentName"`
	AssetType     string `json:"assetType"`
	// Location is the occurrence: a file and line, an address and port, a
	// pki:ca/… location. Empty when the component lists no occurrence.
	Location string `json:"location,omitempty"`
	Line     int    `json:"line,omitempty"`

	// Due is when the rule takes effect. InForce false means it has not yet:
	// the violation is known, and has a date.
	Due     time.Time `json:"due"`
	InForce bool      `json:"inForce"`
	// Detail is the measured fact behind it: "2048 bits, below 3072",
	// "valid 825 days, more than 398".
	Detail string `json:"detail,omitempty"`
}

// Result is what Evaluate found, and how much it looked at. A clean result over
// no rules and a clean result over twelve are different answers.
type Result struct {
	Violations    []Violation `json:"violations"`
	RulesInForce  int         `json:"rulesInForce"`
	RulesUpcoming int         `json:"rulesUpcoming"`
	// Components is how many components the document had.
	Components int `json:"components"`
	// Notes say what could not be evaluated, so silence is never mistaken for
	// compliance.
	Notes []string `json:"notes,omitempty"`
}

// Failing is the in-force FAIL violations: what an enforcement point refuses on.
func (r Result) Failing() []Violation {
	var out []Violation
	for _, v := range r.Violations {
		if v.InForce && v.Action == Fail {
			out = append(out, v)
		}
	}
	return out
}

// Options carries what only the evaluating product knows.
type Options struct {
	// PriorityOf answers an occurrence's M-26-15 priority class from its
	// location (CAMP knows which addresses are HVAs). Nil means no product
	// knowledge: rules scoped to a priority class then match nothing, and the
	// result says so.
	PriorityOf func(location string) string
}

// Evaluate checks every enabled rule against every component, now and ahead:
// rules not yet in force still report, marked with their date.
//
// What each kind looks at:
//
//   - Deny and MinKeySize: algorithm components, and keys that are not a
//     certificate's public key (a KMS key's algorithm appears nowhere else). A
//     certificate's public key is not checked a second time: its algorithm is
//     already an algorithm component with the same occurrences.
//   - MaxLifetime: certificate components with both validity dates.
func Evaluate(rules []Rule, bom pqc.BOM, at time.Time, opt Options) Result {
	res := Result{Components: len(bom.Components)}
	var live []Rule
	scopedSkipped := 0
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if r.InForce(at) {
			res.RulesInForce++
		} else {
			res.RulesUpcoming++
		}
		if r.PriorityClass != "" && opt.PriorityOf == nil {
			scopedSkipped++
			continue
		}
		live = append(live, r)
	}
	if scopedSkipped > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"%d rule(s) apply only to a priority class, which this product cannot tell; they were not evaluated", scopedSkipped))
	}
	if len(live) == 0 && scopedSkipped == 0 {
		res.Notes = append(res.Notes, "No rule is enabled. Nothing was checked.")
	}

	for _, c := range bom.Components {
		ref, detailOf := subjectOf(c)
		for _, r := range live {
			detail, ok := breaks(r, c, ref, detailOf)
			if !ok {
				continue
			}
			for _, o := range occurrences(c) {
				if r.PriorityClass != "" && !coversPriority(r.PriorityClass, opt.PriorityOf(o.Location)) {
					continue
				}
				res.Violations = append(res.Violations, Violation{
					RuleID: r.ID, RuleName: r.Name, Kind: r.Kind, Action: r.Action, Why: r.Why,
					Component: c.BOMRef, ComponentName: c.Name, AssetType: c.AssetType(),
					Location: o.Location, Line: o.Line,
					Due: r.EffectiveFrom, InForce: r.InForce(at), Detail: detail,
				})
			}
		}
	}
	// In force first, failures before warnings, then by due date and place, so
	// the first screenful is what matters now.
	sort.SliceStable(res.Violations, func(i, j int) bool {
		a, b := res.Violations[i], res.Violations[j]
		if a.InForce != b.InForce {
			return a.InForce
		}
		if a.Action != b.Action {
			return a.Action == Fail
		}
		if !a.Due.Equal(b.Due) {
			return a.Due.Before(b.Due)
		}
		if a.Component != b.Component {
			return a.Component < b.Component
		}
		return a.Location < b.Location
	})
	return res
}

// subjectOf is the algorithm ref a component is checked as, for Deny and
// MinKeySize, and the key size it states, if any. Empty ref: not checked.
func subjectOf(c pqc.Component) (string, int) {
	cp := c.CryptoProps
	if cp == nil {
		return "", 0
	}
	switch cp.AssetType {
	case "algorithm":
		return c.BOMRef, 0
	case "related-crypto-material":
		m := cp.MaterialProps
		if m == nil || m.Type == "public-key" || m.AlgorithmRef == "" {
			return "", 0
		}
		return m.AlgorithmRef, m.Size
	}
	return "", 0
}

// breaks decides whether one component breaks one rule, and says how.
func breaks(r Rule, c pqc.Component, ref string, statedBits int) (string, bool) {
	switch r.Kind {
	case Deny:
		if ref == "" || !r.Subject.matchesRef(ref) {
			return "", false
		}
		if r.Risk != "" {
			return string(riskOfRef(ref)), true
		}
		return "", true
	case MinKeySize:
		if ref == "" || !r.Subject.matchesRef(ref) {
			return "", false
		}
		bits, ok := KeyBits(ref)
		if !ok && statedBits > 0 {
			bits, ok = statedBits, true
		}
		if !ok || bits >= r.Bits {
			return "", false
		}
		return fmt.Sprintf("%d bits, below %d", bits, r.Bits), true
	case MaxLifetime:
		cp := c.CryptoProps
		if cp == nil || cp.AssetType != "certificate" || cp.CertProps == nil ||
			cp.CertProps.NotValidBefore == nil || cp.CertProps.NotValidAfter == nil {
			return "", false
		}
		days := LifetimeDays(*cp.CertProps.NotValidBefore, *cp.CertProps.NotValidAfter)
		if days <= r.Days {
			return "", false
		}
		return fmt.Sprintf("valid %d days, more than %d", days, r.Days), true
	}
	return "", false
}

// LifetimeDays is a certificate's validity in whole days, rounded up: a
// certificate valid for 398 days and one second is valid for 399.
func LifetimeDays(notBefore, notAfter time.Time) int {
	d := notAfter.Sub(notBefore)
	days := int(d / (24 * time.Hour))
	if d%(24*time.Hour) != 0 {
		days++
	}
	return days
}

// occurrences is a component's occurrences, or one empty one so a component
// that lists none still reports.
func occurrences(c pqc.Component) []pqc.Occurrence {
	if c.Evidence == nil || len(c.Evidence.Occurrences) == 0 {
		return []pqc.Occurrence{{}}
	}
	return c.Evidence.Occurrences
}
