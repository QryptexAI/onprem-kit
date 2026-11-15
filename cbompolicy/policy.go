// Package cbompolicy is the crypto policy model the three products share: rules
// a compliance officer can read and edit as rows, and Evaluate, which checks a
// CycloneDX CBOM against them.
//
// # Tables, not a policy language
//
// Every rule is one row: what it is about, the limit, the date it takes effect,
// and whether breaking it warns or fails. That covers what crypto policy says in
// practice (deny an algorithm, a minimum key size, a maximum certificate
// lifetime, all dated), and a person can read it. A policy language nobody on the
// customer side writes would be complexity for its own sake.
//
// # One vocabulary, three enforcement points
//
// Each product enforces at its own point: PKI at issuance, QryptoScan in its
// build gate, CAMP over the organisation's combined CBOM. What they share is the
// meaning of a rule's subject. "RSA", "RSA-2048", "ECDSA_P256" and
// "QUANTUM_BROKEN" are resolved here, through pqc.Normalise and pqc.BOMRef, so a
// rule means the same algorithms in every product. Nothing here matches a
// component by its display name.
//
// # Dated rules are evaluated before their date
//
// A rule that takes effect in 2030 is still evaluated today. Its violations come
// back marked not yet in force, with the date they become due, which is what
// migration planning is built from. A rule that only appeared on its deadline
// would announce the problem on the day it is too late to fix.
package cbompolicy

import (
	"fmt"
	"strings"
	"time"

	"github.com/QryptexAI/onprem-kit/pqc"
)

// Kind is what a rule checks.
type Kind string

const (
	// Deny: the subject must not be in use.
	Deny Kind = "DENY"
	// MinKeySize: keys of the subject's family must be at least Bits.
	MinKeySize Kind = "MIN_KEY_SIZE"
	// MaxLifetime: certificates must be valid for at most Days. It has no
	// subject: it applies to every certificate.
	MaxLifetime Kind = "MAX_LIFETIME"
)

// PrioritisedSet as a rule's PriorityClass covers every class in M-26-15's
// prioritised set: anything classified, other than NONE.
const PrioritisedSet = "PRIORITISED"

// coversPriority reports whether a rule's class covers an occurrence's.
func coversPriority(rule, occurrence string) bool {
	switch {
	case rule == "":
		return true
	case strings.EqualFold(rule, PrioritisedSet):
		return occurrence != "" && !strings.EqualFold(occurrence, "NONE")
	}
	return strings.EqualFold(rule, occurrence)
}

// Action is what breaking a rule does. A warning is information; a failure is
// what an enforcement point refuses on.
type Action string

const (
	Warn Action = "WARN"
	Fail Action = "FAIL"
)

// Subject is what a rule is about: an algorithm or a risk class, never both.
//
// Algorithm is any name pqc.Normalise understands ("RSA", "RSA-2048",
// "ECDSA_P256", "ML-DSA-65") or a bom-ref ("crypto/rsa/2048", "rsa/2048"). A
// name without a parameter is the whole family: "RSA" covers RSA-2048 and
// RSA-4096. Risk is a pqc.Risk ("QUANTUM_BROKEN", "QUANTUM_WEAKENED").
type Subject struct {
	Algorithm string `json:"algorithm,omitempty"`
	Risk      string `json:"risk,omitempty"`
}

// Rule is one row of a policy.
type Rule struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind Kind   `json:"kind"`
	Subject
	Bits int `json:"bits,omitempty"` // MinKeySize
	Days int `json:"days,omitempty"` // MaxLifetime
	// PriorityClass narrows a rule to M-26-15's prioritised set: one class
	// (HVA, HIGH_IMPACT, HIGHLY_SENSITIVE, AGENCY_DETERMINED), or
	// PrioritisedSet for any of them. Empty is every occurrence. A product that
	// cannot tell an occurrence's class does not match a scoped rule, and says so.
	PriorityClass string    `json:"priorityClass,omitempty"`
	EffectiveFrom time.Time `json:"effectiveFrom"`
	Action        Action    `json:"action"`
	// Why is the clause the rule implements. A person blocked by it asks.
	Why     string `json:"why,omitempty"`
	Enabled bool   `json:"enabled"`
}

// InForce reports whether a rule applies at a moment.
func (r Rule) InForce(at time.Time) bool {
	return r.Enabled && !r.EffectiveFrom.After(at)
}

// Validate says what is wrong with a rule before it is stored, in words for the
// person who wrote it.
func (r Rule) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("a rule needs a name")
	}
	if r.Action != Warn && r.Action != Fail {
		return fmt.Errorf("action must be %s or %s", Warn, Fail)
	}
	if r.EffectiveFrom.IsZero() {
		return fmt.Errorf("a rule needs the date it takes effect")
	}
	subjects := 0
	if strings.TrimSpace(r.Algorithm) != "" {
		subjects++
	}
	if strings.TrimSpace(r.Risk) != "" {
		subjects++
		switch pqc.Risk(r.Risk) {
		case pqc.QuantumBroken, pqc.QuantumWeakened, pqc.PQCReady, pqc.NotApplicable:
		default:
			return fmt.Errorf("unknown risk class %q", r.Risk)
		}
	}
	switch r.Kind {
	case Deny:
		if subjects != 1 {
			return fmt.Errorf("a deny rule names exactly one algorithm or risk class")
		}
	case MinKeySize:
		if r.Risk != "" || r.Algorithm == "" {
			return fmt.Errorf("a minimum key size names an algorithm, such as RSA")
		}
		if r.Bits <= 0 {
			return fmt.Errorf("a minimum key size needs a number of bits")
		}
	case MaxLifetime:
		if subjects != 0 {
			return fmt.Errorf("a maximum lifetime applies to every certificate and names no algorithm")
		}
		if r.Days <= 0 {
			return fmt.Errorf("a maximum lifetime needs a number of days")
		}
	default:
		return fmt.Errorf("kind must be %s, %s or %s", Deny, MinKeySize, MaxLifetime)
	}
	if r.Algorithm != "" {
		if _, ok := selectorRef(r.Algorithm); !ok {
			return fmt.Errorf("%q is not an algorithm this product recognises", r.Algorithm)
		}
	}
	return nil
}

// Describe is the rule as a sentence, for a screen or a PDF.
func (r Rule) Describe() string {
	switch r.Kind {
	case Deny:
		if r.Risk != "" {
			return "No " + strings.ToLower(strings.ReplaceAll(r.Risk, "_", "-")) + " algorithms"
		}
		return "No " + r.Algorithm
	case MinKeySize:
		return fmt.Sprintf("%s keys of at least %d bits", r.Algorithm, r.Bits)
	case MaxLifetime:
		return fmt.Sprintf("Certificates valid for at most %d days", r.Days)
	}
	return r.Name
}
