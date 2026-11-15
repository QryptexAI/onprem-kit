package cbompolicy

import (
	"strings"
	"testing"
	"time"

	"github.com/QryptexAI/onprem-kit/pqc"
)

var (
	now  = time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	past = now.AddDate(-1, 0, 0)
	y30  = time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC)
)

func alg(t *testing.T, name string, locs ...string) pqc.Component {
	t.Helper()
	a, ok := pqc.Normalise(name)
	if !ok {
		t.Fatalf("kit does not know %s", name)
	}
	c := pqc.NewComponent(a, nil)
	c.Evidence = &pqc.Evidence{}
	for _, l := range locs {
		c.Evidence.Occurrences = append(c.Evidence.Occurrences, pqc.Occurrence{Location: l})
	}
	return c
}

func cert(days int, loc string) pqc.Component {
	f := pqc.CertificateFacts{Subject: "CN=x", IssuerCN: "CA", Serial: "1", NotBefore: now,
		NotAfter: now.Add(time.Duration(days) * 24 * time.Hour), KeyName: "RSA-2048", SignatureName: "SHA-256"}
	c := pqc.NewCertificateComponent(f)
	c.Evidence = &pqc.Evidence{Occurrences: []pqc.Occurrence{{Location: loc}}}
	return c
}

func bom(cs ...pqc.Component) pqc.BOM {
	b := pqc.NewBOM(pqc.Tool{Name: "test"}, now)
	b.Components = cs
	return b
}

func rule(kind Kind, s Subject, from time.Time) Rule {
	return Rule{ID: string(kind) + s.Algorithm + s.Risk, Name: "r", Kind: kind, Subject: s,
		EffectiveFrom: from, Action: Fail, Enabled: true}
}

// "RSA" is the whole family; "RSA-2048" only that size; a bom-ref works too.
// Everyday spellings from each product resolve to the same thing.
func TestSubject_Vocabulary(t *testing.T) {
	for _, c := range []struct {
		subject, name string
		want          bool
	}{
		{"RSA", "RSA-2048", true},
		{"RSA", "RSA_4096", true},
		{"RSA-2048", "RSA-4096", false},
		{"rsa/2048", "RSA-2048", true},
		{"crypto/rsa/2048", "RSA-2048", true},
		{"ECDSA_P256", "secp256r1", true},
		{"ECDSA_P256", "prime256v1", true},
		{"ECDSA_P256", "secp384r1", false},
		{"ML-DSA-65", "mldsa65", true},
		{"RSA", "rsa-pss", true},
	} {
		if got := (Subject{Algorithm: c.subject}).Matches(c.name); got != c.want {
			t.Errorf("%s covers %s = %v, want %v", c.subject, c.name, got, c.want)
		}
	}
	broken := Subject{Risk: string(pqc.QuantumBroken)}
	for name, want := range map[string]bool{"RSA-2048": true, "secp256r1": true, "mldsa65": false,
		"X25519MLKEM768": false, "AES-256": false, "some-made-up-cipher": true} {
		if got := broken.Matches(name); got != want {
			t.Errorf("QUANTUM_BROKEN covers %s = %v, want %v", name, got, want)
		}
	}
}

func TestKeyBits(t *testing.T) {
	for ref, want := range map[string]int{"crypto/rsa/2048": 2048, "crypto/ec/secp384r1": 384,
		"crypto/dh/ffdhe3072": 3072, "crypto/ec/ed25519": 256, "crypto/aes/128": 128,
		"crypto/rsa": 0, "crypto/ml-dsa/mldsa65": 0} {
		got, ok := KeyBits(ref)
		if got != want || ok != (want != 0) {
			t.Errorf("KeyBits(%s) = %d, %v; want %d", ref, got, ok, want)
		}
	}
}

// One violation per occurrence, so a plan item is a thing and a place.
func TestEvaluate_DenyReportsEveryOccurrence(t *testing.T) {
	b := bom(alg(t, "RSA-2048", "10.0.0.5:443", "src/a.go"), alg(t, "mldsa65", "pki:ca/1"))
	res := Evaluate([]Rule{rule(Deny, Subject{Algorithm: "RSA"}, past)}, b, now, Options{})
	if len(res.Violations) != 2 || res.RulesInForce != 1 {
		t.Fatalf("got %+v", res)
	}
	for _, v := range res.Violations {
		if v.Component != "crypto/rsa/2048" || !v.InForce {
			t.Errorf("violation %+v", v)
		}
	}
	if len(res.Failing()) != 2 {
		t.Errorf("failing = %d", len(res.Failing()))
	}
}

// A dated rule is evaluated now and reported with its due date, not in force.
func TestEvaluate_UpcomingRuleReportsWithItsDate(t *testing.T) {
	b := bom(alg(t, "ECDSA-256", "10.0.0.5:443"))
	res := Evaluate([]Rule{rule(Deny, Subject{Risk: "QUANTUM_BROKEN"}, y30)}, b, now, Options{})
	if res.RulesUpcoming != 1 || res.RulesInForce != 0 || len(res.Violations) != 1 {
		t.Fatalf("got %+v", res)
	}
	v := res.Violations[0]
	if v.InForce || !v.Due.Equal(y30) || v.Detail != "QUANTUM_BROKEN" {
		t.Errorf("violation %+v", v)
	}
	if len(res.Failing()) != 0 {
		t.Error("an upcoming rule must not fail anything yet")
	}
}

func TestEvaluate_MinKeySize(t *testing.T) {
	b := bom(alg(t, "RSA-2048", "a"), alg(t, "RSA-4096", "b"), alg(t, "RSA", "c"), alg(t, "secp256r1", "d"))
	r := rule(MinKeySize, Subject{Algorithm: "RSA"}, past)
	r.Bits = 3072
	res := Evaluate([]Rule{r}, b, now, Options{})
	// RSA-2048 only: 4096 passes, a bare "RSA" has no size and is never guessed
	// at, and EC is another family.
	if len(res.Violations) != 1 || res.Violations[0].Location != "a" || res.Violations[0].Detail != "2048 bits, below 3072" {
		t.Fatalf("got %+v", res.Violations)
	}
}

// A KMS key is checked by its algorithm; a certificate's public key is not
// checked twice.
func TestEvaluate_KeysByAlgorithm(t *testing.T) {
	kms := pqc.NewManagedKeyComponent(pqc.ManagedKey{Namespace: "kms", ID: "k1", Name: "payments",
		Type: "private-key", State: pqc.KeyState("ENABLED"), Algorithm: "RSA-2048", Created: now})
	kms.Evidence = &pqc.Evidence{Occurrences: []pqc.Occurrence{{Location: "pki:kms"}}}
	f := pqc.CertificateFacts{Subject: "CN=x", IssuerCN: "CA", Serial: "1", NotBefore: now, NotAfter: now.AddDate(1, 0, 0),
		KeyName: "RSA-2048", KeyBits: 2048, SignatureName: "SHA-256", SPKI: strings.Repeat("ab", 32)}
	pub := *pqc.NewPublicKeyComponent(f)
	res := Evaluate([]Rule{rule(Deny, Subject{Algorithm: "RSA"}, past)}, bom(kms, pub), now, Options{})
	if len(res.Violations) != 1 || res.Violations[0].Location != "pki:kms" {
		t.Fatalf("got %+v", res.Violations)
	}
}

func TestEvaluate_MaxLifetime(t *testing.T) {
	r := rule(MaxLifetime, Subject{}, past)
	r.Days = 398
	res := Evaluate([]Rule{r}, bom(cert(398, "ok"), cert(825, "long"), alg(t, "RSA-2048", "x")), now, Options{})
	if len(res.Violations) != 1 || res.Violations[0].Location != "long" || res.Violations[0].Detail != "valid 825 days, more than 398" {
		t.Fatalf("got %+v", res.Violations)
	}
}

// A rule scoped to a priority class needs the product to know classes; without
// that it is skipped and the result says so, never silently passed.
func TestEvaluate_PriorityClass(t *testing.T) {
	b := bom(alg(t, "RSA-2048", "10.0.0.1:443", "10.0.0.2:443"))
	r := rule(Deny, Subject{Algorithm: "RSA"}, past)
	r.PriorityClass = "HVA"

	res := Evaluate([]Rule{r}, b, now, Options{})
	if len(res.Violations) != 0 || len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "priority class") {
		t.Fatalf("without priorities: %+v", res)
	}
	res = Evaluate([]Rule{r}, b, now, Options{PriorityOf: func(loc string) string {
		if loc == "10.0.0.1:443" {
			return "HVA"
		}
		return ""
	}})
	if len(res.Violations) != 1 || res.Violations[0].Location != "10.0.0.1:443" {
		t.Fatalf("with priorities: %+v", res.Violations)
	}
}

func TestEvaluate_PrioritisedSet(t *testing.T) {
	b := bom(alg(t, "RSA-2048", "hva", "none", "unclassified"))
	r := rule(Deny, Subject{Algorithm: "RSA"}, past)
	r.PriorityClass = PrioritisedSet
	res := Evaluate([]Rule{r}, b, now, Options{PriorityOf: func(loc string) string {
		return map[string]string{"hva": "HVA", "none": "NONE"}[loc]
	}})
	if len(res.Violations) != 1 || res.Violations[0].Location != "hva" {
		t.Fatalf("got %+v", res.Violations)
	}
}

func TestEvaluate_DisabledAndEmpty(t *testing.T) {
	r := rule(Deny, Subject{Algorithm: "RSA"}, past)
	r.Enabled = false
	res := Evaluate([]Rule{r}, bom(alg(t, "RSA-2048", "a")), now, Options{})
	if len(res.Violations) != 0 || len(res.Notes) != 1 {
		t.Fatalf("got %+v", res)
	}
}

// In force before upcoming, failures before warnings.
func TestEvaluate_Order(t *testing.T) {
	warn := rule(Deny, Subject{Algorithm: "RSA"}, past)
	warn.ID, warn.Action = "warn", Warn
	fail := rule(Deny, Subject{Algorithm: "RSA"}, past)
	fail.ID = "fail"
	later := rule(Deny, Subject{Algorithm: "RSA"}, y30)
	later.ID = "later"
	res := Evaluate([]Rule{later, warn, fail}, bom(alg(t, "RSA-2048", "a")), now, Options{})
	var ids []string
	for _, v := range res.Violations {
		ids = append(ids, v.RuleID)
	}
	if strings.Join(ids, ",") != "fail,warn,later" {
		t.Errorf("order %v", ids)
	}
}

func TestValidate(t *testing.T) {
	ok := func(r Rule) Rule { r.Name, r.Action, r.EffectiveFrom, r.Enabled = "n", Fail, now, true; return r }
	for name, r := range map[string]Rule{
		"deny with two subjects": ok(Rule{Kind: Deny, Subject: Subject{Algorithm: "RSA", Risk: "QUANTUM_BROKEN"}}),
		"deny with none":         ok(Rule{Kind: Deny}),
		"unknown algorithm":      ok(Rule{Kind: Deny, Subject: Subject{Algorithm: "made-up-cipher"}}),
		"unknown risk":           ok(Rule{Kind: Deny, Subject: Subject{Risk: "SCARY"}}),
		"size without bits":      ok(Rule{Kind: MinKeySize, Subject: Subject{Algorithm: "RSA"}}),
		"size on a risk":         ok(Rule{Kind: MinKeySize, Subject: Subject{Risk: "QUANTUM_BROKEN"}, Bits: 2048}),
		"lifetime with subject":  ok(Rule{Kind: MaxLifetime, Subject: Subject{Algorithm: "RSA"}, Days: 398}),
		"lifetime without days":  ok(Rule{Kind: MaxLifetime}),
		"no kind":                ok(Rule{Subject: Subject{Algorithm: "RSA"}}),
		"no date":                {Name: "n", Kind: Deny, Subject: Subject{Algorithm: "RSA"}, Action: Fail},
	} {
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, r := range map[string]Rule{
		"deny family": ok(Rule{Kind: Deny, Subject: Subject{Algorithm: "RSA"}}),
		"deny risk":   ok(Rule{Kind: Deny, Subject: Subject{Risk: "QUANTUM_BROKEN"}}),
		"size":        ok(Rule{Kind: MinKeySize, Subject: Subject{Algorithm: "RSA"}, Bits: 3072}),
		"lifetime":    ok(Rule{Kind: MaxLifetime, Days: 398}),
	} {
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
