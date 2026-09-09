package pqcreport

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func sample() Report {
	return Report{
		Product: "CAMP", Org: "Local Dev", Scope: "All sites",
		Generated: time.Date(2026, 9, 9, 17, 0, 0, 0, time.UTC),
		Version:   "v0.9.59", CBOMSHA256: "6f2d7284b102",
		Headline:   "139 findings across 149 assets.",
		Severities: []Severity{{"CRITICAL", 22, "#dc2626"}, {"HIGH", 117, "#ea580c"}},
		Algorithms: []Algorithm{
			{Name: "RSA-3072", Occurrences: 54, Risk: "QUANTUM_BROKEN", Phase: "Phase 4"},
			{Name: "TLS 1.0", Occurrences: 14},
		},
		Worst:       []string{"ldn-core-sw1:443 negotiated TLS 1.0"},
		Exceptions:  []Exception{{"oxf-srv028", "INCAPABLE", "Fixed firmware line.", "admin", time.Date(2027, 9, 9, 0, 0, 0, 0, time.UTC)}},
		NotAssessed: []string{"Five repositories are outside the licence."},
	}
}

func TestRenderProducesAPDF(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, sample()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if buf.Len() < 800 {
		t.Fatalf("suspiciously small PDF: %d bytes", buf.Len())
	}
	if got := buf.String()[:5]; got != "%PDF-" {
		t.Errorf("does not start with a PDF header: %q", got)
	}
	if !strings.Contains(buf.String(), "%%EOF") {
		t.Error("no EOF trailer — the document is not closed")
	}
}

// An empty report must still render. A product with nothing recorded yet is the
// state every install starts in, and a report that errors there is a report
// nobody can generate on day one.
func TestEmptyReportStillRenders(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, Report{Product: "CAMP", Generated: time.Now()}); err != nil {
		t.Fatalf("Render on an empty report: %v", err)
	}
	if buf.Len() < 800 {
		t.Fatalf("suspiciously small PDF: %d bytes", buf.Len())
	}
}

// A colour the caller invents must not break the document.
func TestUnknownColourFallsBack(t *testing.T) {
	r := sample()
	r.Severities = []Severity{{"ODD", 1, "not-a-colour"}}
	var buf bytes.Buffer
	if err := Render(&buf, r); err != nil {
		t.Fatalf("Render with a bad colour: %v", err)
	}
}

func TestHexParsing(t *testing.T) {
	if r, g, b := hex("#dc2626"); r != 0xdc || g != 0x26 || b != 0x26 {
		t.Errorf("hex(#dc2626) = %d,%d,%d", r, g, b)
	}
	if r, _, _ := hex("nonsense"); r != 100 {
		t.Error("an unparseable colour should fall back to grey, not panic")
	}
}

// The core PDF fonts are cp1252, so a UTF-8 em dash written straight through
// arrives as two bytes and renders as two wrong glyphs. Every string the report
// prints goes through latin1 — including operator-supplied text, because
// justifications are typed by people and people paste smart quotes.
func TestTypographyIsTransliterated(t *testing.T) {
	for in, want := range map[string]string{
		"a — b":      "a - b",
		"a • b":      "a - b",
		"“quoted”":   `"quoted"`,
		"it’s":       "it's",
		"more…":      "more...",
		"CAMP · PKI": "CAMP - PKI",
	} {
		if got := latin1(in); got != want {
			t.Errorf("latin1(%q) = %q, want %q", in, got, want)
		}
	}
}

// Accented Latin survives, because cp1252 has it. A name is worth keeping.
func TestAccentedLatinSurvives(t *testing.T) {
	if got := latin1("Amélie Moreau"); got != "Amélie Moreau" {
		t.Errorf("latin1 mangled an accented name: %q", got)
	}
}

// Anything cp1252 cannot represent becomes '?' rather than being dropped. A
// dropped character is a silent lie about what the operator wrote.
func TestUnrepresentableBecomesAQuestionMark(t *testing.T) {
	got := latin1("host-東京-01")
	if strings.Contains(got, "東") {
		t.Errorf("non-Latin passed through unencoded: %q", got)
	}
	if !strings.Contains(got, "?") {
		t.Errorf("non-Latin was dropped instead of marked: %q", got)
	}
}

// The itemised section is what makes the report actionable: the table says how
// much RSA there is, this says which box to go and fix.
func TestItemisedOccurrencesAreRendered(t *testing.T) {
	r := sample()
	r.Algorithms[0].Sightings = []string{"ldn-core-sw1:22", "ldn-core-sw2:22"}
	var buf bytes.Buffer
	if err := Render(&buf, r); err != nil {
		t.Fatalf("Render: %v", err)
	}
	plain := bytes.Buffer{}
	if err := Render(&plain, sample()); err != nil {
		t.Fatal(err)
	}
	if buf.Len() <= plain.Len() {
		t.Errorf("itemised report (%d bytes) is not larger than the consolidated one (%d)", buf.Len(), plain.Len())
	}
}
