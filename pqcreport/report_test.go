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
