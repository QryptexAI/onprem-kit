// Package pqcreport renders a cryptographic posture report as a PDF.
//
// # Why this is not the CBOM
//
// The CycloneDX document is the machine-readable artefact: an auditor's tooling
// ingests it, and pqc.BOMRef is what lets CAMP's half and QryptoScan's half
// merge into one estate. A PDF can do neither. So this sits BESIDE that download
// and answers a different question — what a person needs to read, decide on, or
// put in front of somebody who will never run a tool.
//
// It carries the CBOM's checksum for exactly that reason: the two are one
// answer in two forms, and a report nobody can tie back to the artefact it
// summarises is a report nobody can check.
//
// # Shared, because the two products say the same things differently
//
// CAMP reports an estate of endpoints; QryptoScan reports repositories. The
// SHAPE is identical — a scope, a severity breakdown, the algorithms in use with
// their risk, the worst of them named, what has been formally excepted, and what
// was not assessed. Writing it twice would produce two documents that diverge on
// the third release, which is what onprem-kit exists to prevent.
//
// # What was NOT assessed is a section, not an omission
//
// Every screen in both products reports three-valued: covered, not covered, not
// assessed. A report that silently drops the third turns "we did not look" into
// "there is nothing there", which is the failure this whole product line keeps
// finding. So NotAssessed is a field on Report and it is rendered even when
// empty, because a stated nothing is different from a missing section.
package pqcreport

import (
	"fmt"
	"io"
	"time"

	"github.com/go-pdf/fpdf"
)

// Severity is one row of the breakdown.
type Severity struct {
	Label string
	Count int
	// Hex is the product's own colour for this severity, so the report matches
	// the screen the reader was just looking at.
	Hex string
}

// Algorithm is one cryptographic algorithm in use, and what is known about it.
type Algorithm struct {
	Name string
	// Occurrences is how many times it was seen — endpoints for CAMP, call
	// sites for QryptoScan.
	Occurrences int
	// Risk is the pqc vocabulary: QUANTUM_BROKEN, QUANTUM_WEAKENED, PQC_READY.
	// Empty means NOT ASSESSED and is rendered as such rather than as blank.
	Risk string
	// Phase is the M-26-15 migration phase where one applies.
	Phase string
}

// Exception is a decision somebody signed their name to.
type Exception struct {
	Subject       string
	Kind          string
	Justification string
	GrantedBy     string
	Expires       time.Time
}

// Report is everything the document says.
type Report struct {
	Product   string
	Org       string
	Scope     string
	Generated time.Time
	Version   string

	// CBOMSHA256 ties this document to the machine-readable artefact. Empty is
	// allowed and says so on the page rather than printing a blank.
	CBOMSHA256 string

	Headline    string
	Severities  []Severity
	Algorithms  []Algorithm
	Worst       []string
	Exceptions  []Exception
	NotAssessed []string
}

const (
	pageW  = 210.0
	margin = 18.0
	textW  = pageW - 2*margin
)

// Render writes the report as a PDF.
func Render(w io.Writer, r Report) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(margin, margin, margin)
	pdf.SetAutoPageBreak(true, margin)
	pdf.AddPage()

	title(pdf, r)
	section(pdf, "Posture")
	if r.Headline != "" {
		body(pdf, r.Headline)
	}
	severities(pdf, r.Severities)

	section(pdf, "Algorithms in use")
	algorithms(pdf, r.Algorithms)

	if len(r.Worst) > 0 {
		section(pdf, "Weakest observed")
		for _, s := range r.Worst {
			bullet(pdf, s)
		}
	}

	section(pdf, "Accepted risk and incapability")
	exceptions(pdf, r.Exceptions)

	// ALWAYS rendered, even empty. See the package comment: a stated nothing is
	// a different claim from a missing section.
	section(pdf, "What was not assessed")
	if len(r.NotAssessed) == 0 {
		body(pdf, "Nothing was excluded from this report.")
	}
	for _, s := range r.NotAssessed {
		bullet(pdf, s)
	}

	footer(pdf, r)
	return pdf.Output(w)
}

func title(pdf *fpdf.Fpdf, r Report) {
	pdf.SetFont("Helvetica", "B", 20)
	pdf.MultiCell(textW, 9, "Cryptographic posture", "", "L", false)
	pdf.SetFont("Helvetica", "", 11)
	pdf.SetTextColor(90, 90, 90)
	line := r.Product
	if r.Org != "" {
		line += "  ·  " + r.Org
	}
	if r.Scope != "" {
		line += "  ·  " + r.Scope
	}
	pdf.MultiCell(textW, 6, line, "", "L", false)
	pdf.MultiCell(textW, 6, "Generated "+r.Generated.UTC().Format("2 January 2006, 15:04 MST"), "", "L", false)
	pdf.SetTextColor(0, 0, 0)
	pdf.Ln(3)
}

func section(pdf *fpdf.Fpdf, s string) {
	pdf.Ln(4)
	pdf.SetFont("Helvetica", "B", 13)
	pdf.MultiCell(textW, 7, s, "", "L", false)
	pdf.SetFont("Helvetica", "", 10)
}

func body(pdf *fpdf.Fpdf, s string) {
	pdf.SetFont("Helvetica", "", 10)
	pdf.MultiCell(textW, 5, s, "", "L", false)
	pdf.Ln(1)
}

func bullet(pdf *fpdf.Fpdf, s string) {
	pdf.SetFont("Helvetica", "", 10)
	pdf.MultiCell(textW, 5, "•  "+s, "", "L", false)
}

func severities(pdf *fpdf.Fpdf, ss []Severity) {
	if len(ss) == 0 {
		body(pdf, "No findings recorded.")
		return
	}
	pdf.Ln(1)
	for _, s := range ss {
		rr, gg, bb := hex(s.Hex)
		pdf.SetFillColor(rr, gg, bb)
		pdf.SetTextColor(255, 255, 255)
		pdf.SetFont("Helvetica", "B", 10)
		pdf.CellFormat(34, 8, fmt.Sprintf(" %d  %s", s.Count, s.Label), "", 0, "L", true, 0, "")
		pdf.SetTextColor(0, 0, 0)
		pdf.CellFormat(4, 8, "", "", 0, "L", false, 0, "")
	}
	pdf.Ln(11)
}

func algorithms(pdf *fpdf.Fpdf, as []Algorithm) {
	if len(as) == 0 {
		body(pdf, "No cryptographic algorithms were recorded.")
		return
	}
	head := []string{"Algorithm", "Seen", "Quantum risk", "Phase"}
	wds := []float64{68, 20, 48, 38}
	pdf.SetFont("Helvetica", "B", 9)
	pdf.SetFillColor(238, 238, 240)
	for i, h := range head {
		pdf.CellFormat(wds[i], 7, h, "B", 0, "L", true, 0, "")
	}
	pdf.Ln(-1)
	pdf.SetFont("Helvetica", "", 9)
	for _, a := range as {
		risk := a.Risk
		if risk == "" {
			// Never blank. A blank cell reads as "fine"; this one is a claim
			// about the limits of what was measured.
			risk = "NOT ASSESSED"
		}
		phase := a.Phase
		if phase == "" {
			phase = "—"
		}
		pdf.CellFormat(wds[0], 6, a.Name, "B", 0, "L", false, 0, "")
		pdf.CellFormat(wds[1], 6, fmt.Sprintf("%d", a.Occurrences), "B", 0, "L", false, 0, "")
		pdf.CellFormat(wds[2], 6, risk, "B", 0, "L", false, 0, "")
		pdf.CellFormat(wds[3], 6, phase, "B", 0, "L", false, 0, "")
		pdf.Ln(-1)
	}
	pdf.Ln(2)
}

func exceptions(pdf *fpdf.Fpdf, es []Exception) {
	if len(es) == 0 {
		body(pdf, "None recorded. Nothing in this estate has been formally excepted, "+
			"so every finding above is outstanding rather than accepted.")
		return
	}
	for _, e := range es {
		pdf.SetFont("Helvetica", "B", 10)
		pdf.MultiCell(textW, 5, e.Subject+"  —  "+e.Kind, "", "L", false)
		pdf.SetFont("Helvetica", "", 9)
		pdf.MultiCell(textW, 4.6, e.Justification, "", "L", false)
		pdf.SetTextColor(90, 90, 90)
		meta := "Granted by " + e.GrantedBy
		if !e.Expires.IsZero() {
			meta += ", expires " + e.Expires.UTC().Format("2 January 2006")
		}
		pdf.MultiCell(textW, 4.6, meta, "", "L", false)
		pdf.SetTextColor(0, 0, 0)
		pdf.Ln(2)
	}
}

func footer(pdf *fpdf.Fpdf, r Report) {
	pdf.Ln(5)
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetTextColor(120, 120, 120)
	if r.CBOMSHA256 != "" {
		pdf.MultiCell(textW, 4.4,
			"This report summarises the CycloneDX cryptographic bill of materials "+
				"with checksum sha256:"+r.CBOMSHA256+". The bill of materials is the "+
				"machine-readable record; this document is a reading of it.", "", "L", false)
	} else {
		pdf.MultiCell(textW, 4.4,
			"No cryptographic bill of materials was attached to this report, so there "+
				"is no checksum to tie it to one.", "", "L", false)
	}
	if r.Version != "" {
		pdf.MultiCell(textW, 4.4, "Produced by "+r.Product+" "+r.Version+".", "", "L", false)
	}
	pdf.SetTextColor(0, 0, 0)
}

// hex turns "#dc2626" into RGB, falling back to a neutral grey rather than
// failing: a report must render even if a caller passes a colour it does not
// recognise.
func hex(s string) (int, int, int) {
	var r, g, b int
	if len(s) == 7 && s[0] == '#' {
		if _, err := fmt.Sscanf(s[1:], "%02x%02x%02x", &r, &g, &b); err == nil {
			return r, g, b
		}
	}
	return 100, 100, 100
}
