package pqcreport

import (
	"fmt"
	"io"
	"time"

	"github.com/go-pdf/fpdf"
)

// Document is a report in sections chosen by the caller, for a document whose
// shape is set by someone else: CAMP's M-26-15 plan pack follows Appendix B's
// nine sections, which is not the posture report's shape.
//
// It shares the posture report's type, footer and checksum rule, so the two read
// as one family and both tie themselves to the CBOM they summarise.
type Document struct {
	Title     string
	Product   string
	Org       string
	Scope     string
	Generated time.Time
	Version   string
	// CBOMSHA256 and Signature as on Report: the footer ties the document to
	// the bill of materials it reads.
	CBOMSHA256 string
	Signature  string
	Sections   []Section
}

// Section is one heading. Status, when set, prints beside the heading so a
// reader can see which sections the product filled and which it left for them.
type Section struct {
	Title  string
	Status string
	Body   []string // paragraphs
	Items  []string // bullets
	// Rows print as a fixed-width table: the first row is the header.
	Rows [][]string
	// More counts items left out for length, with where to find them.
	More     int
	MoreHint string
}

// RenderDocument writes a Document as a PDF.
func RenderDocument(w io.Writer, d Document) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(margin, margin, margin)
	pdf.SetAutoPageBreak(true, margin)
	pdf.AddPage()

	pdf.SetFont("Helvetica", "B", 20)
	pdf.MultiCell(textW, 9, latin1(d.Title), "", "L", false)
	pdf.SetFont("Helvetica", "", 11)
	pdf.SetTextColor(90, 90, 90)
	line := d.Product
	if d.Org != "" {
		line += "  ·  " + d.Org
	}
	if d.Scope != "" {
		line += "  ·  " + d.Scope
	}
	pdf.MultiCell(textW, 6, latin1(line), "", "L", false)
	pdf.MultiCell(textW, 6, latin1("Generated "+d.Generated.UTC().Format("2 January 2006, 15:04 MST")), "", "L", false)
	pdf.SetTextColor(0, 0, 0)
	pdf.Ln(3)

	for _, s := range d.Sections {
		section(pdf, s.Title)
		if s.Status != "" {
			pdf.SetFont("Helvetica", "I", 9)
			pdf.SetTextColor(90, 90, 90)
			pdf.MultiCell(textW, 4.5, latin1(s.Status), "", "L", false)
			pdf.SetTextColor(0, 0, 0)
			pdf.Ln(1)
		}
		for _, p := range s.Body {
			body(pdf, p)
		}
		for _, it := range s.Items {
			bullet(pdf, it)
		}
		if len(s.Rows) > 0 {
			table(pdf, s.Rows)
		}
		if s.More > 0 {
			hint := s.MoreHint
			if hint == "" {
				hint = "in the accompanying CSV"
			}
			body(pdf, fmt.Sprintf("... and %d more, %s.", s.More, hint))
		}
	}

	footer(pdf, Report{Product: d.Product, Version: d.Version, CBOMSHA256: d.CBOMSHA256, Signature: d.Signature})
	return pdf.Output(w)
}

// table prints rows with columns sized to their longest cell, capped so a long
// value wraps rather than pushing the table off the page.
func table(pdf *fpdf.Fpdf, rows [][]string) {
	cols := 0
	for _, r := range rows {
		if len(r) > cols {
			cols = len(r)
		}
	}
	if cols == 0 {
		return
	}
	pdf.SetFont("Helvetica", "", 8.5)
	widths := make([]float64, cols)
	for _, r := range rows {
		for i, c := range r {
			if w := pdf.GetStringWidth(latin1(c)) + 3; w > widths[i] {
				widths[i] = w
			}
		}
	}
	total := 0.0
	for _, w := range widths {
		total += w
	}
	if total > textW {
		for i := range widths {
			widths[i] = widths[i] * textW / total
		}
	}
	for n, r := range rows {
		if n == 0 {
			pdf.SetFont("Helvetica", "B", 8.5)
		} else {
			pdf.SetFont("Helvetica", "", 8.5)
		}
		x, y := pdf.GetXY()
		height := 4.6
		for i := 0; i < cols; i++ {
			c := ""
			if i < len(r) {
				c = r[i]
			}
			lines := pdf.SplitText(latin1(c), widths[i]-1)
			if h := float64(len(lines)) * 4.6; h > height {
				height = h
			}
		}
		if y+height > 297-margin {
			pdf.AddPage()
			x, y = pdf.GetXY()
		}
		for i := 0; i < cols; i++ {
			c := ""
			if i < len(r) {
				c = r[i]
			}
			pdf.SetXY(x, y)
			pdf.MultiCell(widths[i], 4.6, latin1(c), "", "L", false)
			x += widths[i]
		}
		pdf.SetXY(margin, y+height)
	}
	pdf.Ln(2)
}
