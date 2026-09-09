package pqcreport

import "strings"

// latin1 makes a string safe for fpdf's core fonts.
//
// THE CORE PDF FONTS ARE NOT UNICODE. Helvetica and its siblings are single-byte
// cp1252, so a UTF-8 em dash written straight through arrives as two bytes and
// renders as two wrong glyphs — which is what put mojibake in the first reports.
// fpdf ships a translator, but it reads a .map file from the font path, and a
// PDF that renders correctly only when a data file was copied into the image is
// a PDF that will one day not render correctly.
//
// So the substitution is here and self-contained. It does two things:
//
//   - Typographic punctuation becomes its ASCII equivalent. An em dash is worth
//     more as "-" than as a pair of broken glyphs.
//   - Anything else outside Latin-1 becomes "?". Accented Latin passes through
//     unharmed, because cp1252 has it: a justification written about "Amélie"
//     survives, a subject name in Japanese does not, and the "?" says so rather
//     than silently dropping characters.
//
// This runs over EVERY string the report prints, including operator-supplied
// text. Justifications are typed by people, and people paste em dashes and smart
// quotes out of documents.
var replacer = strings.NewReplacer(
	"—", "-", // em dash
	"–", "-", // en dash
	"•", "-", // bullet
	"·", "-", // middle dot
	"‘", "'", "’", "'", // curly single quotes
	"“", `"`, "”", `"`, // curly double quotes
	"…", "...", // ellipsis
	" ", " ", // non-breaking space
	"→", "->", // arrow
	"≥", ">=", "≤", "<=",
	"×", "x",
)

func latin1(s string) string {
	s = replacer.Replace(s)
	if isASCII(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r < 0x80:
			b.WriteRune(r)
		case r <= 0xff:
			// cp1252 covers accented Latin; fpdf writes the byte directly.
			b.WriteRune(r)
		default:
			b.WriteByte('?')
		}
	}
	return b.String()
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
