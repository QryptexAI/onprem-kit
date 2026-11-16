package pqcreport

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestRenderDocument(t *testing.T) {
	var buf bytes.Buffer
	err := RenderDocument(&buf, Document{
		Title: "PQC migration plan evidence", Product: "CAMP", Generated: time.Now(), Version: "v0",
		Sections: []Section{
			{Title: "1. Prioritisation", Status: "Filled by CAMP", Body: []string{"Three systems."},
				Rows: [][]string{{"System", "Impact"}, {"Payroll", "HIGH"}, {strings.Repeat("long name ", 30), "LOW"}}},
			{Title: "2. Funding", Status: "Agency to complete", Items: []string{"Personnel", "Funding"}, More: 3},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("%PDF")) || buf.Len() < 1000 {
		t.Fatalf("not a PDF: %d bytes", buf.Len())
	}
}
