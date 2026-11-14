package pqc

import (
	"encoding/json"
	"strings"
)

// Context is an occurrence's additional facts: name/value pairs that CycloneDX
// has no field for.
//
// CycloneDX 1.6 types occurrence.additionalContext as a string, so a Context is
// written as one, readable by a person reading the document:
//
//	agility=HARDCODED; triage=OPEN
//
// A name or value containing %, ; or = has those characters percent-escaped, so
// the string always reads back to the same pairs.
//
// Releases before onprem-kit v0.5.3 wrote an array of {name, value} objects, which
// the schema refuses. Reading accepts that form too, because CAMP stores the raw
// documents older installs sent and re-merges them.
type Context []Property

var (
	ctxEscape   = strings.NewReplacer("%", "%25", ";", "%3B", "=", "%3D")
	ctxUnescape = strings.NewReplacer("%3B", ";", "%3D", "=", "%25", "%")
)

// String is the form written to the document.
func (c Context) String() string {
	parts := make([]string, 0, len(c))
	for _, p := range c {
		parts = append(parts, ctxEscape.Replace(p.Name)+"="+ctxEscape.Replace(p.Value))
	}
	return strings.Join(parts, "; ")
}

// Get returns the value of the first pair called name.
func (c Context) Get(name string) string {
	for _, p := range c {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

func (c Context) MarshalJSON() ([]byte, error) { return json.Marshal(c.String()) }

func (c *Context) UnmarshalJSON(b []byte) error {
	var legacy []Property
	if err := json.Unmarshal(b, &legacy); err == nil {
		*c = legacy
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*c = ParseContext(s)
	return nil
}

// ParseContext reads the string form back into pairs. Text that is not in that
// form (another tool's free-text context) is kept whole, as one pair named
// "context", rather than dropped.
func ParseContext(s string) Context {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var out Context
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			return Context{{Name: "context", Value: s}}
		}
		out = append(out, Property{Name: ctxUnescape.Replace(name), Value: ctxUnescape.Replace(value)})
	}
	return out
}
