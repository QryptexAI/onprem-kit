package cdxsign

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Canonicalize returns doc in the JSON Canonicalization Scheme (RFC 8785): no
// whitespace, object members sorted by their names' UTF-16 code units, strings
// with only the escapes RFC 8785 requires, numbers as ECMAScript prints a double.
//
// It is what a JSF signature is computed over, so a verifier anywhere computes
// the same bytes from the same document however it was formatted.
func Canonicalize(doc []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data after the JSON value")
	}
	var b bytes.Buffer
	if err := write(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func write(b *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(t))
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			return err
		}
		s, err := number(f)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case string:
		str(b, t)
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := write(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			str(b, k)
			b.WriteByte(':')
			if err := write(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("unexpected JSON value %T", v)
	}
	return nil
}

func utf16Less(a, b string) bool {
	x, y := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}

// str writes a string as RFC 8785 §3.2.2.2: only ", \ and the control characters
// are escaped, the common ones by their short forms.
func str(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// number prints a double as ECMAScript's Number.prototype.toString does, which
// RFC 8785 §3.2.2.3 requires: the shortest round-trip digits, fixed notation from
// 1e-6 up to (not including) 1e21, exponent notation outside it ("1e+30", "1e-7").
func number(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("%v is not a JSON number", f)
	}
	if f == 0 {
		return "0", nil
	}
	if a := math.Abs(f); a >= 1e-6 && a < 1e21 {
		return strconv.FormatFloat(f, 'f', -1, 64), nil
	}
	s := strconv.FormatFloat(f, 'e', -1, 64)
	mant, exp, _ := strings.Cut(s, "e")
	sign := exp[0]
	exp = strings.TrimLeft(exp[1:], "0")
	return mant + "e" + string(sign) + exp, nil
}
