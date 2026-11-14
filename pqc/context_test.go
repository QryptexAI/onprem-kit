package pqc

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestContextIsAStringAndReadsBack(t *testing.T) {
	in := Occurrence{Location: "pki:ca/1", AdditionalContext: Context{
		{Name: "tier", Value: "ROOT"}, {Name: "department", Value: "R&D; Labs = 2 (100%)"}}}
	b, _ := json.Marshal(in)
	var raw map[string]any
	_ = json.Unmarshal(b, &raw)
	s, ok := raw["additionalContext"].(string)
	if !ok || s != "tier=ROOT; department=R&D%3B Labs %3D 2 (100%25)" {
		t.Fatalf("written as %#v", raw["additionalContext"])
	}
	var out Occurrence
	if err := json.Unmarshal(b, &out); err != nil || !reflect.DeepEqual(out, in) {
		t.Fatalf("read back %+v, %v", out, err)
	}
	if out.AdditionalContext.Get("department") != "R&D; Labs = 2 (100%)" {
		t.Fatal("Get")
	}
}

// Documents from releases before v0.5.3 carry the array form; CAMP still reads them.
func TestContextReadsTheLegacyArray(t *testing.T) {
	var o Occurrence
	if err := json.Unmarshal([]byte(`{"location":"a.go","additionalContext":[{"name":"agility","value":"HARDCODED"}]}`), &o); err != nil {
		t.Fatal(err)
	}
	if o.AdditionalContext.Get("agility") != "HARDCODED" {
		t.Fatalf("%+v", o)
	}
}

func TestContextKeepsForeignText(t *testing.T) {
	var o Occurrence
	_ = json.Unmarshal([]byte(`{"location":"x","additionalContext":"seen in a handshake"}`), &o)
	if o.AdditionalContext.Get("context") != "seen in a handshake" {
		t.Fatalf("%+v", o.AdditionalContext)
	}
	var none Occurrence
	b, _ := json.Marshal(Occurrence{Location: "x"})
	_ = json.Unmarshal(b, &none)
	if string(b) != `{"location":"x"}` || none.AdditionalContext != nil {
		t.Fatalf("empty context written as %s", b)
	}
}
