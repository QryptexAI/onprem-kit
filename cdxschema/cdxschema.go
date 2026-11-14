// Package cdxschema checks a document against the official CycloneDX 1.6 JSON
// Schema. It exists so the claim in pqc ("conformance is checked against the
// official JSON Schema") is true: every product's tests validate the CBOM it
// exports, and CAMP's validate the organisation-wide one too.
//
// Import it from tests only. Nothing at runtime should depend on it: a product
// builds a CBOM from pqc's types, and this proves those types serialise to a
// valid document.
//
// The schema files in schema/ are copied unmodified from
// github.com/CycloneDX/specification at tag 1.6.1 (schema/bom-1.6.schema.json and
// the two files it references, spdx.schema.json and jsf-0.82.schema.json). To move
// to a later 1.6.x, replace all three from the same tag and update SchemaTag.
package cdxschema

import (
	"bytes"
	"embed"
	"fmt"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// SchemaTag is the CycloneDX specification tag the embedded schema came from.
const SchemaTag = "1.6.1"

//go:embed schema/*.json
var files embed.FS

// The $id the bom schema declares, and the base its relative $refs resolve against.
const base = "http://cyclonedx.org/schema/"

var (
	once     sync.Once
	compiled *jsonschema.Schema
	errLoad  error
)

func load() (*jsonschema.Schema, error) {
	once.Do(func() {
		c := jsonschema.NewCompiler()
		// Formats are asserted: a timestamp that is not date-time or a URL that is
		// not an IRI is a real defect in an exported document.
		c.AssertFormat()
		for _, name := range []string{"bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"} {
			raw, err := files.ReadFile("schema/" + name)
			if err != nil {
				errLoad = err
				return
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				errLoad = fmt.Errorf("%s: %w", name, err)
				return
			}
			if err := c.AddResource(base+name, doc); err != nil {
				errLoad = fmt.Errorf("%s: %w", name, err)
				return
			}
		}
		compiled, errLoad = c.Compile(base + "bom-1.6.schema.json")
	})
	return compiled, errLoad
}

// Validate reports whether doc is a valid CycloneDX 1.6 document. The error, when
// there is one, lists every violation with its JSON location.
func Validate(doc []byte) error {
	s, err := load()
	if err != nil {
		return fmt.Errorf("loading the CycloneDX schema: %w", err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		return fmt.Errorf("not JSON: %w", err)
	}
	if err := s.Validate(inst); err != nil {
		return fmt.Errorf("not valid CycloneDX %s: %s", SchemaTag, strings.TrimSpace(fmt.Sprintf("%#v", err)))
	}
	return nil
}
