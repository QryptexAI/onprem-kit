package pqc

import "time"

// CycloneDX 1.6 cryptographic-asset types, in the subset the two products emit.
//
// NO CYCLONEDX LIBRARY. We only produce these documents, and producing one is a
// struct with JSON tags — a shared kit should not push a dependency onto every
// consumer for that. Conformance comes from validating output against the
// official JSON Schema in CI, which is a test-time cost rather than a runtime
// one. CAMP's aggregation has to PARSE, and a real parser may earn its place
// there; it has not earned it here.
//
// The subset is deliberate: fields nobody emits are fields nobody keeps
// correct.

const (
	bomFormat  = "CycloneDX"
	specVer    = "1.6"
	compCrypto = "cryptographic-asset"
)

// BOM is one CycloneDX document.
type BOM struct {
	BOMFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Version     int         `json:"version"`
	Metadata    Metadata    `json:"metadata"`
	Components  []Component `json:"components"`
}

// NewBOM returns an empty document with the format fields set, so no caller has
// to remember the constants and no two callers can disagree about them.
func NewBOM(tool Tool, at time.Time) BOM {
	return BOM{
		BOMFormat:   bomFormat,
		SpecVersion: specVer,
		Version:     1,
		Metadata:    Metadata{Timestamp: at.UTC(), Tools: []Tool{tool}},
	}
}

type Metadata struct {
	Timestamp time.Time `json:"timestamp"`
	Tools     []Tool    `json:"tools,omitempty"`
	// Properties carries what CycloneDX has no field for and an assessor still
	// needs: which rule pack produced this, and how much of the estate it
	// covered. A document whose completeness is not stated on its face is the
	// artefact CAMP's aggregation design refuses to produce.
	Properties []Property `json:"properties,omitempty"`
}

type Tool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Component is one cryptographic asset. BOMRef is its identity — see ref.go.
type Component struct {
	Type        string            `json:"type"`
	BOMRef      string            `json:"bom-ref"`
	Name        string            `json:"name"`
	CryptoProps *CryptoProperties `json:"cryptoProperties,omitempty"`
	Evidence    *Evidence         `json:"evidence,omitempty"`
	Properties  []Property        `json:"properties,omitempty"`
}

type CryptoProperties struct {
	AssetType string               `json:"assetType"`
	AlgProps  *AlgorithmProperties `json:"algorithmProperties,omitempty"`
	OID       string               `json:"oid,omitempty"`
}

type AlgorithmProperties struct {
	// Primitive is CycloneDX's own enum — signature, kem, key-agree, hash,
	// block-cipher, drbg, other.
	Primitive string `json:"primitive,omitempty"`
	// ParameterSetIdentifier is the curve, group or parameter set. EMPTY IS
	// MEANINGFUL: it makes this a coarser component than a specific one, and
	// the two are never merged. See Algorithm.Parameter.
	ParameterSetIdentifier   string     `json:"parameterSetIdentifier,omitempty"`
	CryptoFunctions          []Function `json:"cryptoFunctions,omitempty"`
	NISTQuantumSecurityLevel int        `json:"nistQuantumSecurityLevel,omitempty"`
}

// Evidence carries every place a component was seen. One component, many
// sightings — "we have an RSA problem" and "here are 4,000 places", rather than
// 4,000 components, which is a document nobody can read and a count nobody can
// report.
type Evidence struct {
	Occurrences []Occurrence `json:"occurrences,omitempty"`
}

// Occurrence is one sighting.
//
// Location is deliberately a plain string, because the two products' location
// spaces are disjoint and must stay so: QryptoScan writes a repository path and
// line, CAMP writes an address and port. That disjointness is what makes
// deduplication at merge time nearly free — two feeds cannot report the same
// occurrence.
type Occurrence struct {
	BOMRef   string `json:"bom-ref,omitempty"`
	Location string `json:"location"`
	Line     int    `json:"line,omitempty"`
	// AdditionalContext is where the per-occurrence facts live that CycloneDX
	// has no home for: the agility grade, the triage state, a waiver and its
	// expiry. Agility belongs HERE and not on the component — "hardcoded but
	// behind one internal wrapper" describes a call site, not RSA.
	AdditionalContext []Property `json:"additionalContext,omitempty"`
}

// primitives maps a family onto CycloneDX's primitive enum.
var primitives = map[Family]string{
	FamilyRSA: "pke", FamilyEC: "key-agree", FamilyDH: "key-agree",
	FamilyDSA: "signature", FamilyMQV: "key-agree",
	FamilyMLKEM: "kem", FamilyHybridKEM: "kem",
	FamilyMLDSA: "signature", FamilySLHDSA: "signature",
	FamilyAES: "block-cipher", FamilyLegacySym: "block-cipher",
	FamilySHA1: "hash", FamilySHA2: "hash", FamilyMD5: "hash",
	FamilyPRNG: "drbg",
}

// NewComponent builds a component from a normalised algorithm.
//
// Both products call this rather than assembling the struct, so the assetType,
// the primitive mapping and the bom-ref cannot be got right in one product and
// wrong in the other.
func NewComponent(a Algorithm, fs []Function) Component {
	prim := primitives[a.Family]
	if prim == "" {
		prim = "other"
	}
	name := a.Native
	if name == "" {
		name = string(a.Family)
	}
	return Component{
		Type:   compCrypto,
		BOMRef: BOMRef(a),
		Name:   name,
		CryptoProps: &CryptoProperties{
			AssetType: "algorithm",
			AlgProps: &AlgorithmProperties{
				Primitive:              prim,
				ParameterSetIdentifier: a.Parameter,
				CryptoFunctions:        fs,
			},
		},
	}
}
