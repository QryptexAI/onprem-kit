package cbompolicy

import (
	"time"

	"github.com/QryptexAI/onprem-kit/pqc"
)

// Candidate is a certificate about to be issued, as an enforcement point knows
// it before signing: its key, the key of the CA that will sign it, and how long
// it will be valid.
type Candidate struct {
	// KeyAlgorithm and IssuerKeyAlgorithm are named as pqc names them
	// ("RSA-2048", "ECDSA-256", "mldsa65"), for example by
	// pqc.CertificateKeyName.
	KeyAlgorithm       string
	IssuerKeyAlgorithm string
	Lifetime           time.Duration
}

// Check evaluates the rules against one candidate certificate, with exactly the
// semantics Evaluate applies to a CBOM: the candidate is turned into the
// components a CBOM would carry for it. A rule about RSA therefore refuses an
// RSA key and a certificate an RSA CA would sign, just as the CBOM would list
// both the key and the CA under it.
//
// Locations in the result are "key", "issuer" and "certificate", so the
// caller can say which part broke the rule.
func Check(rules []Rule, c Candidate, at time.Time) Result {
	b := pqc.BOM{}
	add := func(name, where string) {
		if name == "" {
			return
		}
		a, _ := pqc.Normalise(name)
		comp := pqc.NewComponent(a, nil)
		comp.Evidence = &pqc.Evidence{Occurrences: []pqc.Occurrence{{Location: where}}}
		b.Components = append(b.Components, comp)
	}
	add(c.KeyAlgorithm, "key")
	add(c.IssuerKeyAlgorithm, "issuer")
	if c.Lifetime > 0 {
		nb, na := at, at.Add(c.Lifetime)
		b.Components = append(b.Components, pqc.Component{Type: "cryptographic-asset", BOMRef: "candidate",
			Name: "the certificate", CryptoProps: &pqc.CryptoProperties{AssetType: "certificate",
				CertProps: &pqc.CertificateProperties{NotValidBefore: &nb, NotValidAfter: &na}},
			Evidence: &pqc.Evidence{Occurrences: []pqc.Occurrence{{Location: "certificate"}}}})
	}
	return Evaluate(rules, b, at, Options{})
}
