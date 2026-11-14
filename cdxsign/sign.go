// Package cdxsign signs and verifies a CycloneDX document with an enveloped JSF
// signature (JSON Signature Format 0.82, the format CycloneDX 1.6 defines for its
// top-level "signature"), over the document's RFC 8785 canonical form.
//
// The signature carries the signer's certificate path, so a verifier needs
// nothing but the document to learn who signed it. Whether to TRUST that
// certificate is the verifier's decision: Verify reports who, not whether.
//
// Supported keys: ECDSA P-256/384/521 (ES256/384/512), RSA (PS256) and Ed25519.
// JSF names no post-quantum algorithm, and inventing a name would produce a
// signature no other tool could check, so any other key is refused and the
// caller ships the document unsigned and says so.
package cdxsign

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

// ErrUnsigned means the document has no signature.
var ErrUnsigned = errors.New("the document is not signed")

// ErrUnsupportedKey means the key has no JSF algorithm name.
var ErrUnsupportedKey = errors.New("JSF has no signature algorithm for this key type")

var b64 = base64.RawURLEncoding

// Sign returns doc with a JSF "signature" added, signed by signer, whose
// certificate is chain[0]. doc must be a JSON object without a signature.
// The result is indented for reading; the signature covers the canonical form,
// so formatting does not matter to it.
func Sign(doc []byte, signer crypto.Signer, chain []*x509.Certificate) ([]byte, error) {
	if len(chain) == 0 {
		return nil, errors.New("a signature needs the signer's certificate")
	}
	alg, err := algorithmFor(signer.Public())
	if err != nil {
		return nil, err
	}
	var obj map[string]any
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return nil, fmt.Errorf("not a JSON object: %w", err)
	}
	if _, has := obj["signature"]; has {
		return nil, errors.New("the document is already signed")
	}
	path := make([]any, len(chain))
	for i, c := range chain {
		path[i] = b64.EncodeToString(c.Raw)
	}
	sig := map[string]any{"algorithm": alg, "certificatePath": path}
	obj["signature"] = sig

	data, err := canonical(obj)
	if err != nil {
		return nil, err
	}
	value, err := sign(signer, alg, data)
	if err != nil {
		return nil, err
	}
	sig["value"] = b64.EncodeToString(value)

	out, err := canonical(obj)
	if err != nil {
		return nil, err
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, out, "", " "); err != nil {
		return nil, err
	}
	pretty.WriteByte('\n')
	return pretty.Bytes(), nil
}

// Verify checks doc's JSF signature and returns the certificate that signed it.
// ErrUnsigned when there is none; any other error means the signature does not
// hold (the document was changed, or the signature is malformed).
func Verify(doc []byte) (*x509.Certificate, error) {
	var obj map[string]any
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return nil, fmt.Errorf("not a JSON object: %w", err)
	}
	raw, has := obj["signature"]
	if !has {
		return nil, ErrUnsigned
	}
	sig, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("signature is not a JSF signature object")
	}
	alg, _ := sig["algorithm"].(string)
	value, _ := sig["value"].(string)
	path, _ := sig["certificatePath"].([]any)
	if alg == "" || value == "" || len(path) == 0 {
		return nil, errors.New("signature lacks its algorithm, value or certificate path")
	}
	first, _ := path[0].(string)
	der, err := b64.DecodeString(first)
	if err != nil {
		return nil, fmt.Errorf("certificate path: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("certificate path: %w", err)
	}
	if want, err := algorithmFor(cert.PublicKey); err != nil || want != alg {
		return nil, fmt.Errorf("algorithm %s does not match the signer's key", alg)
	}
	sigBytes, err := b64.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("signature value: %w", err)
	}
	delete(sig, "value")
	data, err := canonical(obj)
	if err != nil {
		return nil, err
	}
	if err := check(cert.PublicKey, alg, data, sigBytes); err != nil {
		return nil, err
	}
	return cert, nil
}

func canonical(obj map[string]any) ([]byte, error) {
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return Canonicalize(b)
}

func algorithmFor(pub crypto.PublicKey) (string, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return "ES256", nil
		case elliptic.P384():
			return "ES384", nil
		case elliptic.P521():
			return "ES512", nil
		}
	case *rsa.PublicKey:
		return "PS256", nil
	case ed25519.PublicKey:
		return "Ed25519", nil
	}
	return "", fmt.Errorf("%w (%T)", ErrUnsupportedKey, pub)
}

func digest(alg string, data []byte) (crypto.Hash, []byte) {
	var h hash.Hash
	var id crypto.Hash
	switch alg {
	case "ES384":
		h, id = sha512.New384(), crypto.SHA384
	case "ES512":
		h, id = sha512.New(), crypto.SHA512
	default:
		h, id = sha256.New(), crypto.SHA256
	}
	h.Write(data)
	return id, h.Sum(nil)
}

func sign(s crypto.Signer, alg string, data []byte) ([]byte, error) {
	switch alg {
	case "Ed25519":
		return s.Sign(rand.Reader, data, crypto.Hash(0))
	case "PS256":
		id, d := digest(alg, data)
		return s.Sign(rand.Reader, d, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: id})
	}
	// ECDSA: JSF, like JWS, carries R || S at the curve's size, not ASN.1.
	id, d := digest(alg, data)
	der, err := s.Sign(rand.Reader, d, id)
	if err != nil {
		return nil, err
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &rs); err != nil {
		return nil, err
	}
	n := (s.Public().(*ecdsa.PublicKey).Curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*n)
	rs.R.FillBytes(out[:n])
	rs.S.FillBytes(out[n:])
	return out, nil
}

func check(pub crypto.PublicKey, alg string, data, sig []byte) error {
	bad := errors.New("the signature does not match the document")
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(k, data, sig) {
			return bad
		}
	case *rsa.PublicKey:
		id, d := digest(alg, data)
		if rsa.VerifyPSS(k, id, d, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: id}) != nil {
			return bad
		}
	case *ecdsa.PublicKey:
		_, d := digest(alg, data)
		n := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*n {
			return bad
		}
		r, s := new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:])
		if !ecdsa.Verify(k, d, r, s) {
			return bad
		}
	default:
		return ErrUnsupportedKey
	}
	return nil
}
