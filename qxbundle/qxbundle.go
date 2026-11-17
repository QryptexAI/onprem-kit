// Package qxbundle carries a product's data out of an air-gapped site to a
// central CAMP on removable media: a .qxbundle file, signed by the install that
// made it and encrypted to the central CAMP.
//
// # Keys
//
//   - The central CAMP holds a Recipient: an HPKE key pair (RFC 9180) with the
//     hybrid ML-KEM-768 + X25519 KEM, so a bundle is no weaker than classical
//     encryption and safe against a future quantum computer.
//   - Each isolated install holds a Signer: an ML-DSA-65 key made once and kept in
//     its config volume. It is the install's identity at the central CAMP and,
//     unlike the TLS key, never changes when a certificate is renewed.
//
// # Enrolment, once per source, by file both ways
//
//  1. The central CAMP issues an Invitation: the source id it assigned and its
//     public key. It is carried into the isolated site.
//  2. The isolated install reads it and answers with an Enrolment: the same
//     source id and its signing key. It is carried out.
//  3. The central CAMP pins that signing key for that source.
//
// Neither file is secret, but either could be swapped on the way: a swapped
// Invitation would make bundles readable by somebody else, a swapped Enrolment
// would let somebody else send them. Both sides therefore show each key's
// Fingerprint, for the people at each end to compare (read aloud or on paper),
// as at a key ceremony.
//
// # The bundle
//
// A tar with three entries, so standard tools can list it:
//
//	header.json    who sent it, what it is, its sequence number (not secret)
//	payload.hpke   the payload, gzipped, then HPKE-sealed to the recipient with
//	               the header as the HPKE info: moving it under another header
//	               fails decryption
//	signature      ML-DSA-65 over the header and the sealed payload's SHA-256
//
// Open checks the signature with the pinned key before decrypting anything, and
// refuses a sequence number at or below the last one imported from that source
// (a replay, or an older bundle arriving late).
package qxbundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/hpke"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Format is the version of every file this package writes.
const Format = 1

// MaxPayload bounds a payload once decompressed, so a small bundle cannot
// expand into something that exhausts the importer.
const MaxPayload = 512 << 20

const (
	kindInvitation = "qxbundle-invitation"
	kindEnrolment  = "qxbundle-enrolment"

	entryHeader    = "header.json"
	entryPayload   = "payload.hpke"
	entrySignature = "signature"

	signatureContext = "qxbundle/1\n"
)

var (
	kem  = hpke.MLKEM768X25519()
	kdf  = hpke.HKDFSHA256()
	aead = hpke.AES256GCM()
	dsa  = mldsa.MLDSA65()
)

// Errors Open reports. Each means the bundle must not be imported.
var (
	ErrNotBundle   = errors.New("not a .qxbundle file")
	ErrBadSigner   = errors.New("the bundle is not signed by this source's enrolled key")
	ErrReplay      = errors.New("this bundle, or a newer one from the same source, was already imported")
	ErrNotForUs    = errors.New("the bundle was encrypted for a different central CAMP")
	ErrTooLarge    = errors.New("the bundle's payload is larger than an import may be")
	ErrWrongSource = errors.New("the bundle names a different source")
)

// Fingerprint is how a person checks a key: the SHA-256 of its bytes, in
// groups of four, as qryptex-root prints a root's.
func Fingerprint(key []byte) string {
	h := sha256.Sum256(key)
	s := hex.EncodeToString(h[:])
	var b strings.Builder
	for i := 0; i < len(s); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(s[i : i+4])
	}
	return b.String()
}

// ---- The central CAMP's key ----

// Recipient is the central CAMP's decryption key.
type Recipient struct{ priv hpke.PrivateKey }

// NewRecipient makes a central CAMP's key pair.
func NewRecipient() (*Recipient, error) {
	priv, err := kem.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &Recipient{priv}, nil
}

// ParseRecipient reads a key Bytes wrote.
func ParseRecipient(b []byte) (*Recipient, error) {
	priv, err := kem.NewPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("not a bundle recipient key: %w", err)
	}
	return &Recipient{priv}, nil
}

// Bytes is the private key, to keep sealed at rest.
func (r *Recipient) Bytes() ([]byte, error) { return r.priv.Bytes() }

// PublicKey is what an Invitation carries.
func (r *Recipient) PublicKey() []byte { return r.priv.PublicKey().Bytes() }

// ---- An isolated install's key ----

// Signer is an isolated install's signing key.
type Signer struct{ priv *mldsa.PrivateKey }

// NewSigner makes an install's signing key.
func NewSigner() (*Signer, error) {
	priv, err := mldsa.GenerateKey(dsa)
	if err != nil {
		return nil, err
	}
	return &Signer{priv}, nil
}

// ParseSigner reads a seed Seed returned.
func ParseSigner(seed []byte) (*Signer, error) {
	priv, err := mldsa.NewPrivateKey(dsa, seed)
	if err != nil {
		return nil, fmt.Errorf("not a bundle signing key: %w", err)
	}
	return &Signer{priv}, nil
}

// Seed is the private key (32 bytes), to keep sealed at rest.
func (s *Signer) Seed() []byte { return s.priv.Bytes() }

// PublicKey is what an Enrolment carries.
func (s *Signer) PublicKey() []byte { return s.priv.PublicKey().Bytes() }

// ---- Enrolment files ----

// Invitation is the file the central CAMP gives an isolated install.
type Invitation struct {
	Format       int       `json:"format"`
	Kind         string    `json:"kind"`
	Central      string    `json:"central"` // the central CAMP, as people know it
	SourceID     string    `json:"sourceId"`
	SourceName   string    `json:"sourceName"`
	KEM          uint16    `json:"kem"`
	RecipientKey []byte    `json:"recipientKey"`
	CreatedAt    time.Time `json:"createdAt"`
}

// NewInvitation invites a source the central CAMP has registered.
func NewInvitation(r *Recipient, central, sourceID, sourceName string, now time.Time) Invitation {
	return Invitation{Format: Format, Kind: kindInvitation, Central: central, SourceID: sourceID,
		SourceName: sourceName, KEM: kem.ID(), RecipientKey: r.PublicKey(), CreatedAt: now.UTC()}
}

// Fingerprint is the central CAMP's key, for the people at each end to compare.
func (i Invitation) Fingerprint() string { return Fingerprint(i.RecipientKey) }

// ParseInvitation reads and checks an invitation file.
func ParseInvitation(b []byte) (Invitation, error) {
	var i Invitation
	if err := json.Unmarshal(b, &i); err != nil || i.Kind != kindInvitation {
		return i, errors.New("not an invitation from a central CAMP")
	}
	if i.Format != Format {
		return i, fmt.Errorf("invitation format %d: this install reads format %d", i.Format, Format)
	}
	if i.KEM != kem.ID() || i.SourceID == "" {
		return i, errors.New("the invitation is incomplete or uses an unknown key type")
	}
	if _, err := kem.NewPublicKey(i.RecipientKey); err != nil {
		return i, errors.New("the invitation's key is not valid")
	}
	return i, nil
}

// Enrolment is the file an isolated install sends back to the central CAMP.
type Enrolment struct {
	Format     int       `json:"format"`
	Kind       string    `json:"kind"`
	SourceID   string    `json:"sourceId"`
	Product    string    `json:"product"` // CAMP, QRYPTOSCAN or PKI
	Name       string    `json:"name"`    // the install, as people know it
	SigningKey []byte    `json:"signingKey"`
	CreatedAt  time.Time `json:"createdAt"`
}

// NewEnrolment answers an invitation.
func NewEnrolment(s *Signer, inv Invitation, product, name string, now time.Time) Enrolment {
	return Enrolment{Format: Format, Kind: kindEnrolment, SourceID: inv.SourceID, Product: product,
		Name: name, SigningKey: s.PublicKey(), CreatedAt: now.UTC()}
}

// Fingerprint is the install's signing key, for the people at each end to compare.
func (e Enrolment) Fingerprint() string { return Fingerprint(e.SigningKey) }

// ParseEnrolment reads and checks an enrolment file.
func ParseEnrolment(b []byte) (Enrolment, error) {
	var e Enrolment
	if err := json.Unmarshal(b, &e); err != nil || e.Kind != kindEnrolment {
		return e, errors.New("not an enrolment from an isolated install")
	}
	if e.Format != Format {
		return e, fmt.Errorf("enrolment format %d: this install reads format %d", e.Format, Format)
	}
	if e.SourceID == "" {
		return e, errors.New("the enrolment names no source")
	}
	if _, err := mldsa.NewPublicKey(dsa, e.SigningKey); err != nil {
		return e, errors.New("the enrolment's signing key is not valid")
	}
	return e, nil
}

// ---- Bundles ----

// Header describes a bundle. It is not encrypted: an importer reads it to find
// the source before anything is decrypted.
type Header struct {
	Format   int    `json:"format"`
	SourceID string `json:"sourceId"`
	Product  string `json:"product"`
	// Kind is what the payload is, in the product's terms ("cbom",
	// "camp-results"); ContentType how it is encoded.
	Kind        string    `json:"kind"`
	ContentType string    `json:"contentType"`
	Seq         uint64    `json:"seq"`
	CreatedAt   time.Time `json:"createdAt"`
	// Recipient is the fingerprint of the key it was sealed to.
	Recipient string `json:"recipient"`
	Size      int64  `json:"size"` // the payload's size before compression
}

// Seal makes a bundle of payload for the central CAMP inv names. h supplies
// Product, Kind, ContentType and Seq; the rest is filled in.
func Seal(s *Signer, inv Invitation, h Header, payload []byte, now time.Time) ([]byte, error) {
	if len(payload) > MaxPayload {
		return nil, ErrTooLarge
	}
	pub, err := kem.NewPublicKey(inv.RecipientKey)
	if err != nil {
		return nil, errors.New("the invitation's key is not valid")
	}
	h.Format, h.SourceID, h.Recipient = Format, inv.SourceID, inv.Fingerprint()
	h.CreatedAt, h.Size = now.UTC(), int64(len(payload))
	header, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	if _, err := zw.Write(payload); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	sealed, err := hpke.Seal(pub, kdf, aead, header, z.Bytes())
	if err != nil {
		return nil, err
	}
	sig, err := s.priv.Sign(nil, signed(header, sealed), nil)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	for _, e := range []struct {
		name string
		data []byte
	}{{entryHeader, header}, {entryPayload, sealed}, {entrySignature, sig}} {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.data)), ModTime: h.CreatedAt}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(e.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// signed is what the signature covers: the header as written and the sealed
// payload's digest.
func signed(header, sealed []byte) []byte {
	d := sha256.Sum256(sealed)
	return append(append([]byte(signatureContext), header...), d[:]...)
}

type parts struct{ header, sealed, sig []byte }

func split(bundle []byte) (parts, Header, error) {
	var p parts
	var h Header
	tr := tar.NewReader(bytes.NewReader(bundle))
	for {
		th, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return p, h, ErrNotBundle
		}
		data, err := io.ReadAll(io.LimitReader(tr, MaxPayload+1))
		if err != nil {
			return p, h, ErrNotBundle
		}
		switch th.Name {
		case entryHeader:
			p.header = data
		case entryPayload:
			p.sealed = data
		case entrySignature:
			p.sig = data
		}
	}
	if p.header == nil || p.sealed == nil || p.sig == nil {
		return p, h, ErrNotBundle
	}
	if err := json.Unmarshal(p.header, &h); err != nil || h.SourceID == "" {
		return p, h, ErrNotBundle
	}
	if h.Format != Format {
		return p, h, fmt.Errorf("bundle format %d: this CAMP reads format %d", h.Format, Format)
	}
	return p, h, nil
}

// Inspect reads a bundle's header without checking it, so an importer can find
// the source's pinned key and last sequence number. Trust nothing in it until
// Open succeeds.
func Inspect(bundle []byte) (Header, error) {
	_, h, err := split(bundle)
	return h, err
}

// Open checks a bundle from the source whose enrolment was pinned and returns
// its header and payload. lastSeq is the highest sequence number already
// imported from that source (0 for none).
func Open(bundle []byte, r *Recipient, pinned Enrolment, lastSeq uint64) (Header, []byte, error) {
	p, h, err := split(bundle)
	if err != nil {
		return h, nil, err
	}
	if h.SourceID != pinned.SourceID {
		return h, nil, ErrWrongSource
	}
	pub, err := mldsa.NewPublicKey(dsa, pinned.SigningKey)
	if err != nil {
		return h, nil, ErrBadSigner
	}
	if mldsa.Verify(pub, signed(p.header, p.sealed), p.sig, nil) != nil {
		return h, nil, ErrBadSigner
	}
	if h.Seq <= lastSeq {
		return h, nil, ErrReplay
	}
	if h.Recipient != Fingerprint(r.PublicKey()) {
		return h, nil, ErrNotForUs
	}
	z, err := hpke.Open(r.priv, kdf, aead, p.header, p.sealed)
	if err != nil {
		return h, nil, ErrNotForUs
	}
	zr, err := gzip.NewReader(bytes.NewReader(z))
	if err != nil {
		return h, nil, ErrNotBundle
	}
	payload, err := io.ReadAll(io.LimitReader(zr, MaxPayload+1))
	if err != nil {
		return h, nil, ErrNotBundle
	}
	if len(payload) > MaxPayload {
		return h, nil, ErrTooLarge
	}
	return h, payload, nil
}
