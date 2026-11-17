package qxbundle

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2027, 1, 12, 9, 0, 0, 0, time.UTC)

// enrolled is one central CAMP and one isolated install, enrolled by file both ways.
func enrolled(t *testing.T) (*Recipient, *Signer, Invitation, Enrolment) {
	t.Helper()
	r, err := NewRecipient()
	if err != nil {
		t.Fatal(err)
	}
	invFile, _ := jsonOf(NewInvitation(r, "camp.hq.example", "src-1", "Plant 4", now))
	inv, err := ParseInvitation(invFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	enrFile, _ := jsonOf(NewEnrolment(s, inv, "CAMP", "camp.plant4.local", now))
	enr, err := ParseEnrolment(enrFile)
	if err != nil {
		t.Fatal(err)
	}
	return r, s, inv, enr
}

func TestRoundTrip(t *testing.T) {
	r, s, inv, enr := enrolled(t)
	payload := []byte(strings.Repeat(`{"bomFormat":"CycloneDX"}`, 1000))
	b, err := Seal(s, inv, Header{Product: "CAMP", Kind: "camp-results", ContentType: "application/json", Seq: 7}, payload, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > len(payload) {
		t.Errorf("not compressed: %d bytes for a %d-byte payload", len(b), len(payload))
	}
	h, err := Inspect(b)
	if err != nil || h.SourceID != "src-1" || h.Seq != 7 {
		t.Fatalf("inspect: %+v %v", h, err)
	}
	h, got, err := Open(b, r, enr, 6)
	if err != nil || !bytes.Equal(got, payload) || h.Kind != "camp-results" || h.Size != int64(len(payload)) {
		t.Fatalf("open: %+v %v", h, err)
	}
	// The payload is not readable in the file.
	if bytes.Contains(b, []byte("CycloneDX")) {
		t.Fatal("the payload is in the clear")
	}
}

func TestReplayAndOrder(t *testing.T) {
	r, s, inv, enr := enrolled(t)
	b, _ := Seal(s, inv, Header{Kind: "cbom", Seq: 5}, []byte("x"), now)
	for _, last := range []uint64{5, 9} {
		if _, _, err := Open(b, r, enr, last); !errors.Is(err, ErrReplay) {
			t.Errorf("seq 5 after %d: %v", last, err)
		}
	}
}

// rewrite replaces one entry of a bundle.
func rewrite(t *testing.T, b []byte, name string, f func([]byte) []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	tr, tw := tar.NewReader(bytes.NewReader(b)), tar.NewWriter(&out)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		data, _ := io.ReadAll(tr)
		if h.Name == name {
			data = f(data)
		}
		h.Size = int64(len(data))
		_ = tw.WriteHeader(h)
		_, _ = tw.Write(data)
	}
	_ = tw.Close()
	return out.Bytes()
}

func TestTamperingIsRefused(t *testing.T) {
	r, s, inv, enr := enrolled(t)
	b, _ := Seal(s, inv, Header{Kind: "cbom", Seq: 2}, []byte("the estate"), now)
	flip := func(d []byte) []byte { d = append([]byte{}, d...); d[len(d)/2] ^= 1; return d }
	for name, bad := range map[string][]byte{
		"header":    rewrite(t, b, entryHeader, func(d []byte) []byte { return bytes.Replace(d, []byte(`"seq":2`), []byte(`"seq":3`), 1) }),
		"payload":   rewrite(t, b, entryPayload, flip),
		"signature": rewrite(t, b, entrySignature, flip),
	} {
		if _, _, err := Open(bad, r, enr, 0); !errors.Is(err, ErrBadSigner) {
			t.Errorf("%s changed: %v", name, err)
		}
	}
	if _, _, err := Open([]byte("not a tar"), r, enr, 0); !errors.Is(err, ErrNotBundle) {
		t.Errorf("garbage: %v", err)
	}
}

func TestOnlyTheEnrolledSourceAndCentral(t *testing.T) {
	r, s, inv, enr := enrolled(t)
	b, _ := Seal(s, inv, Header{Kind: "cbom", Seq: 1}, []byte("x"), now)

	// Another install's key, pinned for this source, does not verify it.
	other, _ := NewSigner()
	impostor := enr
	impostor.SigningKey = other.PublicKey()
	if _, _, err := Open(b, r, impostor, 0); !errors.Is(err, ErrBadSigner) {
		t.Errorf("another key: %v", err)
	}
	// A bundle naming another source is refused before anything else.
	elsewhere := enr
	elsewhere.SourceID = "src-2"
	if _, _, err := Open(b, r, elsewhere, 0); !errors.Is(err, ErrWrongSource) {
		t.Errorf("another source: %v", err)
	}
	// Another central CAMP cannot read it.
	r2, _ := NewRecipient()
	if _, _, err := Open(b, r2, enr, 0); !errors.Is(err, ErrNotForUs) {
		t.Errorf("another central: %v", err)
	}
}

func TestKeysSurviveStorage(t *testing.T) {
	r, s, inv, enr := enrolled(t)
	rb, err := r.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	r2, err := ParseRecipient(rb)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := ParseSigner(s.Seed())
	if err != nil || len(s.Seed()) != 32 {
		t.Fatalf("seed: %d bytes, %v", len(s.Seed()), err)
	}
	b, _ := Seal(s2, inv, Header{Kind: "cbom", Seq: 1}, []byte("x"), now)
	if _, _, err := Open(b, r2, enr, 0); err != nil {
		t.Fatalf("after reloading both keys: %v", err)
	}
}

func TestFilesAreChecked(t *testing.T) {
	r, s, inv, _ := enrolled(t)
	if !strings.Contains(inv.Fingerprint(), " ") || len(inv.Fingerprint()) != 79 {
		t.Errorf("fingerprint %q", inv.Fingerprint())
	}
	for name, raw := range map[string]string{
		"not JSON":     "hello",
		"an enrolment": `{"kind":"qxbundle-enrolment","format":1}`,
		"newer format": `{"kind":"qxbundle-invitation","format":2}`,
		"no key":       `{"kind":"qxbundle-invitation","format":1,"sourceId":"s","kem":` + itoa(kem.ID()) + `}`,
	} {
		if _, err := ParseInvitation([]byte(raw)); err == nil {
			t.Errorf("invitation %s accepted", name)
		}
	}
	e := NewEnrolment(s, inv, "PKI", "pki.plant4", now)
	e.SigningKey = r.PublicKey() // a KEM key is not a signing key
	raw, _ := jsonOf(e)
	if _, err := ParseEnrolment(raw); err == nil {
		t.Error("an enrolment with a non-ML-DSA key was accepted")
	}
}

func TestTooLarge(t *testing.T) {
	_, s, inv, _ := enrolled(t)
	if _, err := Seal(s, inv, Header{Seq: 1}, make([]byte, MaxPayload+1), now); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversized payload: %v", err)
	}
}

func jsonOf(v any) ([]byte, error) { return json.Marshal(v) }

func itoa(n uint16) string { return strconv.Itoa(int(n)) }
