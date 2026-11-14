package cbomfeed

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func camp(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	c, err := New(srv.URL, string(ca))
	if err != nil {
		t.Fatal(err)
	}
	c.wait = func(int) time.Duration { return time.Millisecond }
	return c, srv
}

func TestAddressNeverPlainHTTP(t *testing.T) {
	for in, want := range map[string]string{
		"https://camp.example.com":         "https://camp.example.com",
		" https://camp.example.com:8443/ ": "https://camp.example.com:8443",
	} {
		if got, err := Address(in); err != nil || got != want {
			t.Errorf("Address(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"http://camp.example.com", "camp.example.com", "", "https://u:p@camp.example.com", "https://camp.example.com/?x=1"} {
		if _, err := Address(bad); err == nil {
			t.Errorf("Address(%q) was accepted", bad)
		}
	}
}

func TestRedeemAndPush(t *testing.T) {
	var pushed string
	c, _ := camp(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/cbom/feeds/enroll":
			b, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(b), `"enrolmentToken":"tok"`) {
				w.WriteHeader(401)
				return
			}
			_, _ = io.WriteString(w, `{"credential":"cred","feedId":"f1"}`)
		case "/api/v1/cbom/feeds/push":
			if r.Header.Get("Authorization") != "Bearer cred" {
				w.WriteHeader(401)
				_, _ = io.WriteString(w, `{"error":{"message":"the source credential is not valid"}}`)
				return
			}
			b, _ := io.ReadAll(r.Body)
			pushed = string(b)
			_, _ = io.WriteString(w, `{"accepted":true}`)
		}
	})
	cred, feed, err := c.Redeem(context.Background(), " tok ")
	if err != nil || cred != "cred" || feed != "f1" {
		t.Fatalf("Redeem = %q %q %v", cred, feed, err)
	}
	if err := c.Push(context.Background(), cred, []byte(`{"bomFormat":"CycloneDX"}`)); err != nil || pushed == "" {
		t.Fatalf("Push = %v, sent %q", err, pushed)
	}
	err = c.Push(context.Background(), "revoked", []byte(`{}`))
	if !Unauthorised(err) {
		t.Fatalf("a refused credential: %v", err)
	}
}

// A refusal is CAMP's answer and is not retried; a CAMP that is restarting is.
func TestPushRetriesOnlyWhatMightRecover(t *testing.T) {
	var calls atomic.Int32
	c, _ := camp(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(503)
			return
		}
		_, _ = io.WriteString(w, `{"accepted":true}`)
	})
	if err := c.Push(context.Background(), "cred", []byte(`{}`)); err != nil || calls.Load() != 3 {
		t.Fatalf("Push = %v after %d calls", err, calls.Load())
	}

	calls.Store(0)
	c2, _ := camp(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(400)
		_, _ = io.WriteString(w, `{"error":{"code":"DOCUMENT_REFUSED","message":"specVersion is \"1.4\", want 1.6"}}`)
	})
	err := c2.Push(context.Background(), "cred", []byte(`{}`))
	if e, ok := err.(*Error); !ok || e.Code != "DOCUMENT_REFUSED" || !strings.Contains(e.Message, "1.6") || calls.Load() != 1 {
		t.Fatalf("Push = %v after %d calls", err, calls.Load())
	}
}

func TestPushRefusesAnOversizedDocumentWithoutSending(t *testing.T) {
	var calls atomic.Int32
	c, _ := camp(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1) })
	err := c.Push(context.Background(), "cred", make([]byte, MaxDocumentBytes+1))
	if e, ok := err.(*Error); !ok || e.Status != 413 || calls.Load() != 0 {
		t.Fatalf("Push = %v, %d calls", err, calls.Load())
	}
}

// Without the CA, a CAMP on a private certificate is not trusted.
func TestUntrustedCertificateIsRefused(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Redeem(context.Background(), "tok"); err == nil || !strings.Contains(err.Error(), "could not reach CAMP") {
		t.Fatalf("Redeem against an untrusted certificate: %v", err)
	}
	if _, err := New(srv.URL, "not a certificate"); err == nil {
		t.Error("a CA that is not PEM was accepted")
	}
}
