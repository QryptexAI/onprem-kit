// Package cbomfeed sends a product's CBOM to CAMP, which assembles it with CAMP's
// own and every other source into one organisation-level document.
//
// QryptoScan and PKI both send, and the credential lifecycle is the same for each,
// so it lives here once. What a product does with the result (store the credential,
// record the last push, show a failure) is the product's.
//
// # Trust
//
// The credential is a bearer secret, so CAMP is only ever reached over HTTPS. A CAMP
// on a certificate from the organisation's own CA is reached by giving that CA, in
// addition to the system's roots, never by turning verification off.
//
// # The contract
//
// An administrator registers the source in CAMP and is shown a single-use enrolment
// token. Redeem exchanges it once for a long-lived credential that names this source
// and only this source. Push sends a CycloneDX 1.6 document with that credential;
// CAMP records it, or records why it refused it, against the source.
//
// # Re-issue offer
//
// PKI's pushes also carry where and how CAMP can ask PKI to re-issue a
// certificate it found: PKI's address and a credential that names the
// organisation in PKI. Sent with every push, so a re-issued credential reaches
// CAMP on the next one; a CAMP that predates it ignores the two headers.
package cbomfeed

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MaxDocumentBytes is CAMP's cap on one document. Checked here too, so an oversized
// document is reported as that before it is sent rather than after.
const MaxDocumentBytes = 25 << 20

// Error is CAMP refusing a request, with its reason. Retrying will not help.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("CAMP refused it (%d %s): %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("CAMP refused it (%d): %s", e.Status, e.Message)
}

// Unauthorised reports whether CAMP no longer accepts the credential, which means
// the source was revoked or re-enrolled elsewhere and needs enrolling again.
func Unauthorised(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusUnauthorized
}

// The headers that carry a re-issue offer on a push.
const (
	HeaderReissueURL        = "X-Qryptex-Reissue-Url"
	HeaderReissueCredential = "X-Qryptex-Reissue-Credential"
)

// ReissueOffer is PKI telling CAMP where to file re-issue requests: PKI's
// address (https) and the credential to file them with.
type ReissueOffer struct {
	URL        string
	Credential string
}

// Client talks to one CAMP.
type Client struct {
	base string
	http *http.Client
	// wait is between attempts; replaced in tests.
	wait func(attempt int) time.Duration
}

// New returns a client for CAMP at campURL. caPEM, if not empty, is the certificate
// of a CA to trust for CAMP in addition to the system's.
func New(campURL, caPEM string) (*Client, error) {
	base, err := Address(campURL)
	if err != nil {
		return nil, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if strings.TrimSpace(caPEM) != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, errors.New("the CA certificate is not a PEM certificate")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &Client{
		base: base,
		http: &http.Client{Transport: tr, Timeout: 2 * time.Minute},
		wait: func(attempt int) time.Duration { return time.Duration(attempt*attempt) * 5 * time.Second },
	}, nil
}

// Address checks and normalises CAMP's address: https, a host, no path beyond "/".
func Address(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", errors.New("CAMP's address must be a URL such as https://camp.example.com")
	}
	if u.Scheme != "https" {
		return "", errors.New("CAMP's address must start with https://: the credential is never sent unencrypted")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("CAMP's address must be just the scheme, host and port")
	}
	return "https://" + u.Host + strings.TrimRight(u.Path, "/"), nil
}

// Redeem exchanges a single-use enrolment token for this source's credential.
func (c *Client) Redeem(ctx context.Context, token string) (credential, feedID string, err error) {
	body, _ := json.Marshal(map[string]string{"enrolmentToken": strings.TrimSpace(token)})
	var out struct {
		Credential string `json:"credential"`
		FeedID     string `json:"feedId"`
	}
	if err := c.do(ctx, "/api/v1/cbom/feeds/enroll", "", "application/json", body, &out, nil); err != nil {
		return "", "", err
	}
	if out.Credential == "" {
		return "", "", errors.New("CAMP returned no credential")
	}
	return out.Credential, out.FeedID, nil
}

// Push sends one CycloneDX document. A refusal comes back as *Error at once; a
// network failure or a CAMP that is restarting is tried three times in all.
func (c *Client) Push(ctx context.Context, credential string, doc []byte) error {
	return c.PushWithOffer(ctx, credential, doc, nil)
}

// PushWithOffer is Push carrying a re-issue offer (PKI only). An offer whose URL
// is not https is not sent: the credential never travels unencrypted.
func (c *Client) PushWithOffer(ctx context.Context, credential string, doc []byte, offer *ReissueOffer) error {
	var extra http.Header
	if offer != nil && offer.Credential != "" && strings.HasPrefix(offer.URL, "https://") {
		extra = http.Header{}
		extra.Set(HeaderReissueURL, strings.TrimRight(offer.URL, "/"))
		extra.Set(HeaderReissueCredential, offer.Credential)
	}
	if len(doc) > MaxDocumentBytes {
		return &Error{Status: http.StatusRequestEntityTooLarge, Code: "DOCUMENT_REFUSED",
			Message: fmt.Sprintf("the document is %d MB, over CAMP's 25 MB limit", len(doc)>>20)}
	}
	var last error
	for attempt := 1; attempt <= 3; attempt++ {
		last = c.do(ctx, "/api/v1/cbom/feeds/push", credential, "application/vnd.cyclonedx+json", doc, nil, extra)
		var refused *Error
		if last == nil || (errors.As(last, &refused) && refused.Status < 500) {
			return last
		}
		if attempt < 3 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(c.wait(attempt)):
			}
		}
	}
	return last
}

func (c *Client) do(ctx context.Context, path, credential, contentType string, body []byte, out any, extra http.Header) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range extra {
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", contentType)
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach CAMP: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode/100 != 2 {
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := e.Error.Message
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
			if len(msg) > 200 {
				msg = msg[:200]
			}
		}
		return &Error{Status: res.StatusCode, Code: e.Error.Code, Message: msg}
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("CAMP's answer could not be read: %w", err)
		}
	}
	return nil
}
