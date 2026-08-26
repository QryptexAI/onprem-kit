// Package s3 stores backups in any S3-compatible object store.
//
// ONE BACKEND, SEVERAL PROVIDERS. AWS S3, Google Cloud Storage, MinIO, Backblaze
// B2, Wasabi and most on-prem object stores all speak the S3 API, so they need
// one implementation and a different endpoint — not one SDK each.
//
// GOOGLE CLOUD STORAGE, specifically: this uses GCS's S3 interoperability
// endpoint, which needs an HMAC key pair (an access key and a secret), NOT a
// service-account JSON file. An operator who has only the JSON has to create an
// HMAC key in the console first. That is a real papercut, and it is a deliberate
// trade against carrying a second, much larger SDK for one provider.
package s3

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/QryptexAI/onprem-kit/backupdest"
)

// Endpoint presets. A provider name is easier for an operator to get right than
// a hostname, and wrong hostnames fail in ways that look like credential errors.
const (
	awsSuffix = "s3.amazonaws.com"
	gcsHost   = "storage.googleapis.com"
)

// Store is an S3-compatible destination.
type Store struct {
	c        *minio.Client
	bucket   string
	prefix   string
	describe string
}

// New builds a Store from settings.
func New(s backupdest.Settings) (*Store, error) {
	if s.Bucket == "" {
		return nil, fmt.Errorf("s3: no bucket configured")
	}
	if s.AccessKey == "" || s.SecretKey == "" {
		return nil, fmt.Errorf("s3: no credentials configured")
	}
	endpoint, secure := s.Endpoint, true
	switch strings.ToLower(s.Provider) {
	case "gcs":
		endpoint = gcsHost
	case "s3", "aws", "":
		if endpoint == "" {
			if s.Region != "" {
				endpoint = "s3." + s.Region + ".amazonaws.com"
			} else {
				endpoint = awsSuffix
			}
		}
	}
	if endpoint == "" {
		return nil, fmt.Errorf("s3: provider %q needs an endpoint", s.Provider)
	}
	// A caller may supply a scheme; minio wants host[:port] and a flag.
	if rest, ok := strings.CutPrefix(endpoint, "http://"); ok {
		endpoint, secure = rest, false
	} else if rest, ok := strings.CutPrefix(endpoint, "https://"); ok {
		endpoint = rest
	}

	c, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(s.AccessKey, s.SecretKey, ""),
		Secure: secure,
		Region: s.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("s3: %w", err)
	}
	prefix := s.Prefix
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return &Store{
		c: c, bucket: s.Bucket, prefix: prefix,
		// No credential in here — Describe goes to logs and the UI.
		describe: fmt.Sprintf("%s:%s/%s", endpointLabel(s.Provider), s.Bucket, prefix),
	}, nil
}

func endpointLabel(provider string) string {
	if provider == "" {
		return "s3"
	}
	return strings.ToLower(provider)
}

func (s *Store) Describe() string { return s.describe }

func (s *Store) Put(ctx context.Context, name string, data []byte) error {
	if err := safeName(name); err != nil {
		return err
	}
	_, err := s.c.PutObject(ctx, s.bucket, s.prefix+name,
		bytes.NewReader(data), int64(len(data)),
		minio.PutObjectOptions{ContentType: "application/octet-stream"})
	if err != nil {
		return fmt.Errorf("s3: put %s: %w", name, err)
	}
	return nil
}

func (s *Store) List(ctx context.Context) ([]backupdest.Object, error) {
	var out []backupdest.Object
	for obj := range s.c.ListObjects(ctx, s.bucket,
		minio.ListObjectsOptions{Prefix: s.prefix, Recursive: true}) {
		if obj.Err != nil {
			return nil, fmt.Errorf("s3: list: %w", obj.Err)
		}
		out = append(out, backupdest.Object{
			Name:     strings.TrimPrefix(obj.Key, s.prefix),
			Modified: obj.LastModified,
			Size:     obj.Size,
			Location: fmt.Sprintf("s3://%s/%s", s.bucket, obj.Key),
		})
	}
	return out, nil
}

func (s *Store) Delete(ctx context.Context, name string) error {
	if err := safeName(name); err != nil {
		return err
	}
	if err := s.c.RemoveObject(ctx, s.bucket, s.prefix+name, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("s3: delete %s: %w", name, err)
	}
	return nil
}

// safeName mirrors the check in the core package. A key with ".." in it does not
// escape a bucket the way a path escapes a directory, but it does let a caller
// address objects outside the configured prefix — which is the same problem for
// a destination shared between tenants or products.
func safeName(name string) error {
	if name == "" {
		return fmt.Errorf("s3: empty object name")
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return fmt.Errorf("s3: unsafe object name %q", name)
	}
	return nil
}
