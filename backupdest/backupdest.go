// Package backupdest is where an on-prem backup goes once it has been made.
//
// Shared by PKI, CAMP and QryptoScan. Each product decides WHAT to back up and
// how to restore it — that is product knowledge and stays with the product. Where
// the resulting blob is written is not: a bucket is a bucket. Three
// implementations of "put this object in S3" is three places to fix the same
// pagination bug.
//
// LAYERING, and why this package has no dependencies. onprem-kit is imported by
// all three products for small things like hostmatch and serviceurl, and it has
// had no third-party dependencies at all. Pulling an S3 SDK into the root of it
// would put that in every consumer's dependency graph whether or not they store
// backups anywhere.
//
// So the interface, the retention policy and the filesystem implementation live
// here with no dependencies, and each concrete remote backend is a SUBPACKAGE
// carrying its own: backupdest/s3, backupdest/sftp. A product imports the ones it
// offers.
package backupdest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Object is one stored backup, as the destination reports it.
type Object struct {
	Name     string    `json:"name"`
	Modified time.Time `json:"modified"`
	Size     int64     `json:"size"`
	// Location is a human-usable pointer — a URL or a path — for an operator who
	// needs to find the file without this software. Empty when there isn't one.
	Location string `json:"location,omitempty"`
}

// Destination is somewhere backups are kept.
//
// Deliberately small. Everything a caller needs is put/list/delete plus something
// printable for logs and the UI; anything richer would be one backend's feature
// leaking into an interface the others must fake.
type Destination interface {
	Put(ctx context.Context, name string, data []byte) error
	List(ctx context.Context) ([]Object, error)
	Delete(ctx context.Context, name string) error
	// Describe returns a short, NON-SECRET identifier for logs and the UI —
	// "s3:acme-backups/camp/". It must never include a credential: it is printed
	// in places a password must not reach.
	Describe() string
}

// Prune keeps the newest `keep` backups and deletes the rest.
//
// keep <= 0 disables it, because "keep zero backups" is far more likely to be an
// unset config value than a deliberate instruction to delete everything.
//
// It considers EVERY object the destination lists. Use PruneMatching whenever the
// destination might hold anything else.
func Prune(ctx context.Context, d Destination, keep int) ([]string, error) {
	return PruneMatching(ctx, d, keep, nil)
}

// PruneMatching keeps the newest `keep` objects for which match returns true, and
// deletes the rest of the MATCHING ones. Objects that do not match are never
// listed for deletion and never counted toward `keep`.
//
// THIS EXISTS BECAUSE A BUCKET IS NOT ALWAYS OURS. Customers point backups at a
// bucket they already use, or at one shared between products — PKI, CAMP and
// QryptoScan can all be configured to the same place. A retention pass that
// counts and deletes every object it can see will happily delete another
// product's backups, or a customer's unrelated files, and report a successful
// retention run.
//
// QryptoScan's own implementation filtered on its name prefix and suffix for
// exactly this reason. Moving to a shared package must not lose that.
func PruneMatching(ctx context.Context, d Destination, keep int, match func(Object) bool) ([]string, error) {
	if keep <= 0 {
		return nil, nil
	}
	all, err := d.List(ctx)
	if err != nil {
		return nil, err
	}
	objs := all
	if match != nil {
		objs = objs[:0:0]
		for _, o := range all {
			if match(o) {
				objs = append(objs, o)
			}
		}
	}
	sort.Slice(objs, func(i, j int) bool { return objs[i].Modified.After(objs[j].Modified) })
	var deleted []string
	for i := keep; i < len(objs); i++ {
		if err := d.Delete(ctx, objs[i].Name); err != nil {
			// Returns what was already deleted alongside the error: a caller that
			// logs only the error would otherwise report nothing removed while
			// several were.
			return deleted, fmt.Errorf("prune %s: %w", objs[i].Name, err)
		}
		deleted = append(deleted, objs[i].Name)
	}
	return deleted, nil
}

// Settings describes a destination in configuration. Products persist this; the
// concrete backends read it.
type Settings struct {
	// Provider selects the backend: "local", "s3", "gcs", "minio", "sftp".
	Provider string `json:"provider"`

	// Bucket/Prefix/Region/Endpoint apply to the object-store backends.
	Bucket   string `json:"bucket,omitempty"`
	Prefix   string `json:"prefix,omitempty"`
	Region   string `json:"region,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`

	// AccessKey/SecretKey are the object-store credential. For GCS these are HMAC
	// interoperability keys, not a service-account JSON file.
	AccessKey string `json:"accessKey,omitempty"`
	SecretKey string `json:"secretKey,omitempty"`

	// Host/Port/User/Path/PrivateKeyPEM/HostKey apply to sftp.
	Host          string `json:"host,omitempty"`
	Port          int    `json:"port,omitempty"`
	User          string `json:"user,omitempty"`
	Path          string `json:"path,omitempty"`
	PrivateKeyPEM string `json:"privateKeyPem,omitempty"`
	Password      string `json:"password,omitempty"`
	// HostKey is the expected SSH host public key in authorized_keys form.
	// REQUIRED by backupdest/sftp: without it there is nothing to authenticate the
	// server, and backups would be handed to whoever answers.
	HostKey string `json:"hostKey,omitempty"`

	// LocalDir applies to "local".
	LocalDir string `json:"localDir,omitempty"`

	// Retain is how many backups to keep. 0 keeps everything.
	Retain int `json:"retain,omitempty"`
}

// Redacted returns a copy safe to log or return from an API: every secret is
// replaced with a fixed marker, so "is a credential set" survives while the
// credential does not.
func (s Settings) Redacted() Settings {
	const set = "********"
	if s.SecretKey != "" {
		s.SecretKey = set
	}
	if s.Password != "" {
		s.Password = set
	}
	if s.PrivateKeyPEM != "" {
		s.PrivateKeyPEM = set
	}
	return s
}

// Local writes backups to a filesystem directory. Useful on its own for a
// mounted NFS or a second disk, and it is the destination products fall back to
// when none is configured.
type Local struct{ dir string }

func NewLocal(dir string) *Local { return &Local{dir: dir} }

func (l *Local) Describe() string { return "local:" + l.dir }

func (l *Local) Put(_ context.Context, name string, data []byte) error {
	if err := safeName(name); err != nil {
		return err
	}
	if err := os.MkdirAll(l.dir, 0o700); err != nil {
		return err
	}
	// Written to a temporary name and renamed, so a crash mid-write leaves no
	// half-file that lists as a backup and fails at restore.
	tmp := filepath.Join(l.dir, "."+name+".part")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(l.dir, name))
}

func (l *Local) List(_ context.Context) ([]Object, error) {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // nothing stored yet is not an error
		}
		return nil, err
	}
	var out []Object
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue // skip the .part files above
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		p := filepath.Join(l.dir, e.Name())
		out = append(out, Object{Name: e.Name(), Modified: fi.ModTime(), Size: fi.Size(), Location: p})
	}
	return out, nil
}

func (l *Local) Delete(_ context.Context, name string) error {
	if err := safeName(name); err != nil {
		return err
	}
	err := os.Remove(filepath.Join(l.dir, name))
	if os.IsNotExist(err) {
		return nil // deleting what is already gone is success
	}
	return err
}

// safeName refuses anything that could escape the destination directory or
// prefix. Backup names are generated by the product, but they also arrive from a
// list the operator can act on, and "delete this name" reaching os.Remove with
// "../../etc/passwd" in it is the kind of thing worth making impossible here
// rather than trusting every caller.
func safeName(name string) error {
	if name == "" {
		return fmt.Errorf("backupdest: empty object name")
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return fmt.Errorf("backupdest: unsafe object name %q", name)
	}
	return nil
}
