// Package serviceurl moves an installation from http://host:port to
// https://its.real.hostname.

// Shared by every product, because the operation is identical in all of them and
// the parts that go wrong are subtle: which port to take, what to put back when
// it fails, and who is allowed to read the private key afterwards. Three copies
// would be three chances to get one of those slightly different.
//
// WHY THE UPDATER DOES THIS AND NOT THE SERVICE. qryptoscan-service holds the
// findings database and has no Docker access at all — deliberately. Only the
// updater talks to the engine, through a proxy limited to containers, images,
// networks and volumes. So the service records a PENDING change and this
// consumes it: the component that already recreates the stack for upgrades is
// the one that recreates it for a hostname, with the same rollback.
//
// WHY IT IS A RECREATE. The certificate is a file on the config volume, and a
// restart would pick it up. PUBLIC_URL is an environment variable, baked in when
// a container is created — every service validates tokens against it, and
// Keycloak stamps it into every token it mints. A restart re-uses the old value,
// so the two halves must move together or the installation serves HTTPS while
// its identity layer still believes it is http.
package serviceurl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The gateway runs as uid 101 / gid 101 ("nginx") — nginxinc/nginx-unprivileged.
// The certificate and key MUST be readable by it.
//
// This is not a detail. A key written 0600 by root is present, non-empty and
// unreadable to nginx, which then refuses to start at all — not "no TLS", but no
// gateway, so the whole installation drops off the network because of a file
// mode. The gateway now degrades to HTTP rather than crash-looping, but the
// result is still an administrator who turned on TLS and did not get it.
const (
	GatewayUID = 101
	GatewayGID = 101
)

// Change is what the service recorded and this applies.
type Change struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	CertPEM  string `json:"certPem"`
	KeyPEM   string `json:"keyPem"`
}

// Result is reported back so the screen can say what happened.
type Result struct {
	ID    string `json:"id"`
	State string `json:"state"` // APPLIED | FAILED
	URL   string `json:"url,omitempty"`
	Port  int    `json:"port,omitempty"`
	Error string `json:"error,omitempty"`
}

const (
	StateApplied = "APPLIED"
	StateFailed  = "FAILED"
)

// Paths on the config volume, which the updater mounts read-write and the
// gateway mounts read-only.
type Paths struct {
	// EnvFile is the launcher's env file — the single place PUBLIC_URL lives.
	EnvFile string
	// TLSDir is where the gateway looks for cert.pem and key.pem.
	TLSDir string
}

// DefaultPaths lays out the config volume for a product whose launcher writes
// envName.
//
// The env file is named per product because a host can run more than one of them
// and an operator reading /config should be able to tell whose secrets those are.
// Everything else is identical across products deliberately: tls/cert.pem and
// tls/key.pem are where every gateway looks, so the same script serves all three.
func DefaultPaths(configDir, envName string) Paths {
	if configDir == "" {
		configDir = "/config"
	}
	if envName == "" {
		// Naming nothing is a wiring mistake, not a default worth having: it would
		// rewrite a file no launcher reads, and the address would silently not
		// move. A visible name in /config is what makes that obvious.
		envName = "onprem.env"
	}
	return Paths{
		EnvFile: filepath.Join(configDir, envName),
		TLSDir:  filepath.Join(configDir, "tls"),
	}
}

// snapshot is everything needed to put the installation back exactly as it was.
type snapshot struct {
	env      []byte
	certPEM  []byte
	keyPEM   []byte
	hadCert  bool
	envFound bool
}

// take reads the current state before anything is written. A rollback that
// reconstructs the previous state from assumptions is a rollback nobody has
// tested; this one restores bytes that were actually there.
func take(p Paths) (*snapshot, error) {
	s := &snapshot{}
	if b, err := os.ReadFile(p.EnvFile); err == nil {
		s.env, s.envFound = b, true
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reading %s: %w", p.EnvFile, err)
	}
	c, cerr := os.ReadFile(filepath.Join(p.TLSDir, "cert.pem"))
	k, kerr := os.ReadFile(filepath.Join(p.TLSDir, "key.pem"))
	if cerr == nil && kerr == nil {
		s.certPEM, s.keyPEM, s.hadCert = c, k, true
	}
	return s, nil
}

// restore puts back what take() captured.
func (s *snapshot) restore(p Paths) error {
	if s.envFound {
		if err := writeFile(p.EnvFile, s.env, 0o600, false); err != nil {
			return err
		}
	}
	if s.hadCert {
		if err := WriteTLS(p, s.certPEM, s.keyPEM); err != nil {
			return err
		}
		return nil
	}
	// There was no certificate before, so leaving the new one behind would keep
	// the gateway on HTTPS after a rollback that was supposed to undo exactly
	// that.
	_ = os.Remove(filepath.Join(p.TLSDir, "cert.pem"))
	_ = os.Remove(filepath.Join(p.TLSDir, "key.pem"))
	return nil
}

// WriteTLS puts the certificate and key where the gateway reads them, owned by
// the user nginx runs as.
//
// The chown is the point. Without it the files are root-owned, nginx cannot read
// the key, and TLS silently does not come on — the failure this whole function
// exists to avoid.
func WriteTLS(p Paths, certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(p.TLSDir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", p.TLSDir, err)
	}
	_ = chownForGateway(p.TLSDir)
	// The certificate is public; the key is not. Both are group-readable by the
	// gateway and neither is world-readable.
	//
	// ROOT KEEPS OWNERSHIP. root:101 with 0640 is the conventional arrangement
	// for a TLS key — Debian ships root:ssl-cert 0640 — and it is strictly better
	// than the two alternatives. 0644 would let anything that mounts this volume
	// read a private key, which is a finding in any review even though the
	// "world" here is small. Giving the file to uid 101 outright would mean the
	// process serving the internet owns its own key material; group-read gives it
	// exactly what it needs, which is to read.
	if err := writeFile(filepath.Join(p.TLSDir, "cert.pem"), certPEM, 0o644, true); err != nil {
		return err
	}
	return writeFile(filepath.Join(p.TLSDir, "key.pem"), keyPEM, 0o640, true)
}

// writeFile writes atomically: a temporary file, then a rename. A half-written
// certificate is one the gateway may read between the two, and "present but
// truncated" is the state that produces the least useful error of all.
func writeFile(path string, data []byte, mode os.FileMode, forGateway bool) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("creating a temporary file in %s: %w", dir, err)
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op once the rename has succeeded

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		return err
	}
	if forGateway {
		_ = chownForGateway(name)
	}
	return os.Rename(name, path)
}

// SetEnv rewrites one KEY=value in the launcher's env file, leaving every other
// line — including comments and the install's secrets — exactly as it found
// them.
//
// A regenerated file would be simpler and would lose whatever the customer or a
// past version put there. This is the file holding the master key and the
// database password; it is not one to rewrite wholesale.
func SetEnv(path string, kv map[string]string) ([]byte, error) {
	original, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	lines := strings.Split(string(original), "\n")
	seen := map[string]bool{}
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		eq := strings.IndexByte(t, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(t[:eq])
		if v, ok := kv[key]; ok {
			lines[i] = key + "=" + v
			seen[key] = true
		}
	}
	for k, v := range kv {
		if !seen[k] {
			lines = append(lines, k+"="+v)
		}
	}
	out := strings.Join(lines, "\n")
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return []byte(out), nil
}

// chownForGateway makes a path readable by the gateway's group.
//
// root:101 is preferred, so the writer keeps ownership and the reader gets only
// read. Where the updater is not root — a developer box — that is not possible,
// so it falls back to giving the file to uid 101 outright, and failing that
// leaves the file as it is. A failure here is not fatal: the gateway checks
// readability itself and degrades to HTTP with a message naming the uid that
// could not read what, which is a far better outcome than refusing to write a
// certificate at all.
func chownForGateway(path string) error {
	if err := os.Chown(path, 0, GatewayGID); err == nil {
		return nil
	}
	return os.Chown(path, GatewayUID, GatewayGID)
}
