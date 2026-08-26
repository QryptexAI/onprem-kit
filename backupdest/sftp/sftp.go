// Package sftp stores backups on an SFTP server.
//
// Wanted because plenty of on-prem customers have no object store at all, but
// every one of them has somewhere to put a file.
//
// THE HOST KEY IS MANDATORY, and this is the design decision worth defending.
// The usual shortcut is ssh.InsecureIgnoreHostKey(), which accepts whatever
// server answers. For backups that is the worst possible place to take it: a
// machine that answers on the right host and port receives an encrypted copy of
// the customer's entire deployment, and the operator sees a successful backup.
//
// Encryption limits the damage — the blob is useless without the key — but "we
// handed the archive to an attacker and told the operator it went fine" is not a
// tolerable outcome. So a host key must be configured, and a mismatch is a hard
// failure with the offending key printed so an operator can compare it.
package sftp

import (
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/QryptexAI/onprem-kit/backupdest"
)

// Store writes backups over SFTP. A connection is made per operation rather than
// held open: backups are occasional, and a long-lived idle SSH connection to a
// customer's file server is a liability that buys nothing here.
type Store struct {
	addr     string
	dir      string
	cfg      *ssh.ClientConfig
	describe string
}

// New builds a Store from settings. It fails if no host key is configured.
func New(s backupdest.Settings) (*Store, error) {
	if s.Host == "" {
		return nil, fmt.Errorf("sftp: no host configured")
	}
	if s.User == "" {
		return nil, fmt.Errorf("sftp: no user configured")
	}
	if strings.TrimSpace(s.HostKey) == "" {
		return nil, fmt.Errorf("sftp: no host key configured — refusing to send backups to an unauthenticated server")
	}
	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s.HostKey))
	if err != nil {
		return nil, fmt.Errorf("sftp: host key is not in authorized_keys form: %w", err)
	}

	var auth []ssh.AuthMethod
	if s.PrivateKeyPEM != "" {
		signer, err := ssh.ParsePrivateKey([]byte(s.PrivateKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("sftp: private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if s.Password != "" {
		auth = append(auth, ssh.Password(s.Password))
	}
	if len(auth) == 0 {
		return nil, fmt.Errorf("sftp: no private key or password configured")
	}

	port := s.Port
	if port == 0 {
		port = 22
	}
	dir := s.Path
	if dir == "" {
		dir = "."
	}
	return &Store{
		addr: net.JoinHostPort(s.Host, fmt.Sprint(port)),
		dir:  dir,
		cfg: &ssh.ClientConfig{
			User:            s.User,
			Auth:            auth,
			HostKeyCallback: ssh.FixedHostKey(hostKey),
			Timeout:         30 * time.Second,
		},
		// No credential here — Describe reaches logs and the UI.
		describe: fmt.Sprintf("sftp:%s@%s:%s", s.User, net.JoinHostPort(s.Host, fmt.Sprint(port)), dir),
	}, nil
}

func (s *Store) Describe() string { return s.describe }

func (s *Store) connect() (*ssh.Client, *sftp.Client, error) {
	conn, err := ssh.Dial("tcp", s.addr, s.cfg)
	if err != nil {
		// A host-key mismatch arrives here. Surfaced verbatim because the message
		// names the key that was offered, which is what an operator needs to tell
		// "the server was rebuilt" from "someone is in the middle".
		return nil, nil, fmt.Errorf("sftp: connect %s: %w", s.addr, err)
	}
	c, err := sftp.NewClient(conn)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("sftp: session: %w", err)
	}
	return conn, c, nil
}

func (s *Store) Put(_ context.Context, name string, data []byte) error {
	if err := safeName(name); err != nil {
		return err
	}
	conn, c, err := s.connect()
	if err != nil {
		return err
	}
	defer conn.Close()
	defer c.Close()

	if err := c.MkdirAll(s.dir); err != nil {
		return fmt.Errorf("sftp: mkdir %s: %w", s.dir, err)
	}
	// Written to a temporary name and renamed, so an interrupted transfer does not
	// leave a truncated file that lists as a backup and fails at restore.
	tmp := path.Join(s.dir, "."+name+".part")
	f, err := c.Create(tmp)
	if err != nil {
		return fmt.Errorf("sftp: create %s: %w", tmp, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = c.Remove(tmp)
		return fmt.Errorf("sftp: write %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		_ = c.Remove(tmp)
		return fmt.Errorf("sftp: close %s: %w", tmp, err)
	}
	final := path.Join(s.dir, name)
	_ = c.Remove(final) // rename onto an existing name fails on some servers
	if err := c.Rename(tmp, final); err != nil {
		return fmt.Errorf("sftp: rename to %s: %w", final, err)
	}
	return nil
}

func (s *Store) List(_ context.Context) ([]backupdest.Object, error) {
	conn, c, err := s.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	defer c.Close()

	entries, err := c.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // nothing stored yet
		}
		return nil, fmt.Errorf("sftp: list %s: %w", s.dir, err)
	}
	var out []backupdest.Object
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		out = append(out, backupdest.Object{
			Name: e.Name(), Modified: e.ModTime(), Size: e.Size(),
			Location: s.describe + "/" + e.Name(),
		})
	}
	return out, nil
}

func (s *Store) Delete(_ context.Context, name string) error {
	if err := safeName(name); err != nil {
		return err
	}
	conn, c, err := s.connect()
	if err != nil {
		return err
	}
	defer conn.Close()
	defer c.Close()
	if err := c.Remove(path.Join(s.dir, name)); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("sftp: delete %s: %w", name, err)
	}
	return nil
}

func safeName(name string) error {
	if name == "" {
		return fmt.Errorf("sftp: empty object name")
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return fmt.Errorf("sftp: unsafe object name %q", name)
	}
	return nil
}
