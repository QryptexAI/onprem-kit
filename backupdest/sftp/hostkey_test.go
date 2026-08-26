package sftp

import (
	"strings"
	"testing"

	"github.com/QryptexAI/onprem-kit/backupdest"
)

// The host key must be MANDATORY. The usual shortcut is
// ssh.InsecureIgnoreHostKey(), which hands an encrypted copy of the whole
// deployment to whatever machine answers on that host and port, and reports a
// successful backup.
func TestHostKeyIsMandatory(t *testing.T) {
	_, err := New(backupdest.Settings{Host: "h", User: "u", Password: "p"})
	if err == nil {
		t.Fatal("built an SFTP destination with no host key")
	}
	if !strings.Contains(err.Error(), "host key") {
		t.Errorf("error does not name the host key: %v", err)
	}
	// A malformed one must be refused too, not silently ignored.
	if _, err := New(backupdest.Settings{Host: "h", User: "u", Password: "p", HostKey: "not-a-key"}); err == nil {
		t.Fatal("accepted a malformed host key")
	}
}

// And credentials are required — an SFTP destination with neither key nor
// password would fail at the first backup, hours after it was configured.
func TestCredentialRequired(t *testing.T) {
	hk := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	if _, err := New(backupdest.Settings{Host: "h", User: "u", HostKey: hk}); err == nil {
		t.Fatal("accepted an SFTP destination with no credential")
	}
	if _, err := New(backupdest.Settings{Host: "h", User: "u", HostKey: hk, Password: "p"}); err != nil {
		t.Fatalf("rejected a valid configuration: %v", err)
	}
}

// Describe reaches logs and the UI; it must never carry the credential.
func TestDescribeCarriesNoSecret(t *testing.T) {
	hk := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	s, err := New(backupdest.Settings{Host: "h", User: "u", HostKey: hk, Password: "hunter2", Path: "/backups"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s.Describe(), "hunter2") {
		t.Errorf("Describe leaked the password: %q", s.Describe())
	}
}
