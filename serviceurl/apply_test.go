package serviceurl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeProber answers the port probe. freePorts lists ports Docker would accept.
type fakeProber struct {
	freePorts map[int]bool
	created   []int
	removed   int
}

func (f *fakeProber) Create(_ context.Context, _ string, s ProbeSpec) (string, error) {
	f.created = append(f.created, s.PublishPort)
	return "probe-id", nil
}

func (f *fakeProber) Start(_ context.Context, _ string) error {
	if len(f.created) == 0 {
		return errors.New("start without create")
	}
	port := f.created[len(f.created)-1]
	if f.freePorts[port] {
		return nil
	}
	return errors.New("driver failed programming external connectivity: address already in use")
}

func (f *fakeProber) Remove(context.Context, string) error { f.removed++; return nil }

// fakeStack stands in for the recreate-and-check path.
type fakeStack struct {
	recreates     int
	recreateErr   error
	healthErr     error
	healthCalls   int
	envAtRecreate []string // what PUBLIC_URL said each time it was recreated
	envFile       string
}

func (s *fakeStack) Recreate(context.Context) error {
	s.recreates++
	if b, err := os.ReadFile(s.envFile); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "PUBLIC_URL=") {
				s.envAtRecreate = append(s.envAtRecreate, strings.TrimPrefix(l, "PUBLIC_URL="))
			}
		}
	}
	return s.recreateErr
}

func (s *fakeStack) Healthy(context.Context) error { s.healthCalls++; return s.healthErr }

func setup(t *testing.T) (Paths, *fakeProber, *fakeStack) {
	t.Helper()
	dir := t.TempDir()
	p := DefaultPaths(dir, "test.env")
	// A realistic env file: comments and the install's secrets, which must
	// survive untouched.
	if err := os.WriteFile(p.EnvFile, []byte(
		"# QryptoScan install configuration\n"+
			"POSTGRES_PASSWORD=super-secret\n"+
			"MASTER_KEY=another-secret\n"+
			"PUBLIC_URL=http://localhost:8444\n"+
			"GATEWAY_PORT=8444\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p, &fakeProber{freePorts: map[int]bool{}}, &fakeStack{envFile: p.EnvFile}
}

func applier(p Paths, pr *fakeProber, st *fakeStack) *Applier {
	return &Applier{
		Paths: p, Probe: pr, Stack: st,
		ProbeImg: "gateway:latest", Network: "onprem", CurrPort: 8444,
	}
}

const (
	testCert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	testKey  = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"
)

func change() Change {
	return Change{ID: "c1", Hostname: "pki.acme.com", CertPEM: testCert, KeyPEM: testKey}
}

func TestApply_MovesTo443WhenFree(t *testing.T) {
	p, pr, st := setup(t)
	pr.freePorts[443] = true

	res := applier(p, pr, st).Apply(context.Background(), change())
	if res.State != StateApplied {
		t.Fatalf("state = %s, error = %s", res.State, res.Error)
	}
	if res.URL != "https://pki.acme.com" {
		t.Errorf("URL = %q — 443 should carry no port", res.URL)
	}
	if res.Port != 443 {
		t.Errorf("port = %d", res.Port)
	}
	env, _ := os.ReadFile(p.EnvFile)
	if !strings.Contains(string(env), "PUBLIC_URL=https://pki.acme.com") {
		t.Errorf("env not updated:\n%s", env)
	}
}

// The rule: 443 if free, otherwise the port it is already on. Nobody is asked.
func TestApply_FallsBackToCurrentPort(t *testing.T) {
	p, pr, st := setup(t) // 443 not in freePorts
	pr.freePorts[8444] = true

	var steps []string
	a := applier(p, pr, st)
	a.Step = func(s string) { steps = append(steps, s) }

	res := a.Apply(context.Background(), change())
	if res.State != StateApplied {
		t.Fatalf("state = %s, error = %s", res.State, res.Error)
	}
	if res.URL != "https://pki.acme.com:8444" {
		t.Errorf("URL = %q — should keep the current port", res.URL)
	}
	// And it must SAY so, rather than silently choosing.
	joined := strings.Join(steps, "\n")
	if !strings.Contains(joined, "443 is not available") {
		t.Errorf("the fallback was not explained:\n%s", joined)
	}
}

// The env file holds the master key and the database password. Rewriting it
// wholesale would be simpler and would destroy the installation.
func TestApply_PreservesEverythingElseInTheEnvFile(t *testing.T) {
	p, pr, st := setup(t)
	pr.freePorts[443] = true

	if res := applier(p, pr, st).Apply(context.Background(), change()); res.State != StateApplied {
		t.Fatal(res.Error)
	}
	env, _ := os.ReadFile(p.EnvFile)
	for _, must := range []string{
		"# QryptoScan install configuration",
		"POSTGRES_PASSWORD=super-secret",
		"MASTER_KEY=another-secret",
	} {
		if !strings.Contains(string(env), must) {
			t.Errorf("lost %q from the env file:\n%s", must, env)
		}
	}
}

// A failed switch must leave the installation exactly where it started.
func TestApply_RollsBackWhenUnhealthy(t *testing.T) {
	p, pr, st := setup(t)
	pr.freePorts[443] = true
	st.healthErr = errors.New("readiness returned HTTP 502")

	res := applier(p, pr, st).Apply(context.Background(), change())
	if res.State != StateFailed {
		t.Fatalf("an unhealthy stack must fail the switch, got %s", res.State)
	}
	env, _ := os.ReadFile(p.EnvFile)
	if !strings.Contains(string(env), "PUBLIC_URL=http://localhost:8444") {
		t.Errorf("the previous URL was not restored:\n%s", env)
	}
	// Restored AND brought back up on the old configuration — putting the file
	// back without recreating would leave the stack running the new one.
	if st.recreates != 2 {
		t.Errorf("recreates = %d, want 2 (the attempt and the rollback)", st.recreates)
	}
	if len(st.envAtRecreate) == 2 && st.envAtRecreate[1] != "http://localhost:8444" {
		t.Errorf("the rollback recreate saw %q, not the restored URL", st.envAtRecreate[1])
	}
}

// There was no certificate before, so a rollback must remove the one just
// written — otherwise the gateway comes back on HTTPS after a rollback whose
// whole purpose was to undo that.
func TestApply_RollbackRemovesACertificateThatWasNotThereBefore(t *testing.T) {
	p, pr, st := setup(t)
	pr.freePorts[443] = true
	st.healthErr = errors.New("nope")

	applier(p, pr, st).Apply(context.Background(), change())

	if _, err := os.Stat(filepath.Join(p.TLSDir, "cert.pem")); !os.IsNotExist(err) {
		t.Error("the certificate survived a rollback; the gateway would come back on HTTPS")
	}
	if _, err := os.Stat(filepath.Join(p.TLSDir, "key.pem")); !os.IsNotExist(err) {
		t.Error("the key survived a rollback")
	}
}

// A previous certificate must come back, not be deleted.
func TestApply_RollbackRestoresAPreviousCertificate(t *testing.T) {
	p, pr, st := setup(t)
	pr.freePorts[443] = true
	st.healthErr = errors.New("nope")

	if err := WriteTLS(p, []byte("OLD-CERT"), []byte("OLD-KEY")); err != nil {
		t.Fatal(err)
	}
	applier(p, pr, st).Apply(context.Background(), change())

	got, err := os.ReadFile(filepath.Join(p.TLSDir, "cert.pem"))
	if err != nil {
		t.Fatalf("the previous certificate was not restored: %v", err)
	}
	if string(got) != "OLD-CERT" {
		t.Errorf("certificate = %q, want the previous one", got)
	}
}

func TestApply_RollsBackWhenTheStackDoesNotComeBack(t *testing.T) {
	p, pr, st := setup(t)
	pr.freePorts[443] = true
	st.recreateErr = errors.New("compose exited 1")

	res := applier(p, pr, st).Apply(context.Background(), change())
	if res.State != StateFailed {
		t.Fatalf("state = %s", res.State)
	}
	env, _ := os.ReadFile(p.EnvFile)
	if !strings.Contains(string(env), "PUBLIC_URL=http://localhost:8444") {
		t.Error("the previous URL was not restored")
	}
}

// The worst case: the change could not be written AND the rollback could not put
// the old one back. The message has to name the file a person must restore,
// because nothing else will.
//
// Arranged with the TLS directory writable and the env file's directory not, so
// the certificate write succeeds and the env write — and then its restore —
// both fail. Making everything read-only instead fails at the first step, where
// nothing has changed yet and no rollback is required.
func TestApply_SaysSoWhenTheRollbackAlsoFails(t *testing.T) {
	root := t.TempDir()
	envDir := filepath.Join(root, "env")
	tlsDir := filepath.Join(root, "tls")
	if err := os.MkdirAll(envDir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := Paths{EnvFile: filepath.Join(envDir, "qryptoscan.env"), TLSDir: tlsDir}
	if err := os.WriteFile(p.EnvFile, []byte("PUBLIC_URL=http://localhost:8444\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(envDir, 0o500); err != nil {
		t.Skip("cannot make a directory read-only here")
	}
	t.Cleanup(func() { _ = os.Chmod(envDir, 0o700) })

	pr := &fakeProber{freePorts: map[int]bool{443: true}}
	st := &fakeStack{envFile: p.EnvFile}
	res := applier(p, pr, st).Apply(context.Background(), change())

	if res.State != StateFailed {
		t.Fatalf("state = %s", res.State)
	}
	if !strings.Contains(res.Error, p.EnvFile) {
		t.Errorf("the error must name the file to restore by hand, got: %s", res.Error)
	}
	if !strings.Contains(res.Error, "ROLLBACK FAILED") {
		t.Errorf("a failed rollback must be stated plainly, got: %s", res.Error)
	}
}

// A leftover probe container from an interrupted run would make every future
// probe fail with "name already in use" — reporting a free port as taken and
// pinning the installation to its old port forever.
func TestChoosePort_ClearsALeftoverProbe(t *testing.T) {
	pr := &fakeProber{freePorts: map[int]bool{443: true}}
	port, why := ChoosePort(context.Background(), pr, "img", "net", 8444)
	if port != 443 || why != "" {
		t.Fatalf("port = %d, why = %q", port, why)
	}
	// Removed twice: once before creating, once after.
	if pr.removed < 2 {
		t.Errorf("Remove called %d times; the pre-clean is missing", pr.removed)
	}
}

func TestSetEnv_AddsAKeyThatWasNotThere(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "env")
	if err := os.WriteFile(f, []byte("EXISTING=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := SetEnv(f, map[string]string{"PUBLIC_URL": "https://x"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "EXISTING=1") || !strings.Contains(s, "PUBLIC_URL=https://x") {
		t.Errorf("got:\n%s", s)
	}
}

// A commented-out line is not a setting. Rewriting it would leave the real one
// below still in force and the file looking as though it had been changed.
func TestSetEnv_IgnoresComments(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "env")
	if err := os.WriteFile(f, []byte("#PUBLIC_URL=http://old\nPUBLIC_URL=http://real\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _ := SetEnv(f, map[string]string{"PUBLIC_URL": "https://new"})
	s := string(out)
	if !strings.Contains(s, "#PUBLIC_URL=http://old") {
		t.Error("the comment was rewritten")
	}
	if strings.Count(s, "PUBLIC_URL=https://new") != 1 {
		t.Errorf("expected exactly one live setting:\n%s", s)
	}
}

// A probe that could not RUN says nothing about the port. Reporting a missing
// image or an unreachable engine as "443 is not available" pins the install to
// its old port and writes a false reason into the log — which is exactly what
// happened the first time this ran against a real Docker engine.
type brokenProber struct{ fakeProber }

func (b *brokenProber) Create(context.Context, string, ProbeSpec) (string, error) {
	return "", errors.New(`HTTP 404: {"message":"No such image: gateway:latest"}`)
}

func TestChoosePort_DistinguishesACannotTestFromATakenPort(t *testing.T) {
	_, why := ChoosePort(context.Background(), &brokenProber{}, "gateway:latest", "net", 8444)
	if strings.Contains(why, "not available on this host") {
		t.Errorf("a probe that could not run was reported as a busy port: %s", why)
	}
	if !strings.Contains(why, "could not test") || !strings.Contains(why, "No such image") {
		t.Errorf("the real reason should be named, got: %s", why)
	}
}

// And a genuine bind refusal must still read as a taken port.
func TestChoosePort_ReportsARealConflictAsSuch(t *testing.T) {
	pr := &fakeProber{freePorts: map[int]bool{}} // Start refuses 443
	_, why := ChoosePort(context.Background(), pr, "gateway:latest", "net", 8444)
	if !strings.Contains(why, "not available on this host") {
		t.Errorf("a refused bind should read as a busy port, got: %s", why)
	}
}
