package serviceurl

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
)

// Recreator brings the stack back up with whatever is now in the env file, and
// reports whether it came up healthy. The updater's existing upgrade path
// already does both; this reuses it rather than growing a second way to
// recreate a stack, which would be the least-exercised code on the box doing
// one of the most consequential jobs.
type Recreator interface {
	Recreate(ctx context.Context) error
	Healthy(ctx context.Context) error
}

// Applier moves the installation to a new address.
type Applier struct {
	Paths    Paths
	Probe    Prober
	Stack    Recreator
	ProbeImg string // an image already on the box, so the probe pulls nothing
	Network  string
	CurrPort int
	Step     func(string) // progress, for the log and the screen
}

func (a *Applier) step(msg string) {
	if a.Step != nil {
		a.Step(msg)
	}
}

// Apply performs the move and returns what to report back.
//
// The order is deliberate. Everything that can fail WITHOUT consequence happens
// before anything that cannot be undone: choose the port, write the files, and
// only then recreate. If the stack does not come up healthy, the snapshot taken
// at the start goes back and it is recreated again — so a failed switch leaves
// the installation exactly where it was, rather than half-moved.
func (a *Applier) Apply(ctx context.Context, c Change) Result {
	res := Result{ID: c.ID}

	before, err := take(a.Paths)
	if err != nil {
		res.State, res.Error = StateFailed, "could not read the current configuration: "+err.Error()
		return res
	}

	port, why := ChoosePort(ctx, a.Probe, a.ProbeImg, a.Network, a.CurrPort)
	if why != "" {
		a.step(why)
	}
	res.Port = port
	res.URL = buildURL(c.Hostname, port)
	a.step("moving to " + res.URL)

	if err := WriteTLS(a.Paths, []byte(c.CertPEM), []byte(c.KeyPEM)); err != nil {
		res.State, res.Error = StateFailed, "could not write the certificate: "+err.Error()
		return res
	}

	env, err := SetEnv(a.Paths.EnvFile, map[string]string{
		"PUBLIC_URL":   res.URL,
		"GATEWAY_PORT": strconv.Itoa(port),
	})
	if err != nil {
		res.State, res.Error = StateFailed, "could not read the configuration file: "+err.Error()
		a.rollback(ctx, before, &res)
		return res
	}
	if err := writeFile(a.Paths.EnvFile, env, 0o600, false); err != nil {
		res.State, res.Error = StateFailed, "could not write the configuration file: "+err.Error()
		a.rollback(ctx, before, &res)
		return res
	}

	a.step("recreating the stack")
	if err := a.Stack.Recreate(ctx); err != nil {
		res.State, res.Error = StateFailed, "the stack did not come back: "+err.Error()
		a.rollback(ctx, before, &res)
		return res
	}

	// Health is judged from INSIDE the box. A browser that cannot reach the new
	// address may be looking at its own DNS or an untrusted internal CA, and
	// reverting a correct deployment because one laptop cannot resolve it would
	// leave the administrator retrying into the same wall.
	if err := a.Stack.Healthy(ctx); err != nil {
		res.State, res.Error = StateFailed, "the service did not come up healthy: "+err.Error()
		a.rollback(ctx, before, &res)
		return res
	}

	res.State = StateApplied
	a.step("now serving " + res.URL)
	return res
}

// rollback restores the previous files and brings the stack back on them.
//
// A rollback that itself fails is the worst outcome here, so it says so loudly
// in the reported error: at that point the installation needs a person, and the
// only honest thing is to name the file they have to put back.
func (a *Applier) rollback(ctx context.Context, before *snapshot, res *Result) {
	a.step("rolling back")
	if err := before.restore(a.Paths); err != nil {
		res.Error += fmt.Sprintf(
			" — AND THE ROLLBACK FAILED (%v). The previous configuration is in %s "+
				"and has to be restored by hand.", err, a.Paths.EnvFile)
		return
	}
	if err := a.Stack.Recreate(ctx); err != nil {
		res.Error += fmt.Sprintf(
			" — the previous configuration was restored but the stack did not come "+
				"back (%v). It needs to be started by hand.", err)
		return
	}
	a.step("rolled back to the previous address")
}

// buildURL is always https: the certificate is what this operation is for, and
// an http URL with a certificate installed would be a switch that did nothing.
// The port is omitted at 443, so the address reads the way people expect.
func buildURL(host string, port int) string {
	h := host
	if port != StandardHTTPS {
		h = host + ":" + strconv.Itoa(port)
	}
	u := url.URL{Scheme: "https", Host: h}
	return u.String()
}
