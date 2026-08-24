package serviceurl

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// StandardHTTPS is what the switch aims for. An address with no port in it is
// what people expect of a real service.
const StandardHTTPS = 443

// Prober asks Docker to do things. Satisfied by the updater's dockerapi client.
type Prober interface {
	Create(ctx context.Context, name string, spec ProbeSpec) (string, error)
	Start(ctx context.Context, id string) error
	Remove(ctx context.Context, id string) error
}

// ProbeSpec is the subset of a container specification this needs. Declared here
// rather than importing dockerapi so the package can be tested without one.
type ProbeSpec struct {
	Image       string
	Cmd         []string
	Network     string
	PublishPort int
	Labels      map[string]string
}

// ChoosePort returns the port the service should move to: 443 when it is free,
// otherwise the port it is already on.
//
// Nobody is asked. 443 is what people expect, the current port is a working
// answer, and there is nothing an administrator would learn from being
// interrupted mid-switch to choose between them.
//
// FREE IS TESTED BY BINDING, not by reading Docker's port list. What breaks a
// recreate is usually a process OUTSIDE Docker — another product's reverse
// proxy, an nginx somebody installed years ago — which appears in no Docker
// listing at all. Asking Docker to publish 443 on a throwaway container attempts
// exactly what the recreate will attempt, and finds out without having torn the
// stack down first.
func ChoosePort(ctx context.Context, p Prober, image, network string, current int) (port int, why string) {
	if current <= 0 {
		current = 8444
	}
	err := probe(ctx, p, image, network, StandardHTTPS)
	if err == nil {
		return StandardHTTPS, ""
	}
	// A probe that could not RUN is not evidence about the port. Only a failure
	// to START — where Docker has tried to bind and been refused — says the port
	// is taken. Reporting a missing image or an unreachable engine as "443 is not
	// available" pins the installation to its old port and puts a false reason in
	// the log, which is how a wrong answer survives review.
	var pe probeError
	if errors.As(err, &pe) && pe.stage == stageCreate {
		return current, fmt.Sprintf(
			"could not test whether port 443 is free (%s), so the service stays on %d",
			firstLine(pe.err.Error()), current)
	}
	return current, fmt.Sprintf(
		"port 443 is not available on this host (%s), so the service stays on %d",
		firstLine(err.Error()), current)
}

// probeError says which step failed, because the two mean different things.
type probeError struct {
	stage string
	err   error
}

const (
	stageCreate = "create" // the probe could not run: says nothing about the port
	stageStart  = "start"  // Docker tried to bind the port and was refused
)

func (e probeError) Error() string { return e.stage + ": " + e.err.Error() }
func (e probeError) Unwrap() error { return e.err }

// probe starts and immediately removes a container publishing the port.
func probe(ctx context.Context, p Prober, image, network string, port int) error {
	name := fmt.Sprintf("qscan-portprobe-%d", port)

	// A leftover from an interrupted probe would make every future probe fail
	// with "name already in use" and report a free port as taken — which would
	// quietly pin every installation to its old port forever.
	_ = p.Remove(ctx, name)

	id, err := p.Create(ctx, name, ProbeSpec{
		Image: image,
		// The image is one already on the box — the gateway's — so nothing is
		// pulled. It never serves anything: true exits immediately, and what is
		// being tested is whether Docker can BIND the port, which it decides
		// before the process runs.
		Cmd:         []string{"true"},
		Network:     network,
		PublishPort: port,
		Labels:      map[string]string{"qscan.role": "port-probe"},
	})
	if err != nil {
		return probeError{stage: stageCreate, err: err}
	}
	defer func() { _ = p.Remove(context.WithoutCancel(ctx), id) }()

	// Create succeeds even when the port is taken; the bind happens at START.
	if err := p.Start(ctx, id); err != nil {
		return probeError{stage: stageStart, err: err}
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
