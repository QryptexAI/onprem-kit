package authflow

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// ErrNoAccount is ResetFromHost not finding the account it was named. Only the
// person at the host's terminal sees it, so unlike sign-in it says so.
var ErrNoAccount = errors.New("there is no account with that email or username")

// HostReset is what ResetFromHost did to an account.
type HostReset struct {
	Login      string // the username it signs in with
	Temp       string // the temporary password, for the terminal only
	RemovedMFA bool   // an authenticator app was registered and is now gone
}

// ResetFromHost is the on-prem launcher's `reset-admin`: the way back in for an
// administrator who is locked out, with nobody to reset them and no email to send
// a reset link to. Whoever can run it already controls the host, so it asks for
// nothing more.
//
// The account gets a temporary password with the usual forced change at the next
// sign-in, within TempPasswordTTL. It is returned for the terminal and never
// emailed. The authenticator app is removed too: a lost phone locks someone out as
// surely as a forgotten password, and the first-login change would otherwise still
// ask for its code. If the organisation requires one, the portal has them set it
// up again after signing in. Every session the account had is signed out.
//
// An account whose password lives in a directory or identity provider is refused,
// as an administrator's reset is: the password to change is not here.
func ResetFromHost(ctx context.Context, realm Realm, login string) (HostReset, error) {
	u, found, err := realm.FindUser(ctx, login)
	if err != nil {
		return HostReset{}, err
	}
	if !found {
		return HostReset{}, ErrNoAccount
	}
	if u.Federated {
		return HostReset{}, ErrFederated
	}
	out := HostReset{Login: u.Username}
	if out.RemovedMFA, err = realm.HasOTP(ctx, u.ID); err != nil {
		return HostReset{}, err
	}
	if out.RemovedMFA {
		if err := realm.RemoveOTP(ctx, u.ID); err != nil {
			return HostReset{}, err
		}
	}
	if out.Temp, err = TempPassword(); err != nil {
		return HostReset{}, err
	}
	if err := realm.SetPassword(ctx, u.ID, out.Temp, true); err != nil {
		return HostReset{}, err
	}
	if err := realm.SignOutEverywhere(ctx, u.ID); err != nil {
		return HostReset{}, fmt.Errorf("password reset, but signing the account out failed: %w", err)
	}
	return out, nil
}

// ResetAdminCommand runs `reset-admin <email or username>` for a product's service
// binary, which is where the launcher runs it (`docker compose exec`, or `kubectl
// exec` on Kubernetes): the service already holds the Keycloak admin connection.
// realmFor finds the realm the account is in. It returns the exit code.
//
// Every product prints the same thing, so the install guides can show it once.
func ResetAdminCommand(ctx context.Context, args []string, realmFor func(ctx context.Context, login string) (Realm, error), stdout, stderr io.Writer) int {
	if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
		fmt.Fprintln(stderr, "usage: reset-admin <email or username>")
		return 2
	}
	login := strings.TrimSpace(args[0])
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	realm, err := realmFor(ctx, login)
	if err == nil {
		var r HostReset
		if r, err = ResetFromHost(ctx, realm, login); err == nil {
			fmt.Fprintf(stdout, "Temporary password for %s:\n\n    %s\n\n", r.Login, r.Temp)
			fmt.Fprintf(stdout, "Sign in with it within %s. You will be asked to choose a new password.\n", hours(TempPasswordTTL))
			if r.RemovedMFA {
				fmt.Fprintln(stdout, "The account's authenticator app was removed; set it up again under Security.")
			}
			fmt.Fprintln(stdout, "Every session this account had is signed out.")
			return 0
		}
	}
	switch {
	case errors.Is(err, ErrNoAccount):
		fmt.Fprintf(stderr, "✗ %s: %v\n", login, err)
	case errors.Is(err, ErrFederated):
		fmt.Fprintf(stderr, "✗ %s signs in through a directory or identity provider; reset the password there.\n", login)
	default:
		fmt.Fprintf(stderr, "✗ could not reset %s: %v\n", login, err)
	}
	return 1
}
