package authflow

import (
	"fmt"
	"strings"
	"time"
)

// The wording of every email the flows send. One place, so a person gets the same
// message from all three products and a change to the wording happens once.
//
// None of them contains a password except the administrator's temporary one, which
// is the point of that email. None of them says something will not happen when it
// already has: PKI's old reset email promised "nothing changes until the temporary
// password is used", sent after the password had already been replaced.

func when(t time.Time) string { return t.UTC().Format("Mon 2 Jan 2006 at 15:04 UTC") }

func resetLinkEmail(product, link string, ttl time.Duration) (string, string) {
	return "Reset your " + product + " password", fmt.Sprintf(`We received a request to reset the password for your %s account.

Choose a new password here. The link works once and expires in %s:
  %s

If you didn't ask for this, ignore this email. Your password has not changed.
`, product, minutes(ttl), link)
}

func federatedResetEmail(product, provider string) (string, string) {
	return "Your " + product + " password", fmt.Sprintf(`Someone asked to reset the password for your %s account.

Your account signs in through %s, so its password is managed there, not in %s.
Reset it with %s, or ask your administrator.

If you didn't ask for this, ignore this email.
`, product, provider, product, provider)
}

func passwordChangedEmail(product string, at time.Time, ip, portalURL string) (string, string) {
	from := ""
	if ip != "" {
		from = " from " + ip
	}
	return "Your " + product + " password was changed", fmt.Sprintf(`The password for your %s account was changed on %s%s.

If this was you, there is nothing to do.

If it wasn't, reset your password now (Sign in, then "Forgot password?") and tell
your administrator:
  %s
`, product, when(at), from, portalURL)
}

func tempPasswordEmail(product, login, temp, portalURL string, ttl time.Duration, newAccount bool) (string, string) {
	subject, what := "Your "+product+" password was reset", "reset the password for your account"
	if newAccount {
		subject, what = "Your "+product+" account", "created an account for you"
	}
	return subject, fmt.Sprintf(`An administrator %s in %s.

Sign in at %s with:
  Username:           %s
  Temporary password: %s

You'll choose your own password when you sign in. The temporary password expires
in %s; after that, ask your administrator for a new one.
`, what, product, portalURL, login, temp, hours(ttl))
}

func mfaAddedEmail(product string, at time.Time, portalURL string) (string, string) {
	return "Authenticator app added to your " + product + " account", fmt.Sprintf(`An authenticator app was added to your %s account on %s.
From now on, signing in asks for a code from it.

If this wasn't you, reset your password now and tell your administrator:
  %s
`, product, when(at), portalURL)
}

func mfaRemovedEmail(product string, at time.Time, portalURL string, byAdmin bool) (string, string) {
	who := "The authenticator app was removed from your"
	next := "Signing in no longer asks for a code."
	if byAdmin {
		who = "An administrator removed the authenticator app from your"
		next = "If your organisation requires one, you'll be asked to set up a new one when you next sign in."
	}
	return "Authenticator app removed from your " + product + " account", fmt.Sprintf(`%s %s account on %s.
%s

If you didn't expect this, tell your administrator:
  %s
`, who, product, when(at), next, portalURL)
}

func minutes(d time.Duration) string { return plural(int(d.Minutes()), "minute") }
func hours(d time.Duration) string   { return plural(int(d.Hours()), "hour") }

func plural(n int, unit string) string {
	s := fmt.Sprintf("%d %s", n, unit)
	if n != 1 {
		s += "s"
	}
	return strings.TrimSpace(s)
}
