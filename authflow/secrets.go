package authflow

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
)

// NewResetToken returns the token that goes in the emailed link and the hash that
// is stored. Only the hash is ever kept, so a copy of the store cannot be turned
// into working links.
func NewResetToken() (raw, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, HashResetToken(raw), nil
}

// HashResetToken is the stored form of a reset token.
func HashResetToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// ResetLink is the address emailed to the person. The token rides in the FRAGMENT:
// a browser never sends it to a server, so it stays out of access logs, proxies and
// the Referer of anything the page loads. The portal reads it and posts it back.
//
// portalURL must be the product's CONFIGURED public address. Built from the
// request's Host header instead, anyone could have a victim's reset link pointed at
// a server they control.
func ResetLink(portalURL, raw string) string {
	return strings.TrimRight(portalURL, "/") + "/#reset=" + raw
}

// TempPassword is what an administrator's reset issues. Twenty characters, with at
// least one of each class, so it satisfies any password policy the portal lets an
// administrator set. Characters that are easy to misread (0/O, 1/l/I) are left out
// because a person may type it from an email.
func TempPassword() (string, error) {
	const (
		upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
		lower   = "abcdefghijkmnpqrstuvwxyz"
		digit   = "23456789"
		special = "!@#$%*-_+=?"
	)
	sets := []string{upper, lower, digit, special}
	out := make([]byte, 0, 20)
	for _, s := range sets {
		c, err := pick(s)
		if err != nil {
			return "", err
		}
		out = append(out, c)
	}
	all := upper + lower + digit + special
	for len(out) < cap(out) {
		c, err := pick(all)
		if err != nil {
			return "", err
		}
		out = append(out, c)
	}
	// Shuffle so the guaranteed classes are not always the first four characters.
	for i := len(out) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		out[i], out[j.Int64()] = out[j.Int64()], out[i]
	}
	return string(out), nil
}

func pick(set string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, err
	}
	return set[n.Int64()], nil
}
