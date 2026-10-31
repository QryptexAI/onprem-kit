package authflow

import (
	"net"
	"net/http"
	"strings"
	"time"
)

// RightmostForwarded is the client address as the product's own front proxy saw
// it: the LAST X-Forwarded-For entry, which that proxy appended. Anything to its
// left came from the client and can be forged, so it is never read. Without the
// header, the connection's address.
func RightmostForwarded(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// LimitPerIP allows perMinute requests per client address — the per-IP half of
// the limits on the public routes (Handlers.Public). The per-address limit on
// reset emails is the Service's own. For a product without a limiter of its own;
// PKI passes the one signup-service already has.
func LimitPerIP(perMinute int, clientIP func(*http.Request) string) func(http.HandlerFunc) http.HandlerFunc {
	l := NewLimiter(perMinute, time.Minute)
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !l.Allow(clientIP(r), time.Now()) {
				w.Header().Set("Retry-After", "60")
				writeErr(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many attempts. Wait a minute and try again.")
				return
			}
			next(w, r)
		}
	}
}
