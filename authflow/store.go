package authflow

import (
	"context"
	"sync"
	"time"
)

// ResetToken is one outstanding reset link. Hash is HashResetToken of the link's
// token; the token itself is never stored.
type ResetToken struct {
	Hash    string
	Realm   string
	UserID  string
	Email   string
	Expires time.Time
}

// TokenStore holds outstanding reset links. Each product keeps its own — PKI in
// memory beside its other sign-up state, CAMP and QryptoScan in Postgres so every
// replica sees the same links.
type TokenStore interface {
	// Save stores t and drops any earlier token for the same realm and user, so
	// asking for a new link cancels the old one.
	Save(ctx context.Context, t ResetToken) error
	// Take removes the token with this hash and returns it. A link works once: a
	// second Take of the same hash finds nothing.
	Take(ctx context.Context, hash string) (ResetToken, bool, error)
}

// MemTokens is an in-memory TokenStore. A restart forgets every outstanding link,
// which costs the person one more "Forgot password?" and nothing else — acceptable
// for a single-replica service, and wrong for anything with more than one.
type MemTokens struct {
	mu     sync.Mutex
	byHash map[string]ResetToken
}

func NewMemTokens() *MemTokens { return &MemTokens{byHash: map[string]ResetToken{}} }

func (m *MemTokens) Save(_ context.Context, t ResetToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for h, old := range m.byHash {
		if (old.Realm == t.Realm && old.UserID == t.UserID) || now.After(old.Expires) {
			delete(m.byHash, h)
		}
	}
	m.byHash[t.Hash] = t
	return nil
}

func (m *MemTokens) Take(_ context.Context, hash string) (ResetToken, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.byHash[hash]
	delete(m.byHash, hash)
	return t, ok, nil
}

// Limiter allows n events per key within window — the cap on reset emails to one
// address, so the form cannot be used to flood someone's inbox. Per-IP limits are
// the product's own middleware; this is the per-address half.
type Limiter struct {
	n      int
	window time.Duration
	mu     sync.Mutex
	hits   map[string][]time.Time
}

func NewLimiter(n int, window time.Duration) *Limiter {
	return &Limiter{n: n, window: window, hits: map[string][]time.Time{}}
}

func (l *Limiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if now.Sub(t) < l.window {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.n {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}
