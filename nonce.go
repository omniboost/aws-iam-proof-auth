package iamproof

import (
	"context"
	"sync"
	"time"
)

// NonceStore tracks nonces to prevent presigned URL replay.
type NonceStore interface {
	// Use records the nonce and reports whether it was previously unused.
	Use(ctx context.Context, nonce string) (bool, error)
}

// DefaultNonceTTL is how long a nonce store must remember a nonce. It exceeds
// the longest presigned URL validity the verifier accepts (2 minutes) plus a
// margin for clock skew and processing, so a nonce can never be forgotten while
// STS would still honour its URL.
const DefaultNonceTTL = 5 * time.Minute

// pruneInterval is how many Use calls pass between full sweeps of expired
// entries. The per-call expiry check below keeps correctness independent of
// pruning; the sweep only reclaims memory for nonces that are never seen again.
const pruneInterval = 256

// MemoryNonceStore is an in-memory NonceStore. It is safe for concurrent use
// but does not persist across restarts, so it suits a single long-running
// process rather than a distributed deployment. Entries expire after a TTL and
// expired entries are pruned periodically so the map cannot grow without bound.
type MemoryNonceStore struct {
	ttl time.Duration
	now func() time.Time

	mu       sync.Mutex
	seen     map[string]time.Time
	useCount uint64
}

// MemoryOption configures a MemoryNonceStore.
type MemoryOption func(*MemoryNonceStore)

// WithMemoryTTL overrides the nonce lifetime.
func WithMemoryTTL(ttl time.Duration) MemoryOption {
	return func(s *MemoryNonceStore) { s.ttl = ttl }
}

// NewMemoryNonceStore returns an empty in-memory nonce store.
func NewMemoryNonceStore(opts ...MemoryOption) *MemoryNonceStore {
	s := &MemoryNonceStore{
		ttl:  DefaultNonceTTL,
		now:  time.Now,
		seen: make(map[string]time.Time),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Use records the nonce and reports whether it was previously unused. The
// common lookup/insert path is O(1); a full sweep of expired entries runs only
// periodically so the store stays bounded without scanning on every call.
func (s *MemoryNonceStore) Use(_ context.Context, nonce string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()

	s.useCount++
	if s.useCount%pruneInterval == 0 {
		for key, expiresAt := range s.seen {
			if !now.Before(expiresAt) {
				delete(s.seen, key)
			}
		}
	}

	if expiresAt, ok := s.seen[nonce]; ok && now.Before(expiresAt) {
		return false, nil
	}
	s.seen[nonce] = now.Add(s.ttl)
	return true, nil
}
