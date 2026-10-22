package acl

import (
	"context"
	"time"

	"github.com/omniboost/aws-iam-proof-auth/internal/ttlcache"
)

// DefaultCacheTTL is the lifetime of a cached permission lookup. It is kept
// short so revoked or newly granted permissions take effect quickly while still
// absorbing bursts of requests from the same principal.
const DefaultCacheTTL = 5 * time.Second

// CachedStore wraps a Store with a short-lived in-memory cache keyed on
// account ID + role. It collapses repeated lookups for the same principal
// within the TTL window into a single underlying query. It is safe for
// concurrent use.
type CachedStore struct {
	inner Store
	cache *ttlcache.TTL[[]string]
}

// CacheOption configures a CachedStore.
type CacheOption func(*config)

type config struct {
	ttl time.Duration
}

// WithCacheTTL overrides the cache entry lifetime.
func WithCacheTTL(ttl time.Duration) CacheOption {
	return func(c *config) { c.ttl = ttl }
}

// NewCachedStore wraps inner with a TTL cache.
func NewCachedStore(inner Store, opts ...CacheOption) *CachedStore {
	cfg := &config{ttl: DefaultCacheTTL}
	for _, opt := range opts {
		opt(cfg)
	}
	return &CachedStore{
		inner: inner,
		cache: ttlcache.New(ttlcache.WithTTL[[]string](cfg.ttl)),
	}
}

// Permissions returns the cached permissions for accountID+role, querying the
// underlying store on a miss or when the cached entry has expired. Errors from
// the underlying store are returned and not cached. Returned slices are copies,
// so callers cannot mutate cached entries.
func (c *CachedStore) Permissions(ctx context.Context, accountID, role string) ([]string, error) {
	k := accountID + "-" + role

	perms, err := c.cache.GetOrLoad(ctx, k, func(ctx context.Context) ([]string, error) {
		fetched, err := c.inner.Permissions(ctx, accountID, role)
		if err != nil {
			return nil, err
		}
		return clonePermissions(fetched), nil
	})
	if err != nil {
		return nil, err
	}

	return clonePermissions(perms), nil
}

func clonePermissions(perms []string) []string {
	if len(perms) == 0 {
		return nil
	}
	out := make([]string, len(perms))
	copy(out, perms)
	return out
}
