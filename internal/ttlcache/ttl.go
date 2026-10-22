// Package ttlcache provides a generic, string-keyed, in-memory TTL cache that can
// be reused by any store needing short-lived caching of lookups.
package ttlcache

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// DefaultTTL is the lifetime of a cache entry when no TTL is configured.
const DefaultTTL = 5 * time.Second

// DefaultLoadTimeout bounds a single coalesced loader run when no timeout is
// configured. The loader runs on a context detached from any individual
// caller, so it needs its own deadline to avoid hanging indefinitely.
const DefaultLoadTimeout = 10 * time.Second

type entry[V any] struct {
	value     V
	expiresAt time.Time
}

// TTL is a string-keyed in-memory cache where each entry expires after a fixed
// duration. It is safe for concurrent use. Values are stored and returned as-is;
// callers that store mutable values (e.g. slices) are responsible for copying
// if they need isolation.
type TTL[V any] struct {
	ttl         time.Duration
	loadTimeout time.Duration
	now         func() time.Time

	mu      sync.Mutex
	entries map[string]entry[V]

	// group coalesces concurrent loads for the same cold key so the loader
	// runs at most once per key while callers are waiting.
	group singleflight.Group
}

// Option configures a TTL cache.
type Option[V any] func(*TTL[V])

// WithTTL overrides the entry lifetime.
func WithTTL[V any](ttl time.Duration) Option[V] {
	return func(c *TTL[V]) { c.ttl = ttl }
}

// WithLoadTimeout overrides the deadline applied to a single coalesced loader
// run. A non-positive value disables the timeout.
func WithLoadTimeout[V any](timeout time.Duration) Option[V] {
	return func(c *TTL[V]) { c.loadTimeout = timeout }
}

// setClock overrides the time source. It is exposed to tests via export_test.go.
func (c *TTL[V]) setClock(now func() time.Time) {
	c.now = now
}

// New builds a TTL cache.
func New[V any](opts ...Option[V]) *TTL[V] {
	c := &TTL[V]{
		ttl:         DefaultTTL,
		loadTimeout: DefaultLoadTimeout,
		now:         time.Now,
		entries:     make(map[string]entry[V]),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Get returns the cached value for key and true if present and unexpired.
// Expired entries are evicted on access so stale data cannot accumulate.
func (c *TTL[V]) Get(key string) (V, bool) {
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[key]; ok {
		if now.Before(e.expiresAt) {
			return e.value, true
		}
		delete(c.entries, key)
	}
	var zero V
	return zero, false
}

// Set stores value for key with the configured TTL.
func (c *TTL[V]) Set(key string, value V) {
	expiresAt := c.now().Add(c.ttl)

	c.mu.Lock()
	c.entries[key] = entry[V]{value: value, expiresAt: expiresAt}
	c.mu.Unlock()
}

// GetOrLoad returns the cached value for key, or calls loader to fetch it on a
// miss or expiry and caches the result. Loader errors are returned and not
// cached.
//
// Concurrent misses on the same key are coalesced into a single loader run. The
// loader executes on a context detached from any individual caller (see
// WithLoadTimeout), so one caller cancelling — e.g. a client disconnect — never
// cancels the shared load or poisons the callers coalesced onto it. Each caller
// still observes its own ctx: if ctx is cancelled while waiting, that caller
// returns its own ctx.Err() and the load continues for the others.
func (c *TTL[V]) GetOrLoad(ctx context.Context, key string, loader func(context.Context) (V, error)) (V, error) {
	if v, ok := c.Get(key); ok {
		return v, nil
	}

	ch := c.group.DoChan(key, func() (any, error) {
		// Re-check under the singleflight leader: a concurrent load may have
		// populated the cache while this caller was waiting to lead.
		if v, ok := c.Get(key); ok {
			return v, nil
		}
		// Detach from the caller's ctx so its cancellation can't fail the
		// shared load; bound the detached load with its own timeout.
		loadCtx := context.WithoutCancel(ctx)
		if c.loadTimeout > 0 {
			var cancel context.CancelFunc
			loadCtx, cancel = context.WithTimeout(loadCtx, c.loadTimeout)
			defer cancel()
		}
		v, err := loader(loadCtx)
		if err != nil {
			return nil, err
		}
		c.Set(key, v)
		return v, nil
	})

	select {
	case <-ctx.Done():
		var zero V
		return zero, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			var zero V
			return zero, res.Err
		}
		if res.Val == nil {
			// A successful load may legitimately yield nil for interface-typed
			// V; treat it as the zero value rather than an unexpected type.
			var zero V
			return zero, nil
		}
		v, ok := res.Val.(V)
		if !ok {
			var zero V
			return zero, fmt.Errorf("cache: loaded value for key %q has unexpected type %T", key, res.Val)
		}
		return v, nil
	}
}
