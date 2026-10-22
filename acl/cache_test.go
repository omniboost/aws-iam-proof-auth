package acl

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// countingStore records how many times Permissions is called and returns a
// fixed result (or error).
type countingStore struct {
	calls atomic.Int64
	perms []string
	err   error
}

func (s *countingStore) Permissions(_ context.Context, _, _ string) ([]string, error) {
	s.calls.Add(1)
	if s.err != nil {
		return nil, s.err
	}
	return s.perms, nil
}

func TestCachedStore_CachesWithinTTL(t *testing.T) {
	inner := &countingStore{perms: []string{"mappings.read"}}
	cache := NewCachedStore(inner, WithCacheTTL(time.Minute))
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		got, err := cache.Permissions(ctx, "111", "Reader")
		if err != nil {
			t.Fatalf("Permissions: %v", err)
		}
		if len(got) != 1 || got[0] != "mappings.read" {
			t.Fatalf("got %v, want [mappings.read]", got)
		}
	}

	if n := inner.calls.Load(); n != 1 {
		t.Errorf("inner store called %d times, want 1 (cached)", n)
	}
}

func TestCachedStore_KeysOnAccountAndRole(t *testing.T) {
	inner := &countingStore{perms: []string{"mappings.read"}}
	cache := NewCachedStore(inner, WithCacheTTL(time.Minute))
	ctx := context.Background()

	_, _ = cache.Permissions(ctx, "111", "Reader")
	_, _ = cache.Permissions(ctx, "222", "Reader") // different account
	_, _ = cache.Permissions(ctx, "111", "Writer") // different role

	if n := inner.calls.Load(); n != 3 {
		t.Errorf("inner store called %d times, want 3 (distinct keys not cached together)", n)
	}
}

func TestCachedStore_DoesNotCacheErrors(t *testing.T) {
	inner := &countingStore{err: errors.New("boom")}
	cache := NewCachedStore(inner)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if _, err := cache.Permissions(ctx, "111", "Reader"); err == nil {
			t.Fatal("expected error from underlying store")
		}
	}

	if n := inner.calls.Load(); n != 2 {
		t.Errorf("inner store called %d times, want 2 (errors must not be cached)", n)
	}
}

// TestCachedStore_ReturnsCopy verifies callers cannot mutate cached entries.
func TestCachedStore_ReturnsCopy(t *testing.T) {
	inner := &countingStore{perms: []string{"mappings.read"}}
	cache := NewCachedStore(inner, WithCacheTTL(time.Minute))
	ctx := context.Background()

	first, _ := cache.Permissions(ctx, "111", "Reader")
	first[0] = "tampered"

	second, _ := cache.Permissions(ctx, "111", "Reader")
	if second[0] != "mappings.read" {
		t.Errorf("cached value was mutated through returned slice: %v", second)
	}
}
