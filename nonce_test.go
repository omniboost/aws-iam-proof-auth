package iamproof

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestMemoryNonceStore_Use(t *testing.T) {
	store := NewMemoryNonceStore()
	ctx := context.Background()

	fresh, err := store.Use(ctx, "abc")
	if err != nil {
		t.Fatalf("first Use: %v", err)
	}
	if !fresh {
		t.Fatal("first Use should report the nonce as fresh")
	}

	reused, err := store.Use(ctx, "abc")
	if err != nil {
		t.Fatalf("second Use: %v", err)
	}
	if reused {
		t.Fatal("second Use should report the nonce as already used")
	}

	other, err := store.Use(ctx, "xyz")
	if err != nil {
		t.Fatalf("Use of a distinct nonce: %v", err)
	}
	if !other {
		t.Fatal("a distinct nonce should report as fresh")
	}
}

func TestMemoryNonceStore_Expires(t *testing.T) {
	now := time.Unix(0, 0)
	store := NewMemoryNonceStore(WithMemoryTTL(5 * time.Minute))
	store.SetClock(func() time.Time { return now })
	ctx := context.Background()

	if fresh, _ := store.Use(ctx, "a"); !fresh {
		t.Fatal("first Use should be fresh")
	}
	if fresh, _ := store.Use(ctx, "a"); fresh {
		t.Fatal("second Use within TTL should report reuse")
	}

	// After the TTL elapses the nonce expires, so it is fresh again. The
	// per-call expiry check guarantees this regardless of when pruning runs.
	now = now.Add(6 * time.Minute)
	if fresh, _ := store.Use(ctx, "a"); !fresh {
		t.Fatal("nonce should be fresh again after expiry")
	}
}

// TestMemoryNonceStore_PrunesOnSweep verifies that expired entries are
// eventually reclaimed by the periodic sweep so the map stays bounded, even
// though pruning does not happen on every call.
func TestMemoryNonceStore_PrunesOnSweep(t *testing.T) {
	now := time.Unix(0, 0)
	store := NewMemoryNonceStore(WithMemoryTTL(5 * time.Minute))
	store.SetClock(func() time.Time { return now })
	ctx := context.Background()

	// Insert an entry that will expire, then advance past its TTL.
	if fresh, _ := store.Use(ctx, "expired"); !fresh {
		t.Fatal("first Use should be fresh")
	}
	now = now.Add(6 * time.Minute)

	// Drive enough distinct Use calls to trigger at least one sweep. After the
	// sweep the long-expired entry must be gone, so the map size reflects only
	// the still-valid nonces inserted during this loop.
	for i := 0; i < pruneInterval; i++ {
		if _, err := store.Use(ctx, "valid-"+strconv.Itoa(i)); err != nil {
			t.Fatalf("Use: %v", err)
		}
	}

	if got := store.Len(); got != pruneInterval {
		t.Fatalf("store holds %d nonces, want %d (expired entry should be pruned by sweep)", got, pruneInterval)
	}
}

// TestMemoryNonceStore_ConcurrentSameNonce verifies that when many goroutines
// race to claim the same nonce, exactly one observes it as fresh.
func TestMemoryNonceStore_ConcurrentSameNonce(t *testing.T) {
	store := NewMemoryNonceStore()
	ctx := context.Background()

	const goroutines = 100
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		freshSeen int
	)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			fresh, err := store.Use(ctx, "race")
			if err != nil {
				t.Errorf("Use: %v", err)
				return
			}
			if fresh {
				mu.Lock()
				freshSeen++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if freshSeen != 1 {
		t.Fatalf("expected exactly 1 fresh claim, got %d", freshSeen)
	}
}
