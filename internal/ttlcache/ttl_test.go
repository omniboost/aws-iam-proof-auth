package ttlcache

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTTL_GetSet(t *testing.T) {
	now := time.Unix(0, 0)
	c := New[int](WithTTL[int](5 * time.Second))
	c.SetClock(func() time.Time { return now })

	if _, ok := c.Get("k"); ok {
		t.Fatal("expected miss on empty cache")
	}

	c.Set("k", 42)
	if v, ok := c.Get("k"); !ok || v != 42 {
		t.Fatalf("got (%d, %v), want (42, true)", v, ok)
	}
}

func TestTTL_Expiry(t *testing.T) {
	now := time.Unix(0, 0)
	c := New[int](WithTTL[int](5 * time.Second))
	c.SetClock(func() time.Time { return now })

	c.Set("k", 1)
	now = now.Add(6 * time.Second)
	if _, ok := c.Get("k"); ok {
		t.Error("expected entry to be expired")
	}
}

func TestTTL_GetOrLoad_CachesWithinTTL(t *testing.T) {
	var calls atomic.Int64
	now := time.Unix(0, 0)
	c := New[string](WithTTL[string](5 * time.Second))
	c.SetClock(func() time.Time { return now })
	loader := func(context.Context) (string, error) {
		calls.Add(1)
		return "value", nil
	}

	for i := 0; i < 3; i++ {
		v, err := c.GetOrLoad(context.Background(), "k", loader)
		if err != nil || v != "value" {
			t.Fatalf("got (%q, %v), want (value, nil)", v, err)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("loader called %d times, want 1", n)
	}
}

func TestTTL_GetOrLoad_RefetchesAfterTTL(t *testing.T) {
	var calls atomic.Int64
	now := time.Unix(0, 0)
	c := New[string](WithTTL[string](5 * time.Second))
	c.SetClock(func() time.Time { return now })
	loader := func(context.Context) (string, error) {
		calls.Add(1)
		return "value", nil
	}

	if _, err := c.GetOrLoad(context.Background(), "k", loader); err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Second)
	if _, err := c.GetOrLoad(context.Background(), "k", loader); err != nil {
		t.Fatal(err)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("loader called %d times, want 2", n)
	}
}

func TestTTL_GetOrLoad_DistinctKeys(t *testing.T) {
	var calls atomic.Int64
	c := New[string]()
	loader := func(context.Context) (string, error) {
		calls.Add(1)
		return "v", nil
	}

	_, _ = c.GetOrLoad(context.Background(), "a", loader)
	_, _ = c.GetOrLoad(context.Background(), "b", loader)
	if n := calls.Load(); n != 2 {
		t.Errorf("loader called %d times, want 2 (distinct keys)", n)
	}
}

func TestTTL_GetOrLoad_CoalescesConcurrentLoads(t *testing.T) {
	var calls atomic.Int64
	release := make(chan struct{})
	c := New[string]()
	loader := func(context.Context) (string, error) {
		calls.Add(1)
		<-release // hold the load open so callers pile up on the same key
		return "value", nil
	}

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if v, err := c.GetOrLoad(context.Background(), "k", loader); err != nil || v != "value" {
				t.Errorf("got (%q, %v), want (value, nil)", v, err)
			}
		}()
	}

	// Give the goroutines time to converge on the in-flight load, then release.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if n := calls.Load(); n != 1 {
		t.Errorf("loader called %d times, want 1 (coalesced)", n)
	}
}

func TestTTL_GetOrLoad_LeaderCancelDoesNotPoisonFollowers(t *testing.T) {
	// A cancelled leader must neither cancel the shared load nor propagate its
	// ctx error to followers coalesced onto the same key.
	entered := make(chan struct{})
	release := make(chan struct{})
	c := New[string]()
	loader := func(ctx context.Context) (string, error) {
		close(entered)
		<-release
		if err := ctx.Err(); err != nil {
			return "", err // the detached load ctx must not be cancelled
		}
		return "value", nil
	}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	var leaderErr error
	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		_, leaderErr = c.GetOrLoad(leaderCtx, "k", loader)
	}()

	<-entered // leader is now leading the in-flight load

	var followerVal string
	var followerErr error
	followerDone := make(chan struct{})
	go func() {
		defer close(followerDone)
		followerVal, followerErr = c.GetOrLoad(context.Background(), "k", loader)
	}()

	// Give the follower time to coalesce onto the leader's load, then cancel
	// the leader and let the load complete.
	time.Sleep(50 * time.Millisecond)
	cancelLeader()
	close(release)

	<-leaderDone
	<-followerDone

	if !errors.Is(leaderErr, context.Canceled) {
		t.Errorf("leader err = %v, want context.Canceled", leaderErr)
	}
	if followerErr != nil || followerVal != "value" {
		t.Errorf("follower got (%q, %v), want (value, nil)", followerVal, followerErr)
	}
}

func TestTTL_GetOrLoad_LoadTimeoutBoundsSharedLoad(t *testing.T) {
	// The loader runs on a context detached from callers but bounded by
	// WithLoadTimeout, so a loader that blocks past that timeout is cancelled by
	// it — and every coalesced caller observes the resulting deadline error,
	// even though none of them set a deadline of their own.
	const loadTimeout = 50 * time.Millisecond
	c := New[string](WithLoadTimeout[string](loadTimeout))

	entered := make(chan struct{})
	var once sync.Once
	loader := func(ctx context.Context) (string, error) {
		once.Do(func() { close(entered) })
		<-ctx.Done() // the load ctx's timeout is the only thing that unblocks us
		return "", ctx.Err()
	}

	const callers = 10
	errs := make([]error, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	// Start the leader and wait for it to enter the loader so the rest coalesce
	// onto its single in-flight load rather than starting their own.
	go func() {
		defer wg.Done()
		_, errs[0] = c.GetOrLoad(context.Background(), "k", loader)
	}()
	<-entered
	for i := 1; i < callers; i++ {
		go func() {
			defer wg.Done()
			_, errs[i] = c.GetOrLoad(context.Background(), "k", loader)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("caller %d err = %v, want context.DeadlineExceeded", i, err)
		}
	}
}

func TestTTL_GetOrLoad_DoesNotCacheErrors(t *testing.T) {
	var calls atomic.Int64
	c := New[string]()
	loader := func(context.Context) (string, error) {
		calls.Add(1)
		return "", errors.New("boom")
	}

	for i := 0; i < 2; i++ {
		if _, err := c.GetOrLoad(context.Background(), "k", loader); err == nil {
			t.Fatal("expected error")
		}
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("loader called %d times, want 2 (errors not cached)", n)
	}
}
