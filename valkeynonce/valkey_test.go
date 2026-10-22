package valkeynonce

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	iamproof "github.com/omniboost/aws-iam-proof-auth"
	"github.com/valkey-io/valkey-go"
)

func uniqueNonce(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())
}

// TestNew_Defaults verifies the constructor applies the documented
// defaults. It needs no server: a nil client is fine because no command runs.
func TestNew_Defaults(t *testing.T) {
	store := New(nil)

	if store.ttl != iamproof.DefaultNonceTTL {
		t.Errorf("ttl = %v, want %v", store.ttl, iamproof.DefaultNonceTTL)
	}
	if store.keyPrefix != DefaultKeyPrefix {
		t.Errorf("keyPrefix = %q, want %q", store.keyPrefix, DefaultKeyPrefix)
	}
}

// TestNew_Options verifies that options override the defaults.
func TestNew_Options(t *testing.T) {
	store := New(nil,
		WithTTL(90*time.Second),
		WithKeyPrefix("custom:"),
	)

	if store.ttl != 90*time.Second {
		t.Errorf("ttl = %v, want %v", store.ttl, 90*time.Second)
	}
	if store.keyPrefix != "custom:" {
		t.Errorf("keyPrefix = %q, want %q", store.keyPrefix, "custom:")
	}
}

// TestStore_Use_NilClient verifies Use fails with an error rather than
// panicking when the store was built without a client.
func TestStore_Use_NilClient(t *testing.T) {
	store := New(nil)
	fresh, err := store.Use(context.Background(), "n")
	if err == nil {
		t.Fatal("expected an error from Use with a nil client")
	}
	if fresh {
		t.Error("fresh should be false when Use errors")
	}
}

// TestStore_Use exercises the real SET NX EX semantics against a Valkey
// (or Redis) server. It is skipped unless VALKEY_TEST_URL points at one, e.g.
//
//	VALKEY_TEST_URL=redis://127.0.0.1:6379 go test ./valkeynonce/...
func TestStore_Use(t *testing.T) {
	url := os.Getenv("VALKEY_TEST_URL")
	if url == "" {
		t.Skip("set VALKEY_TEST_URL to run the Valkey nonce store test")
	}

	opt, err := valkey.ParseURL(url)
	if err != nil {
		t.Fatalf("parse VALKEY_TEST_URL: %v", err)
	}
	// Match the production client: servers behind a proxy reject the
	// CLIENT TRACKING probe that client-side caching needs.
	opt.DisableCache = true
	client, err := valkey.NewClient(opt)
	if err != nil {
		t.Fatalf("connect to valkey: %v", err)
	}
	defer client.Close()

	store := New(client, WithTTL(30*time.Second), WithKeyPrefix("nonce-test:"))
	ctx := context.Background()
	n := uniqueNonce(t)

	fresh, err := store.Use(ctx, n)
	if err != nil {
		t.Fatalf("first Use: %v", err)
	}
	if !fresh {
		t.Fatal("first Use should report the nonce as fresh")
	}

	reused, err := store.Use(ctx, n)
	if err != nil {
		t.Fatalf("second Use: %v", err)
	}
	if reused {
		t.Fatal("second Use should report the nonce as already used")
	}

	other, err := store.Use(ctx, uniqueNonce(t))
	if err != nil {
		t.Fatalf("Use of a distinct nonce: %v", err)
	}
	if !other {
		t.Fatal("a distinct nonce should report as fresh")
	}
}
