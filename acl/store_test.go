package acl

import (
	"context"
	"testing"
)

func TestMemoryStore_Permissions(t *testing.T) {
	store := NewMemoryStore(
		Grant{AccountID: "111", Role: "Reader", Permissions: []string{"mappings.read"}},
		Grant{AccountID: "111", Role: "Writer", Permissions: []string{"mappings.read", "mappings.write"}},
	)
	ctx := context.Background()

	got, err := store.Permissions(ctx, "111", "Writer")
	if err != nil {
		t.Fatalf("Permissions: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d permissions, want 2: %v", len(got), got)
	}

	// Unknown account+role yields an empty set, not an error.
	none, err := store.Permissions(ctx, "999", "Writer")
	if err != nil {
		t.Fatalf("Permissions: %v", err)
	}
	if len(none) != 0 {
		t.Errorf("expected no permissions, got %v", none)
	}
}

// TestMemoryStore_AccountAndRoleKeyed verifies the same role name in a
// different account does not inherit grants.
func TestMemoryStore_AccountAndRoleKeyed(t *testing.T) {
	store := NewMemoryStore(
		Grant{AccountID: "111", Role: "Admin", Permissions: []string{"mappings.write"}},
	)
	ctx := context.Background()

	ok, err := Has(ctx, store, "111", "Admin", "mappings.write")
	if err != nil {
		t.Fatalf("Has: %v", err)
	}
	if !ok {
		t.Error("account 111 Admin should have mappings.write")
	}

	other, err := Has(ctx, store, "222", "Admin", "mappings.write")
	if err != nil {
		t.Fatalf("Has: %v", err)
	}
	if other {
		t.Error("account 222 Admin must not inherit account 111's grants")
	}
}

func TestHas_ExactMatch(t *testing.T) {
	store := NewMemoryStore(
		Grant{AccountID: "111", Role: "R", Permissions: []string{"software-combination.read"}},
	)
	ctx := context.Background()

	ok, err := Has(ctx, store, "111", "R", "software-combination.read")
	if err != nil {
		t.Fatalf("Has: %v", err)
	}
	if !ok {
		t.Error("expected exact permission to match")
	}

	// A different permission string must not match (no wildcards/prefixes).
	for _, p := range []string{"software-combination.write", "software-combination", "software-combination.*"} {
		got, err := Has(ctx, store, "111", "R", p)
		if err != nil {
			t.Fatalf("Has(%q): %v", p, err)
		}
		if got {
			t.Errorf("permission %q must not match the granted read permission", p)
		}
	}
}

// TestMemoryStore_MergesGrants verifies grants for the same account+role merge.
func TestMemoryStore_MergesGrants(t *testing.T) {
	store := NewMemoryStore(
		Grant{AccountID: "111", Role: "R", Permissions: []string{"a.read"}},
		Grant{AccountID: "111", Role: "R", Permissions: []string{"a.write"}},
	)

	got, err := store.Permissions(context.Background(), "111", "R")
	if err != nil {
		t.Fatalf("Permissions: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected merged grants of 2 permissions, got %v", got)
	}
}
