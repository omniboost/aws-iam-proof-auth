// Package acl provides authorization grants keyed by account ID and role name.
package acl

import "context"

// Store resolves the permissions granted to an account+role pair.
type Store interface {
	// Permissions returns the permission strings granted to the given account
	// and role. An account+role with no grants returns an empty slice and a
	// nil error, never an error.
	Permissions(ctx context.Context, accountID, role string) ([]string, error)
}

// Grant assigns a set of permissions to a single account+role pair. Its JSON
// form is the one ParseGrants reads and the Mongo store keeps.
type Grant struct {
	AccountID   string   `json:"account_id"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

type key struct {
	accountID string
	role      string
}

// MemoryStore is an in-memory Store backed by a map built from a fixed set of
// grants. It is safe for concurrent reads.
type MemoryStore struct {
	grants map[key][]string
}

// NewMemoryStore builds a MemoryStore from the given grants. Grants that share
// the same account+role are merged.
func NewMemoryStore(grants ...Grant) *MemoryStore {
	m := &MemoryStore{grants: make(map[key][]string, len(grants))}
	for _, g := range grants {
		k := key{accountID: g.AccountID, role: g.Role}
		m.grants[k] = append(m.grants[k], g.Permissions...)
	}
	return m
}

// Permissions returns a copy of the permissions granted to accountID+role.
func (m *MemoryStore) Permissions(_ context.Context, accountID, role string) ([]string, error) {
	perms := m.grants[key{accountID: accountID, role: role}]
	if len(perms) == 0 {
		return []string{}, nil
	}
	out := make([]string, len(perms))
	copy(out, perms)
	return out, nil
}

// Has reports whether the account+role has been granted the exact permission.
func Has(ctx context.Context, store Store, accountID, role, permission string) (bool, error) {
	perms, err := store.Permissions(ctx, accountID, role)
	if err != nil {
		return false, err
	}
	for _, p := range perms {
		if p == permission {
			return true, nil
		}
	}
	return false, nil
}
