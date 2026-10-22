// Package valkeynonce is an iamproof.NonceStore backed by Valkey (or Redis), for
// replay protection shared by every instance of a service.
package valkeynonce

import (
	"context"
	"errors"
	"fmt"
	"time"

	iamproof "github.com/omniboost/aws-iam-proof-auth"
	"github.com/valkey-io/valkey-go"
)

// DefaultKeyPrefix namespaces nonce keys within the Valkey keyspace.
const DefaultKeyPrefix = "nonce:"

var _ iamproof.NonceStore = (*Store)(nil)

// Store is a NonceStore backed by Valkey. It claims each nonce with a
// single atomic SET NX EX, so replay protection holds across all server
// instances and Lambda invocations sharing the same Valkey deployment.
type Store struct {
	client    valkey.Client
	ttl       time.Duration
	keyPrefix string
}

// Option configures a Store.
type Option func(*Store)

// WithTTL overrides the nonce lifetime.
func WithTTL(ttl time.Duration) Option {
	return func(s *Store) { s.ttl = ttl }
}

// WithKeyPrefix overrides the key prefix used for nonce keys.
func WithKeyPrefix(prefix string) Option {
	return func(s *Store) { s.keyPrefix = prefix }
}

// New builds a Store around an existing client. The caller
// owns the client's lifecycle (and is responsible for closing it).
func New(client valkey.Client, opts ...Option) *Store {
	s := &Store{
		client:    client,
		ttl:       iamproof.DefaultNonceTTL,
		keyPrefix: DefaultKeyPrefix,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Use atomically claims the nonce. It returns true if the nonce was previously
// unused (the claim succeeded) and false if it has already been used within the
// TTL window. The SET NX EX is atomic on the Valkey server, so concurrent
// callers across instances cannot both observe a fresh nonce.
func (s *Store) Use(ctx context.Context, nonce string) (bool, error) {
	if s.client == nil {
		return false, errors.New("valkey nonce store has no client")
	}

	cmd := s.client.B().Set().
		Key(s.keyPrefix + nonce).
		Value("1").
		Nx().
		Ex(s.ttl).
		Build()

	err := s.client.Do(ctx, cmd).Error()
	switch {
	case err == nil:
		// SET returned OK: the key did not exist, so this nonce is fresh.
		return true, nil
	case valkey.IsValkeyNil(err):
		// NX condition failed: the key already existed, so the nonce was used.
		return false, nil
	default:
		return false, fmt.Errorf("valkey set nonce: %w", err)
	}
}
