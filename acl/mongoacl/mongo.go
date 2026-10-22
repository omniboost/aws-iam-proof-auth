// Package mongoacl is an acl.Store backed by a MongoDB collection of grants,
// one document per account ID + role:
//
//	{"account_id": "123456789012", "role": "Developer", "permissions": ["pipelines.view"]}
package mongoacl

import (
	"context"
	"errors"
	"fmt"

	"github.com/omniboost/aws-iam-proof-auth/acl"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// DefaultCollection is the collection New reads grants from.
const DefaultCollection = "acl_grants"

var _ acl.Store = (*Store)(nil)

// grantDocument is the stored shape of a grant. It is keyed on account ID and
// role name, matching acl.MemoryStore.
type grantDocument struct {
	AccountID   string   `bson:"account_id"`
	Role        string   `bson:"role"`
	Permissions []string `bson:"permissions"`
}

// Store is an acl.Store backed by a MongoDB collection. It reads grants keyed
// on account ID + role name. The caller owns the underlying client's lifecycle.
// Wrap it in acl.NewCachedStore to avoid a query per request.
type Store struct {
	collection *mongo.Collection
}

// New builds a Store reading from the acl_grants collection in db.
func New(db *mongo.Database) *Store {
	return NewWithCollection(db.Collection(DefaultCollection))
}

// NewWithCollection builds a Store reading from collection.
func NewWithCollection(collection *mongo.Collection) *Store {
	return &Store{collection: collection}
}

// EnsureIndexes creates the unique compound index on (account_id, role), the
// lookup Permissions does. It is idempotent and safe to call on every startup.
func (s *Store) EnsureIndexes(ctx context.Context) error {
	_, err := s.collection.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "account_id", Value: 1},
			{Key: "role", Value: 1},
		},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("acl ensure index: %w", err)
	}
	return nil
}

// Permissions returns the permissions granted to accountID+role. A missing
// document yields an empty slice and a nil error, never an error.
func (s *Store) Permissions(ctx context.Context, accountID, role string) ([]string, error) {
	filter := bson.D{
		{Key: "account_id", Value: accountID},
		{Key: "role", Value: role},
	}

	var doc grantDocument
	err := s.collection.FindOne(ctx, filter).Decode(&doc)
	switch {
	case errors.Is(err, mongo.ErrNoDocuments):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("acl mongo find grant: %w", err)
	}

	if len(doc.Permissions) == 0 {
		return nil, nil
	}
	return doc.Permissions, nil
}
