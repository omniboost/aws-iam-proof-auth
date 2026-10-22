package acl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// EnvVar is the environment variable FromEnv reads grants from.
const EnvVar = "AWS_IAM_PROOF_ACL"

var accountIDPattern = regexp.MustCompile(`^[0-9]{12}$`)

// ParseGrants decodes a JSON array of grants:
//
//	[{"account_id": "123456789012", "role": "Developer", "permissions": ["pipelines.view"]}]
//
// It is strict, because a typo here silently denies access: unknown fields, an
// account ID that is not 12 digits, an empty role and an empty permission are
// all errors.
func ParseGrants(data []byte) ([]Grant, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var grants []Grant
	if err := dec.Decode(&grants); err != nil {
		return nil, fmt.Errorf("acl: decode grants: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("acl: decode grants: unexpected data after the array")
	}

	for i, g := range grants {
		if !accountIDPattern.MatchString(g.AccountID) {
			return nil, fmt.Errorf("acl: grant %d: account_id %q is not a 12-digit AWS account ID", i, g.AccountID)
		}
		if g.Role == "" {
			return nil, fmt.Errorf("acl: grant %d: role is empty", i)
		}
		for _, p := range g.Permissions {
			if strings.TrimSpace(p) == "" {
				return nil, fmt.Errorf("acl: grant %d: empty permission", i)
			}
		}
	}
	return grants, nil
}

// FromEnv builds a MemoryStore from the grants in the AWS_IAM_PROOF_ACL
// environment variable, in the format ParseGrants reads. ok is false when the
// variable is unset or blank, so the caller can fall back to another store.
func FromEnv() (store *MemoryStore, ok bool, err error) {
	raw := strings.TrimSpace(os.Getenv(EnvVar))
	if raw == "" {
		return nil, false, nil
	}
	grants, err := ParseGrants([]byte(raw))
	if err != nil {
		return nil, true, fmt.Errorf("%s: %w", EnvVar, err)
	}
	return NewMemoryStore(grants...), true, nil
}
