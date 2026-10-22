package acl

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestParseGrants(t *testing.T) {
	grants, err := ParseGrants([]byte(`[
		{"account_id": "123456789012", "role": "Developer", "permissions": ["pipelines.view", "pipelines.edit"]},
		{"account_id": "210987654321", "role": "Reader", "permissions": []}
	]`))
	if err != nil {
		t.Fatalf("ParseGrants: %v", err)
	}

	want := []Grant{
		{AccountID: "123456789012", Role: "Developer", Permissions: []string{"pipelines.view", "pipelines.edit"}},
		{AccountID: "210987654321", Role: "Reader", Permissions: []string{}},
	}
	if !slices.EqualFunc(grants, want, func(a, b Grant) bool {
		return a.AccountID == b.AccountID && a.Role == b.Role && slices.Equal(a.Permissions, b.Permissions)
	}) {
		t.Errorf("got %+v, want %+v", grants, want)
	}
}

// TestParseGrants_Rejects runs the invalid inputs shared with the PHP tests, so
// both languages reject the same grants.
func TestParseGrants_Rejects(t *testing.T) {
	data, err := os.ReadFile("../testdata/acl/invalid.json")
	if err != nil {
		t.Fatal(err)
	}
	var tests map[string]string
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatal(err)
	}

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseGrants([]byte(input)); err == nil {
				t.Errorf("ParseGrants(%s) succeeded, want an error", input)
			}
		})
	}
}

func TestParseGrants_SharedValid(t *testing.T) {
	data, err := os.ReadFile("../testdata/acl/valid.json")
	if err != nil {
		t.Fatal(err)
	}
	grants, err := ParseGrants(data)
	if err != nil {
		t.Fatalf("ParseGrants: %v", err)
	}
	perms, _ := NewMemoryStore(grants...).Permissions(context.Background(), "123456789012", "Developer")
	if want := []string{"pipelines.view", "pipelines.edit", "pipelines.delete"}; !slices.Equal(perms, want) {
		t.Errorf("merged permissions = %q, want %q", perms, want)
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv(EnvVar, `[{"account_id": "123456789012", "role": "Developer", "permissions": ["pipelines.view"]}]`)

	store, ok, err := FromEnv()
	if err != nil || !ok {
		t.Fatalf("FromEnv = ok %v, err %v", ok, err)
	}
	allowed, err := Has(context.Background(), store, "123456789012", "Developer", "pipelines.view")
	if err != nil || !allowed {
		t.Errorf("Has = %v, %v; want true", allowed, err)
	}
}

func TestFromEnv_Unset(t *testing.T) {
	for _, value := range []string{"", "   "} {
		t.Setenv(EnvVar, value)
		if store, ok, err := FromEnv(); ok || err != nil || store != nil {
			t.Errorf("FromEnv with %q = %v, %v, %v; want nil, false, nil", value, store, ok, err)
		}
	}
}

func TestFromEnv_Invalid(t *testing.T) {
	t.Setenv(EnvVar, `[{"account_id": "1", "role": "R", "permissions": []}]`)

	_, ok, err := FromEnv()
	if !ok || err == nil {
		t.Fatalf("FromEnv = ok %v, err %v; want ok and an error", ok, err)
	}
	if !strings.Contains(err.Error(), EnvVar) {
		t.Errorf("error %q does not name %s", err, EnvVar)
	}
}
