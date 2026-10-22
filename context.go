package iamproof

import "context"

// contextKey is an unexported type for context keys defined in this package,
// preventing collisions with keys from other packages.
type contextKey int

const principalKey contextKey = iota

// ContextWithPrincipal returns a copy of ctx carrying the verified Principal.
func ContextWithPrincipal(ctx context.Context, principal *Principal) context.Context {
	return context.WithValue(ctx, principalKey, principal)
}

// PrincipalFromContext returns the Principal stored in ctx, if any.
func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	principal, ok := ctx.Value(principalKey).(*Principal)
	return principal, ok
}
