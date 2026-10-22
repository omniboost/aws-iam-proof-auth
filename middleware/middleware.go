// Package middleware is net/http middleware that authenticates requests with
// an AWS-IAM-PROOF header and authorizes them against an acl.Store.
//
//	verifier := iamproof.NewVerifier(valkeynonce.New(valkeyClient))
//	auth := middleware.NewAuth(verifier, aclStore, middleware.WithLogger(logger))
//	mux.Handle("GET /pipelines", auth.Require("pipelines.view")(handler))
//
// The middleware are plain func(http.Handler) http.Handler, so they compose
// with any router.
package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"

	iamproof "github.com/omniboost/aws-iam-proof-auth"
	"github.com/omniboost/aws-iam-proof-auth/acl"
)

// Verifier verifies an AWS-IAM-PROOF Authorization header into a Principal.
// *iamproof.Verifier implements it.
type Verifier interface {
	Verify(ctx context.Context, authorization string) (*iamproof.Principal, error)
}

// ErrorWriter writes an error response. The default writes {"error": message}
// as JSON.
type ErrorWriter func(w http.ResponseWriter, r *http.Request, status int, message string)

// Option configures the middleware.
type Option func(*config)

type config struct {
	logger     *slog.Logger
	writeError ErrorWriter
}

// WithLogger sets the logger. The default is slog.Default().
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// WithErrorWriter replaces how error responses are written.
func WithErrorWriter(writeError ErrorWriter) Option {
	return func(c *config) {
		if writeError != nil {
			c.writeError = writeError
		}
	}
}

func newConfig(opts []Option) *config {
	c := &config{logger: slog.Default(), writeError: writeJSONError}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func writeJSONError(w http.ResponseWriter, _ *http.Request, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// RequireIdentity verifies the Authorization header and stores the Principal in
// the request context (see iamproof.PrincipalFromContext). Requests without a
// valid proof get a 401 and never reach next.
func RequireIdentity(verifier Verifier, opts ...Option) func(http.Handler) http.Handler {
	cfg := newConfig(opts)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authorization := r.Header.Get("Authorization")
			if authorization == "" {
				cfg.writeError(w, r, http.StatusUnauthorized, "missing Authorization header")
				return
			}

			principal, err := verifier.Verify(r.Context(), authorization)
			if err != nil {
				// Infrastructure failures (e.g. the nonce store being down) are
				// server faults: log at error so they are reported. An invalid
				// or expired proof is an ordinary client error, logged at info.
				if errors.Is(err, iamproof.ErrInfrastructure) {
					cfg.logger.ErrorContext(r.Context(), "identity verification failed due to infrastructure error", "error", err)
				} else {
					cfg.logger.InfoContext(r.Context(), "identity verification failed", "error", err)
				}
				cfg.writeError(w, r, http.StatusUnauthorized, "identity verification failed")
				return
			}

			ctx := iamproof.ContextWithPrincipal(r.Context(), principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequirePermission allows the request only if the authenticated principal has
// been granted the exact permission, and answers 403 otherwise. It must run
// after RequireIdentity, which puts the principal in the context.
func RequirePermission(store acl.Store, permission string, opts ...Option) func(http.Handler) http.Handler {
	cfg := newConfig(opts)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := iamproof.PrincipalFromContext(r.Context())
			if !ok {
				// A missing principal means the middleware chain is
				// misconfigured (RequirePermission without RequireIdentity).
				cfg.logger.ErrorContext(r.Context(), "permission check without authenticated principal", "permission", permission)
				cfg.writeError(w, r, http.StatusInternalServerError, "authorization misconfigured")
				return
			}

			allowed, err := acl.Has(r.Context(), store, principal.AccountID, principal.Role, permission)
			if err != nil {
				cfg.logger.ErrorContext(r.Context(), "permission lookup failed", "error", err, "permission", permission)
				cfg.writeError(w, r, http.StatusInternalServerError, "authorization lookup failed")
				return
			}
			if !allowed {
				cfg.logger.InfoContext(r.Context(), "permission denied",
					"account_id", principal.AccountID, "role", principal.Role, "permission", permission)
				cfg.writeError(w, r, http.StatusForbidden, "permission denied")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Auth bundles a verifier, an ACL store and options, so routes can declare
// their protection without wiring the dependencies each time.
type Auth struct {
	verifier Verifier
	store    acl.Store
	opts     []Option
}

// NewAuth builds an Auth.
func NewAuth(verifier Verifier, store acl.Store, opts ...Option) *Auth {
	return &Auth{verifier: verifier, store: store, opts: opts}
}

// RequireIdentity is RequireIdentity with a's verifier.
func (a *Auth) RequireIdentity() func(http.Handler) http.Handler {
	return RequireIdentity(a.verifier, a.opts...)
}

// RequirePermission is RequirePermission with a's store. It must run after
// RequireIdentity.
func (a *Auth) RequirePermission(permission string) func(http.Handler) http.Handler {
	return RequirePermission(a.store, permission, a.opts...)
}

// Require verifies the identity and then requires every one of permissions.
// With no permissions it only verifies the identity.
func (a *Auth) Require(permissions ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		for _, permission := range slices.Backward(permissions) {
			next = a.RequirePermission(permission)(next)
		}
		return a.RequireIdentity()(next)
	}
}
