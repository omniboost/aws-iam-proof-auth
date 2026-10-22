package middleware

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	iamproof "github.com/omniboost/aws-iam-proof-auth"
	"github.com/omniboost/aws-iam-proof-auth/acl"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeVerifier returns a fixed principal or error regardless of input.
type fakeVerifier struct {
	principal *iamproof.Principal
	err       error
}

func (f fakeVerifier) Verify(_ context.Context, _ string) (*iamproof.Principal, error) {
	return f.principal, f.err
}

func TestRequireIdentity_Success(t *testing.T) {
	principal := &iamproof.Principal{AccountID: "111", Role: "Reader"}
	mw := RequireIdentity(fakeVerifier{principal: principal}, WithLogger(discardLogger()))

	var seen *iamproof.Principal
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = iamproof.PrincipalFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/identity", nil)
	req.Header.Set("Authorization", "AWS-IAM-PROOF whatever")
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if seen != principal {
		t.Errorf("principal not propagated to handler: got %+v", seen)
	}
}

func TestRequireIdentity_MissingHeader(t *testing.T) {
	mw := RequireIdentity(fakeVerifier{principal: &iamproof.Principal{}}, WithLogger(discardLogger()))
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })

	req := httptest.NewRequest(http.MethodPost, "/v1/identity", nil)
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if called {
		t.Error("next handler must not run without an Authorization header")
	}
}

func TestRequireIdentity_VerifyFails(t *testing.T) {
	mw := RequireIdentity(fakeVerifier{err: errors.New("bad proof")}, WithLogger(discardLogger()))
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })

	req := httptest.NewRequest(http.MethodPost, "/v1/identity", nil)
	req.Header.Set("Authorization", "AWS-IAM-PROOF whatever")
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if called {
		t.Error("next handler must not run when verification fails")
	}
}

// levelCapturingHandler records the level of the last log record it handles.
type levelCapturingHandler struct {
	lastLevel slog.Level
	handled   bool
}

func (h *levelCapturingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *levelCapturingHandler) Handle(_ context.Context, r slog.Record) error {
	h.lastLevel = r.Level
	h.handled = true
	return nil
}
func (h *levelCapturingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *levelCapturingHandler) WithGroup(string) slog.Handler      { return h }

func TestRequireIdentity_InfrastructureErrorLogsAtError(t *testing.T) {
	capture := &levelCapturingHandler{}
	logger := slog.New(capture)
	infraErr := fmt.Errorf("check nonce: %w: %w", iamproof.ErrInfrastructure, errors.New("valkey down"))
	mw := RequireIdentity(fakeVerifier{err: infraErr}, WithLogger(logger))

	req := httptest.NewRequest(http.MethodPost, "/v1/identity", nil)
	req.Header.Set("Authorization", "AWS-IAM-PROOF whatever")
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)

	if !capture.handled || capture.lastLevel != slog.LevelError {
		t.Errorf("infrastructure failure logged at %v, want error", capture.lastLevel)
	}
}

func TestRequireIdentity_ClientErrorLogsBelowError(t *testing.T) {
	capture := &levelCapturingHandler{}
	logger := slog.New(capture)
	mw := RequireIdentity(fakeVerifier{err: errors.New("invalid proof")}, WithLogger(logger))

	req := httptest.NewRequest(http.MethodPost, "/v1/identity", nil)
	req.Header.Set("Authorization", "AWS-IAM-PROOF whatever")
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)

	if !capture.handled || capture.lastLevel >= slog.LevelError {
		t.Errorf("client failure logged at %v, want below error", capture.lastLevel)
	}
}

func TestRequirePermission_Allowed(t *testing.T) {
	store := acl.NewMemoryStore(
		acl.Grant{AccountID: "111", Role: "Reader", Permissions: []string{"mappings.read"}},
	)
	mw := RequirePermission(store, "mappings.read", WithLogger(discardLogger()))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/mappings", nil)
	req = req.WithContext(iamproof.ContextWithPrincipal(req.Context(),
		&iamproof.Principal{AccountID: "111", Role: "Reader"}))
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !called {
		t.Error("next handler should run when permission is granted")
	}
}

func TestRequirePermission_Denied(t *testing.T) {
	store := acl.NewMemoryStore(
		acl.Grant{AccountID: "111", Role: "Reader", Permissions: []string{"mappings.read"}},
	)
	mw := RequirePermission(store, "mappings.write", WithLogger(discardLogger()))

	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })

	req := httptest.NewRequest(http.MethodPost, "/v1/mappings", nil)
	req = req.WithContext(iamproof.ContextWithPrincipal(req.Context(),
		&iamproof.Principal{AccountID: "111", Role: "Reader"}))
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if called {
		t.Error("next handler must not run when permission is denied")
	}
}

func TestRequirePermission_NoPrincipal(t *testing.T) {
	store := acl.NewMemoryStore()
	mw := RequirePermission(store, "mappings.read", WithLogger(discardLogger()))

	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })

	req := httptest.NewRequest(http.MethodGet, "/v1/mappings", nil)
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if called {
		t.Error("next handler must not run without an authenticated principal")
	}
}

func TestAuthRequire_ChecksEveryPermission(t *testing.T) {
	store := acl.NewMemoryStore(
		acl.Grant{AccountID: "111", Role: "Reader", Permissions: []string{"a", "b"}},
	)
	verifier := fakeVerifier{principal: &iamproof.Principal{AccountID: "111", Role: "Reader"}}
	a := NewAuth(verifier, store, WithLogger(discardLogger()))

	tests := []struct {
		permissions []string
		want        int
	}{
		{nil, http.StatusOK},
		{[]string{"a"}, http.StatusOK},
		{[]string{"a", "b"}, http.StatusOK},
		{[]string{"a", "c"}, http.StatusForbidden},
		{[]string{"c", "a"}, http.StatusForbidden},
	}
	for _, tt := range tests {
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "AWS-IAM-PROOF whatever")
		rec := httptest.NewRecorder()
		a.Require(tt.permissions...)(next).ServeHTTP(rec, req)

		if rec.Code != tt.want {
			t.Errorf("Require(%q) status = %d, want %d", tt.permissions, rec.Code, tt.want)
		}
	}
}

func TestDefaultErrorFormat(t *testing.T) {
	mw := RequireIdentity(fakeVerifier{}, WithLogger(discardLogger()))
	rec := httptest.NewRecorder()
	mw(http.NotFoundHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got, want := rec.Body.String(), `{"error":"missing Authorization header"}`+"\n"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestWithErrorWriter(t *testing.T) {
	var gotStatus int
	var gotMessage string
	writer := func(w http.ResponseWriter, _ *http.Request, status int, message string) {
		gotStatus, gotMessage = status, message
		w.WriteHeader(status)
	}
	mw := RequireIdentity(fakeVerifier{}, WithLogger(discardLogger()), WithErrorWriter(writer))
	mw(http.NotFoundHandler()).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if gotStatus != http.StatusUnauthorized || gotMessage != "missing Authorization header" {
		t.Errorf("error writer got (%d, %q)", gotStatus, gotMessage)
	}
}
