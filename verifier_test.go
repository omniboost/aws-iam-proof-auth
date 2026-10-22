package iamproof

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeNonceStore is a controllable NonceStore for verifier tests.
type fakeNonceStore struct {
	fresh bool
	err   error
	calls int
}

func (f *fakeNonceStore) Use(_ context.Context, _ string) (bool, error) {
	f.calls++
	if f.err != nil {
		return false, f.err
	}
	return f.fresh, nil
}

// rewriteTransport routes every request to the test server, so a presigned URL
// pointed at sts.amazonaws.com is served by httptest while keeping the real
// validation path (which requires an STS hostname) intact.
type rewriteTransport struct {
	target *url.URL
}

func (rt rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = rt.target.Scheme
	req.URL.Host = rt.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

const validARN = "arn:aws:sts::123456789012:assumed-role/MyRole/my-session"

func validIdentityXML() string {
	return `<GetCallerIdentityResponse><GetCallerIdentityResult>` +
		`<Arn>` + validARN + `</Arn>` +
		`<UserId>AROAEXAMPLE:my-session</UserId>` +
		`<Account>123456789012</Account>` +
		`</GetCallerIdentityResult></GetCallerIdentityResponse>`
}

func newTestVerifier(t *testing.T, store NonceStore, handler http.HandlerFunc) *Verifier {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	client := &http.Client{Transport: rewriteTransport{target: target}}
	return NewVerifier(store, WithHTTPClient(client))
}

func stsHeader(nonce string) string {
	date := time.Now().UTC().Format(amzDateLayout)
	raw := "https://sts.amazonaws.com/?Action=GetCallerIdentity" +
		"&X-Amz-Date=" + date + "&X-Amz-Expires=60&X-Amz-Nonce=" + nonce
	return "AWS-IAM-PROOF " + encodeProof(raw)
}

func TestVerify_Success(t *testing.T) {
	store := &fakeNonceStore{fresh: true}
	v := newTestVerifier(t, store, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validIdentityXML()))
	})

	principal, err := v.Verify(context.Background(), stsHeader("nonce-1"))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if principal.Role != "MyRole" || principal.AccountID != "123456789012" {
		t.Errorf("unexpected principal: %+v", principal)
	}
	if store.calls != 1 {
		t.Errorf("nonce store called %d times, want 1", store.calls)
	}
}

func TestVerify_ReplayedNonceRejected(t *testing.T) {
	store := &fakeNonceStore{fresh: false}
	stsCalled := false
	v := newTestVerifier(t, store, func(w http.ResponseWriter, _ *http.Request) {
		stsCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validIdentityXML()))
	})

	_, err := v.Verify(context.Background(), stsHeader("reused"))
	if err == nil {
		t.Fatal("expected replayed nonce to be rejected")
	}
	if !strings.Contains(err.Error(), "already been used") {
		t.Errorf("unexpected error: %v", err)
	}
	if stsCalled {
		t.Error("STS must not be called once a nonce is rejected as replayed")
	}
}

func TestVerify_NonceStoreErrorIsInfrastructure(t *testing.T) {
	store := &fakeNonceStore{err: errors.New("valkey unreachable")}
	v := newTestVerifier(t, store, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("STS must not be called when the nonce store fails")
	})

	_, err := v.Verify(context.Background(), stsHeader("any"))
	if err == nil {
		t.Fatal("expected an error when the nonce store fails")
	}
	if !errors.Is(err, ErrInfrastructure) {
		t.Errorf("error not marked as infrastructure: %v", err)
	}
}

func TestVerify_InvalidHeaderShortCircuits(t *testing.T) {
	store := &fakeNonceStore{fresh: true}
	v := newTestVerifier(t, store, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("STS must not be called for an invalid header")
	})

	if _, err := v.Verify(context.Background(), "Bearer nope"); err == nil {
		t.Fatal("expected error for invalid header scheme")
	}
	if store.calls != 0 {
		t.Errorf("nonce store called %d times, want 0", store.calls)
	}
}

func TestVerify_STSErrorPropagates(t *testing.T) {
	store := &fakeNonceStore{fresh: true}
	v := newTestVerifier(t, store, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("AccessDenied"))
	})

	_, err := v.Verify(context.Background(), stsHeader("nonce-2"))
	if err == nil {
		t.Fatal("expected error when STS returns non-200")
	}
	// A 403 means the proof is invalid/expired: a client error, not infra.
	if errors.Is(err, ErrInfrastructure) {
		t.Errorf("STS 403 should not be an infrastructure error: %v", err)
	}
}

func TestVerify_STSServerErrorIsInfrastructure(t *testing.T) {
	store := &fakeNonceStore{fresh: true}
	v := newTestVerifier(t, store, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unavailable"))
	})

	_, err := v.Verify(context.Background(), stsHeader("nonce-5xx"))
	if err == nil {
		t.Fatal("expected error when STS returns 5xx")
	}
	if !errors.Is(err, ErrInfrastructure) {
		t.Errorf("STS 5xx should be an infrastructure error: %v", err)
	}
}

func TestVerify_STSUnreachableIsInfrastructure(t *testing.T) {
	store := &fakeNonceStore{fresh: true}
	// Point the client at a server that is immediately closed, so the request
	// fails at the transport level (connection refused).
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	server.Close()
	client := &http.Client{Transport: rewriteTransport{target: target}}
	v := NewVerifier(store, WithHTTPClient(client))

	_, err = v.Verify(context.Background(), stsHeader("nonce-net"))
	if err == nil {
		t.Fatal("expected error when STS is unreachable")
	}
	if !errors.Is(err, ErrInfrastructure) {
		t.Errorf("unreachable STS should be an infrastructure error: %v", err)
	}
}

// TestVerify_NilStoreSkipsReplayCheck documents that a nil store disables
// replay protection (the documented behaviour of NewVerifier).
func TestVerify_NilStoreSkipsReplayCheck(t *testing.T) {
	v := newTestVerifier(t, nil, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validIdentityXML()))
	})

	if _, err := v.Verify(context.Background(), stsHeader("nonce-3")); err != nil {
		t.Fatalf("Verify with nil store: %v", err)
	}
}
