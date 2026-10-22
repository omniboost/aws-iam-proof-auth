package iamproof

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
)

// fallbackRegion is used only when nothing in the environment names one;
// presigning needs a region to build the endpoint and the signing scope.
const fallbackRegion = "eu-west-1"

// ambientCredentials probes the machine's default credential chain, returning
// the region it resolved (empty when nothing names one) or the reason it could
// not resolve. Probed once per run and bounded: with nothing configured the
// chain falls through to IMDS, which off EC2 only gives up after a wait, and
// paying that per test adds up.
var ambientCredentials = sync.OnceValues(func() (region string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return "", err
	}
	if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
		return "", err
	}
	return cfg.Region, nil
})

// useCredentials makes sure the default credential chain resolves to something.
//
// A machine with a real AWS session — an SSO login, a profile, an instance role
// — keeps it, so `go test -v .` still prints a presigned URL that STS
// will actually accept. Only when nothing resolves does the test fall back to
// static throwaway keys: presigning never leaves the process, so fake keys are
// enough to exercise and assert the whole signing path, and CI stays green
// without any credentials at all.
func useCredentials(t *testing.T) {
	t.Helper()

	region, err := ambientCredentials()
	if err == nil {
		t.Log("signing with the ambient AWS credentials")
		if region == "" {
			t.Setenv("AWS_REGION", fallbackRegion)
		}
		return
	}

	// An environment that names an identity and then fails to produce one is a
	// broken session, not an absent one — an expired SSO login, most often. Say
	// so instead of quietly signing with keys STS will reject, which would hand
	// back a URL that looks fine and is not. CI sets none of these, so it takes
	// the fallback below.
	for _, key := range []string{"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_ROLE_ARN"} {
		if os.Getenv(key) != "" {
			t.Fatalf("%s is set but no credentials resolved (expired SSO session? run `aws sso login`): %v", key, err)
		}
	}

	// Both profile variables are cleared because a named profile outranks the
	// environment keys in the chain, and IMDS is disabled so the fallback cannot
	// stall either.
	t.Logf("no AWS credentials configured (%v) — signing with throwaway keys", err)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_REGION", fallbackRegion)
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_DEFAULT_PROFILE", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

// assertNonce checks the nonce is what generateNonce claims to produce: 16
// random bytes, hex-encoded. Length alone would accept a non-hex value the
// verifier would then have to reject.
func assertNonce(t *testing.T, nonce string) {
	t.Helper()

	raw, err := hex.DecodeString(nonce)
	if err != nil {
		t.Errorf("%s = %q, want hexadecimal: %v", NonceParam, nonce, err)
		return
	}
	if len(raw) != 16 {
		t.Errorf("%s = %q decodes to %d bytes, want 16", NonceParam, nonce, len(raw))
	}
}

func TestPresignedURL(t *testing.T) {
	useCredentials(t)

	raw, err := PresignedURL(context.Background())
	if err != nil {
		t.Fatalf("PresignedURL failed: %v", err)
	}
	// Printed so `go test -v -run TestPresignedURL .` on a machine
	// with a real session doubles as a way to mint a URL by hand.
	t.Log(raw)

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("presigned URL does not parse: %v", err)
	}
	if !strings.HasPrefix(u.Host, "sts.") {
		t.Errorf("host = %q, want an STS endpoint", u.Host)
	}

	q := u.Query()
	if got := q.Get(ActionParam); got != "GetCallerIdentity" {
		t.Errorf("%s = %q, want GetCallerIdentity", ActionParam, got)
	}
	// The nonce and the short expiry are what noncePresigner adds before
	// signing; the verifier on the other end rejects a URL without them.
	assertNonce(t, q.Get(NonceParam))
	if got := q.Get(ExpiresParam); got != "60" {
		t.Errorf("%s = %q, want 60", ExpiresParam, got)
	}
	if q.Get("X-Amz-Signature") == "" {
		t.Error("X-Amz-Signature is missing — the URL was not signed")
	}
	// SigV4's ISO8601 basic format. It is signer/internal/v4.TimeFormat in the
	// SDK, which this module cannot import. The URL dies 60s after this stamp,
	// so a value that does not parse — or that is nowhere near now — is a URL
	// the verifier will throw out.
	const sigV4TimeFormat = "20060102T150405Z"
	if got := q.Get(DateParam); got == "" {
		t.Errorf("%s is missing", DateParam)
	} else if signedAt, err := time.Parse(sigV4TimeFormat, got); err != nil {
		t.Errorf("%s = %q, want a SigV4 timestamp: %v", DateParam, got, err)
	} else if skew := time.Since(signedAt).Abs(); skew > 5*time.Minute {
		t.Errorf("%s = %q is %s from now", DateParam, got, skew)
	}
}

// TestPresignedURL_NonceIsFresh guards the replay protection: two URLs
// signed back to back must not carry the same nonce.
func TestPresignedURL_NonceIsFresh(t *testing.T) {
	useCredentials(t)

	nonce := func() string {
		t.Helper()
		raw, err := PresignedURL(context.Background())
		if err != nil {
			t.Fatalf("PresignedURL failed: %v", err)
		}
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("presigned URL does not parse: %v", err)
		}
		got := u.Query().Get(NonceParam)
		assertNonce(t, got)
		return got
	}

	if first, second := nonce(), nonce(); first == second {
		t.Errorf("two presigned URLs share the nonce %q", first)
	}
}

func TestHeader(t *testing.T) {
	useCredentials(t)

	header, err := Header(context.Background())
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}
	t.Log(header)

	scheme, encoded, ok := strings.Cut(header, " ")
	if !ok {
		t.Fatalf("header = %q, want %q followed by a value", header, AuthScheme)
	}
	if scheme != AuthScheme {
		t.Errorf("scheme = %q, want %q", scheme, AuthScheme)
	}

	decoded, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("value is not URL-safe base64: %v", err)
	}
	u, err := url.Parse(string(decoded))
	if err != nil {
		t.Fatalf("decoded value is not a URL: %v", err)
	}
	if u.Query().Get("X-Amz-Signature") == "" {
		t.Errorf("decoded URL %q carries no signature", decoded)
	}
}

// TestHeader_PassesValidation checks the signer's output against the verifier's
// own checks, so the two halves of the protocol cannot drift apart.
func TestHeader_PassesValidation(t *testing.T) {
	useCredentials(t)

	header, err := Header(context.Background())
	if err != nil {
		t.Fatalf("Header failed: %v", err)
	}
	rawURL, err := parseAuthorization(header)
	if err != nil {
		t.Fatalf("parseAuthorization: %v", err)
	}
	if _, err := validatePresignedURL(rawURL, time.Now()); err != nil {
		t.Fatalf("validatePresignedURL rejects the signer's own output: %v", err)
	}
}

func TestTransport_SignsEveryAttempt(t *testing.T) {
	useCredentials(t)

	signer, err := NewDefaultSigner(context.Background())
	if err != nil {
		t.Fatalf("NewDefaultSigner: %v", err)
	}

	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
	}))
	t.Cleanup(server.Close)

	client := &http.Client{Transport: &Transport{Signer: signer}}
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		_ = resp.Body.Close()
	}

	if req.Header.Get("Authorization") != "" {
		t.Error("Transport modified the caller's request")
	}
	if len(seen) != 2 || !strings.HasPrefix(seen[0], AuthScheme+" ") {
		t.Fatalf("server saw %q, want two AWS-IAM-PROOF headers", seen)
	}
	if seen[0] == seen[1] {
		t.Error("two requests carried the same proof")
	}
}
