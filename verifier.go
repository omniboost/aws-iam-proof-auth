package iamproof

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// ErrInfrastructure marks a verification failure caused by a backend dependency
// (e.g. the nonce store being unreachable) rather than an invalid proof.
// Callers can use errors.Is to distinguish server faults, which should be
// logged and reported, from ordinary client errors.
var ErrInfrastructure = errors.New("infrastructure failure")

// defaultHTTPTimeout bounds STS requests when the caller does not supply its
// own client, so a slow or hung STS endpoint cannot block a request forever.
const defaultHTTPTimeout = 10 * time.Second

// Verifier turns an AWS-IAM-PROOF authorization header into a verified
// Principal. It is safe for concurrent use.
type Verifier struct {
	httpClient *http.Client
	nonces     NonceStore
}

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier)

// WithHTTPClient sets the client used to call STS. The default has a 10s
// timeout. A nil client is ignored.
func WithHTTPClient(httpClient *http.Client) VerifierOption {
	return func(v *Verifier) {
		if httpClient != nil {
			v.httpClient = httpClient
		}
	}
}

// NewVerifier builds a Verifier that claims each proof's nonce in nonces. A
// nil store disables replay protection, which is only acceptable in tests: in
// production use a store shared by every instance, such as valkeynonce.Store.
func NewVerifier(nonces NonceStore, opts ...VerifierOption) *Verifier {
	v := &Verifier{
		httpClient: &http.Client{Timeout: defaultHTTPTimeout},
		nonces:     nonces,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Verify validates the authorization header, calls STS, and returns the caller.
func (v *Verifier) Verify(ctx context.Context, authorization string) (*Principal, error) {
	rawURL, err := parseAuthorization(authorization)
	if err != nil {
		return nil, err
	}

	nonceValue, err := validatePresignedURL(rawURL, time.Now())
	if err != nil {
		return nil, err
	}

	if v.nonces != nil {
		fresh, err := v.nonces.Use(ctx, nonceValue)
		if err != nil {
			// A nonce-store failure is an infrastructure problem, not an
			// invalid proof, so mark it for callers to report.
			return nil, fmt.Errorf("check nonce: %w: %w", ErrInfrastructure, err)
		}
		if !fresh {
			return nil, fmt.Errorf("nonce %q has already been used", nonceValue)
		}
	}

	identity, err := fetchIdentity(ctx, v.httpClient, rawURL)
	if err != nil {
		return nil, err
	}

	return NewPrincipalFromCallerARN(aws.ToString(identity.Arn))
}
