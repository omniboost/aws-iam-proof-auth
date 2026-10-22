package iamproof

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// DefaultExpiry is how long a proof made by Signer stays valid at STS.
const DefaultExpiry = 60 * time.Second

// Signer makes AWS-IAM-PROOF headers from AWS credentials. It is safe for
// concurrent use; build one and reuse it, so the credential cache in its
// aws.Config is reused too.
type Signer struct {
	presigner *sts.PresignClient
}

// NewSigner builds a Signer from cfg. cfg must name a region: the proof is
// signed for that region's STS endpoint.
func NewSigner(cfg aws.Config) *Signer {
	presigner := sts.NewPresignClient(sts.NewFromConfig(cfg), func(o *sts.PresignOptions) {
		o.Presigner = &noncePresigner{signer: v4.NewSigner()}
	})
	return &Signer{presigner: presigner}
}

// NewDefaultSigner builds a Signer from the default AWS credential chain
// (environment, shared config and SSO, container and instance roles).
func NewDefaultSigner(ctx context.Context) (*Signer, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return NewSigner(cfg), nil
}

// Header returns a fresh "AWS-IAM-PROOF <proof>" Authorization header value.
// Each value carries its own nonce, so it is good for exactly one request.
func (s *Signer) Header(ctx context.Context) (string, error) {
	presignedURL, err := s.PresignedURL(ctx)
	if err != nil {
		return "", err
	}
	return AuthScheme + " " + base64.URLEncoding.EncodeToString([]byte(presignedURL)), nil
}

// PresignedURL returns a presigned STS GetCallerIdentity URL carrying a fresh
// nonce. Header wraps it into the Authorization header value.
func (s *Signer) PresignedURL(ctx context.Context) (string, error) {
	req, err := s.presigner.PresignGetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("presign GetCallerIdentity: %w", err)
	}
	return req.URL, nil
}

// Header returns a fresh Authorization header value signed with the default
// AWS credential chain. It loads the AWS config on every call; for repeated use
// build a Signer once with NewDefaultSigner.
func Header(ctx context.Context) (string, error) {
	signer, err := NewDefaultSigner(ctx)
	if err != nil {
		return "", err
	}
	return signer.Header(ctx)
}

// PresignedURL is Header without the scheme and encoding.
func PresignedURL(ctx context.Context) (string, error) {
	signer, err := NewDefaultSigner(ctx)
	if err != nil {
		return "", err
	}
	return signer.PresignedURL(ctx)
}

// noncePresigner wraps a v4.Signer and adds a random nonce and the expiry to
// the query before signing, so both are covered by the SigV4 signature.
type noncePresigner struct {
	signer *v4.Signer
}

func (p *noncePresigner) PresignHTTP(
	ctx context.Context, credentials aws.Credentials, r *http.Request,
	payloadHash string, service string, region string, signingTime time.Time,
	optFns ...func(*v4.SignerOptions),
) (string, http.Header, error) {
	nonce, err := generateNonce()
	if err != nil {
		return "", nil, fmt.Errorf("generate nonce: %w", err)
	}

	query := r.URL.Query()
	query.Set(NonceParam, nonce)
	query.Set(ExpiresParam, strconv.Itoa(int(DefaultExpiry/time.Second)))
	r.URL.RawQuery = query.Encode()

	return p.signer.PresignHTTP(ctx, credentials, r, payloadHash, service, region, signingTime, optFns...)
}

// generateNonce returns a cryptographically random 16-byte hex string.
func generateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
