package iamproof

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// maxPresignedURLValidity caps the X-Amz-Expires window we accept on a proof.
//
// A presigned URL is protected against replay only while its nonce is still
// remembered by the nonce store: once STS would still honour a URL but the
// nonce has been evicted, a captured proof could be replayed successfully.
// Keeping this cap safely below the nonce store TTL (DefaultNonceTTL)
// guarantees STS rejects the URL as expired well before that replay window can
// open. Signer requests 60s (DefaultExpiry); 120s leaves headroom without
// approaching the nonce TTL.
const maxPresignedURLValidity = 2 * time.Minute

// amzDateLayout is the SigV4 X-Amz-Date format (ISO 8601 basic, UTC).
const amzDateLayout = "20060102T150405Z"

// Principal is the verified identity behind a request.
type Principal struct {
	AccountID string `json:"account_id"`
	Role      string `json:"role"`
	Session   string `json:"session"`
	ARN       string `json:"arn"`
}

type getCallerIdentityEnvelope struct {
	XMLName xml.Name `xml:"GetCallerIdentityResponse"`
	Result  struct {
		Arn     string `xml:"Arn"`
		UserID  string `xml:"UserId"`
		Account string `xml:"Account"`
	} `xml:"GetCallerIdentityResult"`
}

// parseAuthorization extracts the presigned STS URL from an Authorization
// header value of the form "AWS-IAM-PROOF <base64-url>".
//
// Signer emits padded URL-safe base64, but the standard alphabet and unpadded
// forms are accepted too: PHP's base64_encode emits the standard alphabet, and
// callers built from older examples send it.
func parseAuthorization(header string) (string, error) {
	parts := strings.SplitN(strings.TrimSpace(header), " ", 2)
	if len(parts) != 2 || parts[0] != AuthScheme {
		return "", fmt.Errorf("authorization header must use the %s scheme", AuthScheme)
	}

	raw, err := decodeProof(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode proof: %w", err)
	}

	return string(raw), nil
}

// decodeProof decodes base64 in either alphabet, with or without padding.
func decodeProof(encoded string) ([]byte, error) {
	encoded = strings.TrimRight(encoded, "=")
	if strings.ContainsAny(encoded, "+/") {
		return base64.RawStdEncoding.DecodeString(encoded)
	}
	return base64.RawURLEncoding.DecodeString(encoded)
}

// validatePresignedURL ensures the presigned URL targets the STS
// GetCallerIdentity action, stays valid for only a short window, and carries a
// nonce. now is the current time, used to bound the URL's freshness.
func validatePresignedURL(rawURL string, now time.Time) (nonce string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse presigned url: %w", err)
	}

	if u.Scheme != "https" {
		return "", fmt.Errorf("presigned url scheme %q is not https", u.Scheme)
	}

	query := u.Query()

	if query.Get(ActionParam) != "GetCallerIdentity" {
		return "", errors.New("presigned url action must be GetCallerIdentity")
	}

	hostname := u.Hostname()
	if (!strings.HasSuffix(hostname, ".amazonaws.com") && !strings.HasSuffix(hostname, ".api.aws")) ||
		(!strings.HasPrefix(hostname, "sts.") && !strings.HasPrefix(hostname, "sts-fips.")) {
		return "", fmt.Errorf("presigned url host %q is not a valid STS endpoint", hostname)
	}

	if err := validateValidityWindow(query, now); err != nil {
		return "", err
	}

	nonce = query.Get(NonceParam)
	if nonce == "" {
		return "", errors.New("presigned url is missing a nonce")
	}

	return nonce, nil
}

// validateValidityWindow bounds how long a presigned proof stays usable so a
// captured URL cannot outlive its nonce and be replayed. It rejects an
// X-Amz-Expires above maxPresignedURLValidity and, as defense in depth, an
// X-Amz-Date signed longer ago than the nonce store would remember it.
func validateValidityWindow(query url.Values, now time.Time) error {
	expiresStr := query.Get(ExpiresParam)
	if expiresStr == "" {
		return errors.New("presigned url is missing X-Amz-Expires")
	}
	expires, err := strconv.Atoi(expiresStr)
	if err != nil || expires <= 0 {
		return fmt.Errorf("presigned url has invalid X-Amz-Expires %q", expiresStr)
	}
	// Compare in seconds before converting to a Duration: expires is an
	// attacker-controlled int, and time.Duration(expires)*time.Second overflows
	// int64 for large values (wrapping to a small/negative duration that would
	// slip past the cap).
	if int64(expires) > int64(maxPresignedURLValidity/time.Second) {
		return fmt.Errorf("presigned url validity %ds exceeds the %s maximum", expires, maxPresignedURLValidity)
	}

	dateStr := query.Get(DateParam)
	if dateStr == "" {
		return errors.New("presigned url is missing X-Amz-Date")
	}
	signedAt, err := time.Parse(amzDateLayout, dateStr)
	if err != nil {
		return fmt.Errorf("presigned url has invalid X-Amz-Date %q: %w", dateStr, err)
	}
	if age := now.Sub(signedAt); age > DefaultNonceTTL {
		return fmt.Errorf("presigned url signed %s ago exceeds the %s freshness window",
			age.Round(time.Second), DefaultNonceTTL)
	}

	return nil
}

// fetchIdentity calls the presigned STS URL and decodes the caller identity.
func fetchIdentity(ctx context.Context, httpClient *http.Client, rawURL string) (*sts.GetCallerIdentityOutput, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		// Reaching STS failed (DNS, connection, timeout): infrastructure, not
		// an invalid proof.
		return nil, fmt.Errorf("execute request: %w: %w", ErrInfrastructure, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		// Connection dropped while reading STS's response: infrastructure.
		return nil, fmt.Errorf("read response body: %w: %w", ErrInfrastructure, err)
	}

	if resp.StatusCode != http.StatusOK {
		// 5xx means STS itself is failing (infrastructure); other statuses
		// (e.g. 403) indicate the proof is invalid or expired (client error).
		if resp.StatusCode >= http.StatusInternalServerError {
			return nil, fmt.Errorf("sts returned %s: %s: %w", resp.Status, strings.TrimSpace(string(body)), ErrInfrastructure)
		}
		return nil, fmt.Errorf("sts returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var envelope getCallerIdentityEnvelope
	if err := xml.Unmarshal(body, &envelope); err != nil {
		// A 200 with an unparseable body means STS returned something
		// unexpected: treat as an upstream/infrastructure problem.
		return nil, fmt.Errorf("decode GetCallerIdentityResponse XML: %w: %w", ErrInfrastructure, err)
	}

	return &sts.GetCallerIdentityOutput{
		Account: aws.String(envelope.Result.Account),
		Arn:     aws.String(envelope.Result.Arn),
		UserId:  aws.String(envelope.Result.UserID),
	}, nil
}

// NewPrincipalFromCallerARN parses an assumed-role STS ARN into a Principal.
func NewPrincipalFromCallerARN(callerArn string) (*Principal, error) {
	parsed, err := arn.Parse(callerArn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse arn '%s': %w", callerArn, err)
	}

	// currently we only support sts as resource provider
	if parsed.Service != "sts" {
		return nil, fmt.Errorf("arn '%s' is not 'sts'", callerArn)
	}

	// the resource is formatted as "<type>/<role>/<session>", and we only want assumed-role resources
	parts := strings.SplitN(parsed.Resource, "/", 3)
	if len(parts) != 3 || parts[0] != "assumed-role" {
		return nil, errors.New("unexpected arn format")
	}

	return &Principal{
		AccountID: parsed.AccountID,
		Role:      normalizeRole(parts[1]),
		Session:   parts[2],
		ARN:       callerArn,
	}, nil
}

var ssoRolePattern = regexp.MustCompile(`^AWSReservedSSO_(.+?)_[a-f0-9]+$`)

func normalizeRole(role string) string {
	matches := ssoRolePattern.FindStringSubmatch(role)
	if len(matches) == 2 {
		return matches[1]
	}

	return role
}
