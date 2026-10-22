// Package iamproof authenticates HTTP requests between services with the
// caller's AWS identity, without shared secrets.
//
// The caller presigns an STS GetCallerIdentity request with its own AWS
// credentials and sends the presigned URL, base64-encoded, in the Authorization
// header:
//
//	Authorization: AWS-IAM-PROOF <base64url(presigned STS URL)>
//
// The receiving service checks the URL really targets STS, claims the nonce
// signed into it so it cannot be replayed, and calls the URL. STS answers with
// the caller's ARN, which becomes a Principal (account ID + role).
//
// Signer builds the header and Transport attaches it to outgoing requests.
// Verifier checks an incoming header. The middleware package wraps Verifier and
// an acl.Store into net/http middleware.
package iamproof

// AuthScheme is the Authorization scheme carrying the proof.
const AuthScheme = "AWS-IAM-PROOF"

// Query parameters of the presigned STS URL the verifier inspects.
const (
	// NonceParam carries the random nonce the signer adds before signing, so
	// it is covered by the signature and each proof can be used only once.
	NonceParam   = "X-Amz-Nonce"
	ExpiresParam = "X-Amz-Expires"
	DateParam    = "X-Amz-Date"
	ActionParam  = "Action"
)
