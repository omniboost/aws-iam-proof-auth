package iamproof

import (
	"fmt"
	"net/http"
)

// Transport is an http.RoundTripper that adds a fresh AWS-IAM-PROOF
// Authorization header to every request, retries included, since a proof is
// good for one request only.
//
//	client := &http.Client{Transport: &iamproof.Transport{Signer: signer}}
type Transport struct {
	// Signer makes the headers. Required.
	Signer *Signer
	// Base sends the request. Nil uses http.DefaultTransport.
	Base http.RoundTripper
}

// RoundTrip signs a copy of req and sends it with Base.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	header, err := t.Signer.Header(req.Context())
	if err != nil {
		// A RoundTripper must close the body, even on error.
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, fmt.Errorf("aws-iam-proof: %w", err)
	}

	// A RoundTripper must not modify the caller's request.
	signed := req.Clone(req.Context())
	signed.Header.Set("Authorization", header)

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(signed)
}
