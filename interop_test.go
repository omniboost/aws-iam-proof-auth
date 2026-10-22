package iamproof

import (
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// TestInterop checks that headers signed by the Go and PHP signers pass the
// Go verifier's checks. php/tests/InteropTest.php runs the same fixtures
// through the PHP verifier. The fixtures are signed with AWS's documented
// example key, so STS would reject them; only the format is under test.
func TestInterop(t *testing.T) {
	for _, name := range []string{"go-header.txt", "php-header.txt"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile("testdata/interop/" + name)
			if err != nil {
				t.Fatal(err)
			}

			rawURL, err := parseAuthorization(strings.TrimSpace(string(data)))
			if err != nil {
				t.Fatalf("parseAuthorization: %v", err)
			}
			u, err := url.Parse(rawURL)
			if err != nil {
				t.Fatal(err)
			}
			// Validate as of the signing time, so the fixture never goes stale.
			signedAt, err := time.Parse(amzDateLayout, u.Query().Get(DateParam))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := validatePresignedURL(rawURL, signedAt); err != nil {
				t.Errorf("validatePresignedURL: %v", err)
			}
		})
	}
}
