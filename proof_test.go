package iamproof

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// stdAlphabetURL encodes to base64 containing both '+' and '/' in the standard
// alphabet, so it tells the two alphabets apart.
const stdAlphabetURL = "https://sts.amazonaws.com/?a=~~~"

func TestParseAuthorization(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		want    string
		wantErr bool
	}{
		{
			name:   "valid",
			header: "AWS-IAM-PROOF " + encodeProof("https://sts.amazonaws.com/?Action=GetCallerIdentity"),
			want:   "https://sts.amazonaws.com/?Action=GetCallerIdentity",
		},
		{
			name:   "valid with surrounding whitespace",
			header: "  AWS-IAM-PROOF " + encodeProof("https://example.test") + "  ",
			want:   "https://example.test",
		},
		{
			name:   "standard alphabet",
			header: "AWS-IAM-PROOF " + base64.StdEncoding.EncodeToString([]byte(stdAlphabetURL)),
			want:   stdAlphabetURL,
		},
		{
			name:   "unpadded url-safe",
			header: "AWS-IAM-PROOF " + base64.RawURLEncoding.EncodeToString([]byte(stdAlphabetURL)),
			want:   stdAlphabetURL,
		},
		{
			name:    "wrong scheme",
			header:  "Bearer " + encodeProof("https://sts.amazonaws.com"),
			wantErr: true,
		},
		{
			name:    "missing proof part",
			header:  "AWS-IAM-PROOF",
			wantErr: true,
		},
		{
			name:    "invalid base64",
			header:  "AWS-IAM-PROOF not-valid-base64!!!",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAuthorization(tt.header)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result %q)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// TestValidatePresignedURL runs the cases shared with the PHP verifier, so the
// two implementations accept and reject the same URLs.
func TestValidatePresignedURL(t *testing.T) {
	data, err := os.ReadFile("testdata/proof/urls.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Now   time.Time `json:"now"`
		Cases []struct {
			Name  string  `json:"name"`
			URL   string  `json:"url"`
			Nonce *string `json:"nonce"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}

	for _, tt := range vectors.Cases {
		t.Run(tt.Name, func(t *testing.T) {
			nonce, err := validatePresignedURL(tt.URL, vectors.Now)
			if tt.Nonce == nil {
				if err == nil {
					t.Fatalf("expected error, got nil (nonce %q)", nonce)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if nonce != *tt.Nonce {
				t.Errorf("nonce = %q, want %q", nonce, *tt.Nonce)
			}
		})
	}
}

func TestNewPrincipalFromCallerARN(t *testing.T) {
	tests := []struct {
		name    string
		arn     string
		want    *Principal
		wantErr bool
	}{
		{
			name: "assumed role",
			arn:  "arn:aws:sts::123456789012:assumed-role/MyRole/my-session",
			want: &Principal{
				AccountID: "123456789012",
				Role:      "MyRole",
				Session:   "my-session",
				ARN:       "arn:aws:sts::123456789012:assumed-role/MyRole/my-session",
			},
		},
		{
			name: "sso role is normalized",
			arn:  "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_AdminAccess_0123abcd4567ef89/alice",
			want: &Principal{
				AccountID: "123456789012",
				Role:      "AdminAccess",
				Session:   "alice",
				ARN:       "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_AdminAccess_0123abcd4567ef89/alice",
			},
		},
		{
			name:    "non-sts service",
			arn:     "arn:aws:iam::123456789012:user/bob",
			wantErr: true,
		},
		{
			name:    "not an assumed role",
			arn:     "arn:aws:sts::123456789012:federated-user/bob",
			wantErr: true,
		},
		{
			name:    "malformed arn",
			arn:     "not-an-arn",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewPrincipalFromCallerARN(tt.arn)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if *got != *tt.want {
				t.Errorf("got %+v, want %+v", *got, *tt.want)
			}
		})
	}
}

func TestNormalizeRole(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"PlainRole", "PlainRole"},
		{"AWSReservedSSO_AdminAccess_0123abcd4567ef89", "AdminAccess"},
		{"AWSReservedSSO_Read_Only_deadbeef", "Read_Only"},
		{"AWSReservedSSO_malformed", "AWSReservedSSO_malformed"},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := normalizeRole(tt.in); got != tt.want {
				t.Errorf("normalizeRole(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// encodeProof mirrors how the client encodes the presigned URL into the
// AWS-IAM-PROOF authorization header (base64 URL encoding).
func encodeProof(rawURL string) string {
	return base64.URLEncoding.EncodeToString([]byte(rawURL))
}
