package s3validate

import (
	"context"
	"time"
)

const (
	// Algorithm is the AWS SigV4 signing algorithm identifier.
	Algorithm = "AWS4-HMAC-SHA256"
	// Service is the AWS service identifier for S3.
	Service = "s3"
)

// CredentialsProvider supplies the secret key for a given access key.
type CredentialsProvider interface {
	SecretKey(ctx context.Context, accessKey string) (string, error)
}

// Verifier validates incoming S3 SigV4 signed requests.
type Verifier struct {
	Credentials CredentialsProvider
	// AllowedClockSkew defines how far the request timestamp
	// may drift from the verifier's clock. Defaults to 5 minutes.
	AllowedClockSkew time.Duration
	// Now allows overriding the source of current time. Useful for tests.
	Now func() time.Time
}

// Result describes the identity extracted from a valid signature.
type Result struct {
	AccessKey       string
	ScopeDate       string
	ScopeRegion     string
	SignedHeaders   []string
	SignatureSource SignatureSource
}

// SignatureSource indicates where the signature was extracted from.
type SignatureSource int

const (
	// SignatureSourceHeader indicates the signature was in the Authorization header.
	SignatureSourceHeader SignatureSource = iota
	// SignatureSourceQuery indicates the signature was in URL query parameters.
	SignatureSourceQuery
)

// signatureData holds the components required to rebuild the signature.
type signatureData struct {
	Credential     string
	SignedHeaders  []string
	Signature      string
	SignatureBytes []byte
	PayloadHash    string
	AmzDate        string
	Expires        string
	source         SignatureSource
}

// CredentialScope returns the credential scope string from signature data.
func (s signatureData) CredentialScope() string {
	parts := splitCredential(s.Credential)
	if len(parts) < 5 {
		return ""
	}
	return joinParts(parts[1:])
}

func splitCredential(credential string) []string {
	// Helper to avoid import cycle
	result := []string{}
	current := ""
	for _, c := range credential {
		if c == '/' {
			result = append(result, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

func joinParts(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += "/" + parts[i]
	}
	return result
}

// headerCanonicalization wraps the canonical header output and preserves list order.
type headerCanonicalization struct {
	CanonicalHeaders  string
	SignedHeaders     string
	SignedHeadersList []string
}