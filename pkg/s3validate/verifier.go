package s3validate

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Verify validates the given request against the SigV4 algorithm.
// The request body must not be consumed prior to calling Verify.
// Verify returns a Result describing the signer on success.
func (v *Verifier) Verify(ctx context.Context, r *http.Request) (*Result, error) {
	if v == nil {
		return nil, errors.New("s3validate: verifier is nil")
	}
	if v.Credentials == nil {
		return nil, errors.New("s3validate: credentials provider is nil")
	}

	source, sigData, err := extractSignatureData(r)
	if err != nil {
		return nil, err
	}

	accessKey, scopeDate, scopeRegion, scopeService, scopeTerm, err := parseCredentialScope(sigData.Credential)
	if err != nil {
		return nil, err
	}
	if scopeService != Service {
		return nil, fmt.Errorf("s3validate: unsupported service %q", scopeService)
	}
	if scopeTerm != "aws4_request" {
		return nil, fmt.Errorf("s3validate: unexpected credential termination %q", scopeTerm)
	}

	amzDate, err := time.Parse("20060102T150405Z", sigData.AmzDate)
	if err != nil {
		return nil, fmt.Errorf("s3validate: invalid X-Amz-Date %q: %w", sigData.AmzDate, err)
	}

	now := v.now()

	// Enforce expiration for presigned requests.
	if source == SignatureSourceQuery && sigData.Expires != "" {
		expires, err := strconv.ParseInt(sigData.Expires, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("s3validate: invalid X-Amz-Expires %q", sigData.Expires)
		}
		if expires < 0 {
			return nil, fmt.Errorf("s3validate: negative X-Amz-Expires %q", sigData.Expires)
		}
		if now.After(amzDate.Add(time.Duration(expires) * time.Second)) {
			return nil, errors.New("s3validate: presigned URL has expired")
		}
	}

	allowedSkew := v.AllowedClockSkew
	if allowedSkew == 0 {
		allowedSkew = 5 * time.Minute
	}
	if amzDate.Before(now.Add(-allowedSkew)) || amzDate.After(now.Add(allowedSkew)) {
		return nil, errors.New("s3validate: signature time outside allowed clock skew")
	}

	secretKey, err := v.Credentials.SecretKey(ctx, accessKey)
	if err != nil {
		return nil, fmt.Errorf("s3validate: fetching secret for access key %q failed: %w", accessKey, err)
	}

	canonicalReqHash, signedHeaders, err := buildCanonicalRequestHash(r, sigData.SignedHeaders, sigData.PayloadHash, source)
	if err != nil {
		return nil, err
	}

	stringToSign := buildStringToSign(sigData.AmzDate, sigData.CredentialScope(), canonicalReqHash)
	signingKey := deriveSigningKey(secretKey, scopeDate, scopeRegion, scopeService)

	expected := hmacSHA256(signingKey, stringToSign)
	if !hmac.Equal(expected, sigData.SignatureBytes) {
		return nil, errors.New("s3validate: signature mismatch")
	}

	return &Result{
		AccessKey:       accessKey,
		ScopeDate:       scopeDate,
		ScopeRegion:     scopeRegion,
		SignedHeaders:   signedHeaders,
		SignatureSource: source,
	}, nil
}

// now returns the current time, using v.Now if set or time.Now otherwise.
func (v *Verifier) now() time.Time {
	if v != nil && v.Now != nil {
		return v.Now()
	}
	return time.Now()
}