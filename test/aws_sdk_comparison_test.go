package test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DullJZ/s3-validate/internal/testutil"
	"github.com/DullJZ/s3-validate/pkg/s3validate"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// TestAWSSDKComparison tests that requests signed by AWS SDK v2
// can be successfully verified by our s3validate library.
func TestAWSSDKComparison(t *testing.T) {
	accessKey := "AKIAIOSFODNN7EXAMPLE"
	secretKey := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	region := "us-east-1"

	// Fixed time for reproducible signatures
	fixedTime := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		method      string
		url         string
		headers     map[string]string
		body        string
		payloadHash string
	}{
		{
			name:        "GET request with no body",
			method:      "GET",
			url:         "https://examplebucket.s3.amazonaws.com/test.txt",
			headers:     map[string]string{},
			body:        "",
			payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // empty body SHA256
		},
		{
			name:   "GET request with Range header",
			method: "GET",
			url:    "https://examplebucket.s3.amazonaws.com/test.txt",
			headers: map[string]string{
				"Range": "bytes=0-9",
			},
			body:        "",
			payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:   "PUT request with body",
			method: "PUT",
			url:    "https://examplebucket.s3.amazonaws.com/test.txt",
			headers: map[string]string{
				"Content-Type": "text/plain",
			},
			body:        "Hello, World!",
			payloadHash: "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f", // SHA256 of "Hello, World!"
		},
		{
			name:   "PUT request with JSON body",
			method: "PUT",
			url:    "https://examplebucket.s3.amazonaws.com/data.json",
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			body:        `{"key":"value"}`,
			payloadHash: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", // SHA256 of JSON
		},
		{
			name:        "GET request with trailing slash",
			method:      "GET",
			url:         "https://examplebucket.s3.amazonaws.com/folder/",
			headers:     map[string]string{},
			body:        "",
			payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:        "GET request without trailing slash",
			method:      "GET",
			url:         "https://examplebucket.s3.amazonaws.com/folder",
			headers:     map[string]string{},
			body:        "",
			payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:        "GET request with nested path and trailing slash",
			method:      "GET",
			url:         "https://examplebucket.s3.amazonaws.com/folder/subfolder/",
			headers:     map[string]string{},
			body:        "",
			payloadHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			var bodyReader io.Reader
			if tt.body != "" {
				bodyReader = strings.NewReader(tt.body)
			}
			req, err := http.NewRequest(tt.method, tt.url, bodyReader)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			req.Host = req.URL.Host

			// Set custom headers
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			// Set X-Amz-Content-Sha256 header explicitly
			req.Header.Set("X-Amz-Content-Sha256", tt.payloadHash)

			// Sign request using AWS SDK v2
			creds := aws.Credentials{
				AccessKeyID:     accessKey,
				SecretAccessKey: secretKey,
			}
			signer := v4.NewSigner()

			// Reset body reader for signing
			if tt.body != "" {
				bodyReader = strings.NewReader(tt.body)
				req.Body = io.NopCloser(bodyReader)
				req.ContentLength = int64(len(tt.body))
			}

			err = signer.SignHTTP(context.Background(), creds, req, tt.payloadHash, "s3", region, fixedTime)
			if err != nil {
				t.Fatalf("failed to sign request: %v", err)
			}

			// Ensure Content-Length is preserved after signing (AWS SDK may modify it)
			if tt.body != "" && req.ContentLength == 0 {
				req.ContentLength = int64(len(tt.body))
			}

			// Verify using our library
			verifier := &s3validate.Verifier{
				Credentials: testutil.StaticCredentials{accessKey: secretKey},
				Now: func() time.Time {
					return fixedTime
				},
			}

			// Reset body reader for verification
			if tt.body != "" {
				req.Body = io.NopCloser(strings.NewReader(tt.body))
			}

			result, err := verifier.Verify(context.Background(), req)
			if err != nil {
				t.Fatalf("verification failed: %v", err)
			}

			// Validate result
			if result.AccessKey != accessKey {
				t.Errorf("expected access key %s, got %s", accessKey, result.AccessKey)
			}
			if result.ScopeRegion != region {
				t.Errorf("expected region %s, got %s", region, result.ScopeRegion)
			}
			if result.SignatureSource != s3validate.SignatureSourceHeader {
				t.Errorf("expected signature source header, got %v", result.SignatureSource)
			}

			t.Logf("✓ Successfully verified AWS SDK signed request")
		})
	}
}

// TestAWSSDKPresignedURL tests that presigned URLs generated by AWS SDK
// can be verified by our library.
func TestAWSSDKPresignedURL(t *testing.T) {
	accessKey := "AKIAIOSFODNN7EXAMPLE"
	secretKey := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	region := "us-east-1"

	fixedTime := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		method  string
		url     string
		expires time.Duration
	}{
		{
			name:    "GET presigned URL - 1 hour expiry",
			method:  "GET",
			url:     "https://examplebucket.s3.amazonaws.com/test.txt",
			expires: 1 * time.Hour,
		},
		{
			name:    "GET presigned URL - 24 hours expiry",
			method:  "GET",
			url:     "https://examplebucket.s3.amazonaws.com/document.pdf",
			expires: 24 * time.Hour,
		},
		{
			name:    "PUT presigned URL",
			method:  "PUT",
			url:     "https://examplebucket.s3.amazonaws.com/upload.txt",
			expires: 15 * time.Minute,
		},
		{
			name:    "GET presigned URL with trailing slash",
			method:  "GET",
			url:     "https://examplebucket.s3.amazonaws.com/folder/",
			expires: 1 * time.Hour,
		},
		{
			name:    "GET presigned URL without trailing slash",
			method:  "GET",
			url:     "https://examplebucket.s3.amazonaws.com/folder",
			expires: 1 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create initial request
			req, err := http.NewRequest(tt.method, tt.url, nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			// Create presigned URL using AWS SDK
			creds := aws.Credentials{
				AccessKeyID:     accessKey,
				SecretAccessKey: secretKey,
			}
			signer := v4.NewSigner()

			presignedURL, _, err := signer.PresignHTTP(
				context.Background(),
				creds,
				req,
				"UNSIGNED-PAYLOAD",
				"s3",
				region,
				fixedTime,
			)
			if err != nil {
				t.Fatalf("failed to presign request: %v", err)
			}

			t.Logf("Presigned URL: %s", presignedURL)

			// Create new request with presigned URL
			verifyReq, err := http.NewRequest(tt.method, presignedURL, nil)
			if err != nil {
				t.Fatalf("failed to create verify request: %v", err)
			}
			verifyReq.Host = verifyReq.URL.Host

			// Verify using our library
			verifier := &s3validate.Verifier{
				Credentials: testutil.StaticCredentials{accessKey: secretKey},
				Now: func() time.Time {
					return fixedTime
				},
			}

			result, err := verifier.Verify(context.Background(), verifyReq)
			if err != nil {
				t.Logf("Presigned URL: %s", presignedURL)
				t.Logf("Query params: %+v", verifyReq.URL.Query())
				t.Fatalf("verification failed: %v", err)
			}

			// Validate result
			if result.AccessKey != accessKey {
				t.Errorf("expected access key %s, got %s", accessKey, result.AccessKey)
			}
			if result.ScopeRegion != region {
				t.Errorf("expected region %s, got %s", region, result.ScopeRegion)
			}
			if result.SignatureSource != s3validate.SignatureSourceQuery {
				t.Errorf("expected signature source query, got %v", result.SignatureSource)
			}

			t.Logf("✓ Successfully verified AWS SDK presigned URL")
		})
	}
}

// TestAWSSDKAndLocalVerifierClockSkew verifies clock skew handling
func TestAWSSDKAndLocalVerifierClockSkew(t *testing.T) {
	accessKey := "AKIAIOSFODNN7EXAMPLE"
	secretKey := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	region := "us-east-1"

	signTime := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)

	// Sign request at signTime
	req, err := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Host = req.URL.Host

	// Set X-Amz-Content-Sha256 header for consistency with AWS SDK behavior
	req.Header.Set("X-Amz-Content-Sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

	creds := aws.Credentials{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
	}
	signer := v4.NewSigner()
	err = signer.SignHTTP(context.Background(), creds, req, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "s3", region, signTime)
	if err != nil {
		t.Fatalf("failed to sign request: %v", err)
	}

	tests := []struct {
		name      string
		verifyAt  time.Time
		shouldErr bool
	}{
		{
			name:      "Same time - should pass",
			verifyAt:  signTime,
			shouldErr: false,
		},
		{
			name:      "4 minutes later - should pass",
			verifyAt:  signTime.Add(4 * time.Minute),
			shouldErr: false,
		},
		{
			name:      "6 minutes later - should fail",
			verifyAt:  signTime.Add(6 * time.Minute),
			shouldErr: true,
		},
		{
			name:      "4 minutes earlier - should pass",
			verifyAt:  signTime.Add(-4 * time.Minute),
			shouldErr: false,
		},
		{
			name:      "6 minutes earlier - should fail",
			verifyAt:  signTime.Add(-6 * time.Minute),
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := &s3validate.Verifier{
				Credentials: testutil.StaticCredentials{accessKey: secretKey},
				Now: func() time.Time {
					return tt.verifyAt
				},
			}

			_, err := verifier.Verify(context.Background(), req)
			if tt.shouldErr && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
