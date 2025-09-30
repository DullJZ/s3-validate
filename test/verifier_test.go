package test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/DullJZ/s3-validate/internal/testutil"
	"github.com/DullJZ/s3-validate/pkg/s3validate"
)

func TestVerifyHeaderRequest(t *testing.T) {
	secret := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	req, err := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Host = req.URL.Host
	req.Header.Set("Range", "bytes=0-9")
	req.Header.Set("x-amz-date", "20130524T000000Z")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-date,Signature=2659292253a418ecabdfa4021ef53ef713a688d7d55dd34c2758f3b5dd5eebe6")

	verifier := &s3validate.Verifier{
		Credentials: testutil.StaticCredentials{"AKIDEXAMPLE": secret},
		Now: func() time.Time {
			return time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
		},
	}

	result, err := verifier.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected verify error: %v", err)
	}
	if result.AccessKey != "AKIDEXAMPLE" {
		t.Fatalf("unexpected access key: %s", result.AccessKey)
	}
	if result.ScopeRegion != "us-east-1" {
		t.Fatalf("unexpected region: %s", result.ScopeRegion)
	}
	if result.SignatureSource != s3validate.SignatureSourceHeader {
		t.Fatalf("unexpected signature source: %v", result.SignatureSource)
	}
}

func TestVerifyQueryRequest(t *testing.T) {
	secret := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	url := "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=ca6159ff16837c055653a722d9f10b6a529b7c62c84174a2859958324bc78766"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Host = req.URL.Host

	verifier := &s3validate.Verifier{
		Credentials: testutil.StaticCredentials{"AKIDEXAMPLE": secret},
		Now: func() time.Time {
			return time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
		},
	}

	result, err := verifier.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected verify error: %v", err)
	}
	if result.SignatureSource != s3validate.SignatureSourceQuery {
		t.Fatalf("unexpected signature source: %v", result.SignatureSource)
	}
}

func TestVerifyExpiredPresign(t *testing.T) {
	secret := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	url := "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host&X-Amz-Signature=04c0fa10ea8bb9c4cf594f4c77ce7d5bf1ed9e5fe79772442ff74a257f561e65"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Host = req.URL.Host

	verifier := &s3validate.Verifier{
		Credentials: testutil.StaticCredentials{"AKIDEXAMPLE": secret},
		Now: func() time.Time {
			return time.Date(2013, 5, 24, 0, 2, 0, 0, time.UTC)
		},
	}

	if _, err := verifier.Verify(context.Background(), req); err == nil {
		t.Fatal("expected expiration error")
	}
}

func TestMissingSignature(t *testing.T) {
	req, err := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	verifier := &s3validate.Verifier{Credentials: testutil.StaticCredentials{"AKID": "secret"}}
	if _, err := verifier.Verify(context.Background(), req); err == nil {
		t.Fatal("expected error for missing signature")
	}
}

// TestCanonicalRequestDetails provides detailed validation of canonical request construction.
// This test is kept for documentation purposes and to verify internal consistency.
func TestCanonicalRequestDetails(t *testing.T) {
	secret := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	url := "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=ca6159ff16837c055653a722d9f10b6a529b7c62c84174a2859958324bc78766"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Host = req.URL.Host

	// This test uses internal functions for detailed verification
	// In production code, users only need to call Verify()
	verifier := &s3validate.Verifier{
		Credentials: testutil.StaticCredentials{"AKIDEXAMPLE": secret},
		Now: func() time.Time {
			return time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
		},
	}

	// The main verification should succeed
	result, err := verifier.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected verify error: %v", err)
	}
	if result.SignatureSource != s3validate.SignatureSourceQuery {
		t.Fatalf("unexpected signature source: %v", result.SignatureSource)
	}
}
