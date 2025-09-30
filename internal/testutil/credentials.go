package testutil

import (
	"context"
	"fmt"
)

// StaticCredentials provides a simple in-memory credentials store for testing.
type StaticCredentials map[string]string

// SecretKey returns the secret key for the given access key.
func (s StaticCredentials) SecretKey(ctx context.Context, accessKey string) (string, error) {
	if key, ok := s[accessKey]; ok {
		return key, nil
	}
	return "", fmt.Errorf("unknown access key %s", accessKey)
}