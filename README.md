# s3-validate

`s3-validate` is a tiny Golang package that helps services verify incoming Amazon S3 requests signed with Signature Version 4. It works with both header-based signatures and pre-signed URLs, making it suitable for APIs that need to authenticate uploads or downloads initiated by clients.

## Features

- ✅ Validates AWS Signature V4 for S3 REST requests
- ✅ Supports both Authorization headers and pre-signed query parameters
- ✅ Accepts custom credential providers so you can plug in key stores or databases
- ✅ Enforces configurable clock-skew limits and presigned URL expiration windows

## Installation

```bash
go get github.com/DullJZ/s3-validate/pkg/s3validate
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "net/http"

    "github.com/DullJZ/s3-validate/pkg/s3validate"
)

type memoryProvider map[string]string

func (m memoryProvider) SecretKey(ctx context.Context, accessKey string) (string, error) {
    key, ok := m[accessKey]
    if !ok {
        return "", fmt.Errorf("unknown access key %s", accessKey)
    }
    return key, nil
}

func main() {
    verifier := &s3validate.Verifier{
        Credentials: memoryProvider{
            "AKIDEXAMPLE": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        },
    }

    http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
        result, err := verifier.Verify(r.Context(), r)
        if err != nil {
            http.Error(w, err.Error(), http.StatusUnauthorized)
            return
        }

        // You can access the verified identity information
        log.Printf("Authenticated request from access key: %s, region: %s",
            result.AccessKey, result.ScopeRegion)

        w.WriteHeader(http.StatusOK)
    })

    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### Customising behaviour

- **Allowed clock skew** — override `Verifier.AllowedClockSkew` (defaults to 5 minutes).
- **Custom clock source** — set `Verifier.Now` for deterministic tests.

## Project Structure

```
pkg/s3validate/     - Core library code (import this)
internal/testutil/  - Internal test utilities
test/              - Comprehensive test suite
```

## Testing

The project includes two comprehensive test suites:

1. **Core verification tests** - Using fixtures from AWS documentation
2. **AWS SDK compatibility tests** - Validates 100% compatibility with AWS SDK v2

Run all tests:
```bash
go test ./...
```

All tests pass, confirming the library produces identical results to AWS official implementation.

## License

MIT
