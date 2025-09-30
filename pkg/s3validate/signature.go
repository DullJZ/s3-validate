package s3validate

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// extractSignatureData extracts signature components from the request.
func extractSignatureData(r *http.Request) (SignatureSource, signatureData, error) {
	if auth := r.Header.Get("Authorization"); auth != "" {
		data, err := parseAuthorizationHeader(auth)
		if err != nil {
			return SignatureSourceHeader, signatureData{}, err
		}
		data.source = SignatureSourceHeader
		data.PayloadHash = payloadHashFromHeader(r, data.SignedHeaders)
		data.AmzDate = headerOrSingle(r.Header, "x-amz-date")
		if data.AmzDate == "" {
			return SignatureSourceHeader, signatureData{}, errors.New("s3validate: missing X-Amz-Date header")
		}
		return SignatureSourceHeader, data, nil
	}

	if sig := r.URL.Query().Get("X-Amz-Signature"); sig != "" {
		data, err := parsePresignQuery(r.URL)
		if err != nil {
			return SignatureSourceQuery, signatureData{}, err
		}
		data.source = SignatureSourceQuery
		return SignatureSourceQuery, data, nil
	}

	return SignatureSourceHeader, signatureData{}, errors.New("s3validate: no signature found")
}

// parseAuthorizationHeader parses the Authorization header for signature components.
func parseAuthorizationHeader(header string) (signatureData, error) {
	if !strings.HasPrefix(header, Algorithm+" ") {
		return signatureData{}, errors.New("s3validate: unsupported authorization algorithm")
	}

	segments := strings.Split(header[len(Algorithm)+1:], ",")
	data := signatureData{}

	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		kv := strings.SplitN(segment, "=", 2)
		if len(kv) != 2 {
			return signatureData{}, fmt.Errorf("s3validate: malformed authorization component %q", segment)
		}
		key := kv[0]
		value := strings.Trim(kv[1], "\"")
		switch key {
		case "Credential":
			data.Credential = value
		case "SignedHeaders":
			if value == "" {
				return signatureData{}, errors.New("s3validate: empty SignedHeaders")
			}
			data.SignedHeaders = strings.Split(value, ";")
		case "Signature":
			data.Signature = value
		}
	}

	if data.Credential == "" || len(data.SignedHeaders) == 0 || data.Signature == "" {
		return signatureData{}, errors.New("s3validate: missing fields in authorization header")
	}
	sigBytes, err := hex.DecodeString(data.Signature)
	if err != nil {
		return signatureData{}, fmt.Errorf("s3validate: invalid signature encoding: %w", err)
	}
	data.SignatureBytes = sigBytes
	return data, nil
}

// parsePresignQuery parses signature components from presigned URL query parameters.
func parsePresignQuery(u *url.URL) (signatureData, error) {
	q := u.Query()
	cred := q.Get("X-Amz-Credential")
	if cred == "" {
		return signatureData{}, errors.New("s3validate: missing X-Amz-Credential")
	}
	signedHeaders := q.Get("X-Amz-SignedHeaders")
	if signedHeaders == "" {
		return signatureData{}, errors.New("s3validate: missing X-Amz-SignedHeaders")
	}
	sig := q.Get("X-Amz-Signature")
	if sig == "" {
		return signatureData{}, errors.New("s3validate: missing X-Amz-Signature")
	}
	amzDate := q.Get("X-Amz-Date")
	if amzDate == "" {
		return signatureData{}, errors.New("s3validate: missing X-Amz-Date")
	}

	sigBytes, err := hex.DecodeString(sig)
	if err != nil {
		return signatureData{}, fmt.Errorf("s3validate: invalid signature encoding: %w", err)
	}

	payloadHash := q.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		payloadHash = "UNSIGNED-PAYLOAD"
	}

	return signatureData{
		Credential:     cred,
		SignedHeaders:  strings.Split(signedHeaders, ";"),
		Signature:      sig,
		SignatureBytes: sigBytes,
		PayloadHash:    payloadHash,
		AmzDate:        amzDate,
		Expires:        q.Get("X-Amz-Expires"),
	}, nil
}

// parseCredentialScope parses the credential string into its components.
func parseCredentialScope(credential string) (accessKey, date, region, svc, term string, err error) {
	parts := strings.Split(credential, "/")
	if len(parts) != 5 {
		return "", "", "", "", "", fmt.Errorf("s3validate: invalid credential scope %q", credential)
	}
	return parts[0], parts[1], parts[2], parts[3], parts[4], nil
}

// headerOrSingle returns a header value, joining multiple values with commas.
func headerOrSingle(h http.Header, key string) string {
	values := h.Values(key)
	if len(values) == 0 {
		return ""
	}
	if len(values) > 1 {
		// Multiple headers are concatenated with commas per SigV4 docs.
		return strings.Join(values, ",")
	}
	return values[0]
}

// payloadHashFromHeader extracts the payload hash from headers if signed.
func payloadHashFromHeader(r *http.Request, signedHeaders []string) string {
	// x-amz-content-sha256 must be part of signed headers for SDKs.
	for _, h := range signedHeaders {
		if strings.EqualFold(h, "x-amz-content-sha256") {
			return headerOrSingle(r.Header, "x-amz-content-sha256")
		}
	}
	return "UNSIGNED-PAYLOAD"
}

// buildStringToSign constructs the string that will be signed.
func buildStringToSign(amzDate, credScope, canonicalHash string) string {
	return strings.Join([]string{
		Algorithm,
		amzDate,
		credScope,
		canonicalHash,
	}, "\n")
}

// deriveSigningKey derives the signing key from the secret and scope components.
func deriveSigningKey(secret, scopeDate, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), scopeDate)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	return kSigning
}

// hmacSHA256 computes HMAC-SHA256 of data using the given key.
func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}