package s3validate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// buildCanonicalRequestHash builds and hashes the canonical request.
func buildCanonicalRequestHash(r *http.Request, signedHeaders []string, payloadHash string, source SignatureSource) (string, []string, error) {
	canonicalURI := canonicalizeURI(r.URL.Path)
	canonicalQuery := canonicalizeQuery(r.URL.RawQuery, source)
	canonicalHeaders, err := canonicalizeHeaders(r, signedHeaders)
	if err != nil {
		return "", nil, err
	}
	canonical := strings.Join([]string{
		r.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders.CanonicalHeaders,
		canonicalHeaders.SignedHeaders,
		payloadHash,
	}, "\n")

	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:]), canonicalHeaders.SignedHeadersList, nil
}

// canonicalizeHeaders creates the canonical headers string.
func canonicalizeHeaders(r *http.Request, signedHeaders []string) (headerCanonicalization, error) {
	lowerSigned := make([]string, len(signedHeaders))
	for i, h := range signedHeaders {
		lowerSigned[i] = strings.ToLower(strings.TrimSpace(h))
	}
	sort.Strings(lowerSigned)

	headerMap := make(map[string][]string)
	for key, values := range r.Header {
		lowerKey := strings.ToLower(key)
		headerMap[lowerKey] = append([]string{}, values...)
	}
	if host := r.Host; host != "" {
		headerMap["host"] = []string{host}
	}
	// Content-Length is a special case - it's not in r.Header but in r.ContentLength
	if r.ContentLength > 0 {
		headerMap["content-length"] = []string{strconv.FormatInt(r.ContentLength, 10)}
	}

	var builder strings.Builder

	for _, header := range lowerSigned {
		values, ok := headerMap[header]
		if !ok {
			return headerCanonicalization{}, fmt.Errorf("s3validate: missing signed header %q", header)
		}
		cleaned := canonicalizeHeaderValues(values)
		builder.WriteString(header)
		builder.WriteString(":")
		builder.WriteString(strings.Join(cleaned, ","))
		builder.WriteString("\n")
	}

	return headerCanonicalization{
		CanonicalHeaders:  builder.String(),
		SignedHeaders:     strings.Join(lowerSigned, ";"),
		SignedHeadersList: lowerSigned,
	}, nil
}

// canonicalizeHeaderValues normalizes header values per AWS spec.
func canonicalizeHeaderValues(values []string) []string {
	cleaned := make([]string, len(values))
	for i, v := range values {
		v = strings.TrimSpace(v)
		v = strings.Join(strings.Fields(v), " ")
		cleaned[i] = v
	}
	sort.Strings(cleaned)
	return cleaned
}

// canonicalizeQuery creates the canonical query string.
func canonicalizeQuery(rawQuery string, source SignatureSource) string {
	if rawQuery == "" {
		return ""
	}
	values, _ := url.ParseQuery(rawQuery)

	type pair struct{ key, value string }
	var items []pair
	for key, vals := range values {
		if source == SignatureSourceQuery && strings.EqualFold(key, "X-Amz-Signature") {
			continue
		}
		encKey := uriEncode(key, true)
		for _, v := range vals {
			items = append(items, pair{encKey, uriEncode(v, true)})
		}
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].key == items[j].key {
			return items[i].value < items[j].value
		}
		return items[i].key < items[j].key
	})

	var builder strings.Builder
	for i, item := range items {
		if i > 0 {
			builder.WriteString("&")
		}
		builder.WriteString(item.key)
		builder.WriteString("=")
		builder.WriteString(item.value)
	}
	return builder.String()
}

// canonicalizeURI normalizes the URI path per AWS spec.
func canonicalizeURI(path string) string {
	if path == "" {
		return "/"
	}
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		segments[i] = uriEncode(segment, true)
	}
	// strings.Split preserves trailing slash as an empty last element,
	// so strings.Join will automatically restore it. No need to add it back.
	return strings.Join(segments, "/")
}

// uriEncode encodes a string per AWS SigV4 URI encoding rules.
func uriEncode(s string, encodeSlash bool) string {
	var builder strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			builder.WriteByte(c)
			continue
		}
		if c == '/' && !encodeSlash {
			builder.WriteByte('/')
			continue
		}
		builder.WriteString(fmt.Sprintf("%%%02X", c))
	}
	return builder.String()
}