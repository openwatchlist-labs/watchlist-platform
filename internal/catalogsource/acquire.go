package catalogsource

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var ErrInvalidSource = errors.New("invalid catalog source")

const DefaultMaxBytes int64 = 768 << 20

var approvedHosts = map[string]struct{}{
	"sanctionslistservice.ofac.treas.gov": {},
	"sanctionslist.ofac.treas.gov":        {},
	"ofac.treasury.gov":                   {},
	"www.treasury.gov":                    {},
	"data.opensanctions.org":              {},
	"delivery.opensanctions.com":          {},
}

type AcquireOptions struct {
	AcquiredAt  time.Time
	MaxBytes    int64
	Accept      string
	BearerToken string
	UserAgent   string
}

func AcquireLocal(path, sourceURL, mediaType string, options AcquireOptions) (Acquired, error) {
	file, err := os.Open(path)
	if err != nil {
		return Acquired{}, fmt.Errorf("%w: open local source: %v", ErrInvalidSource, err)
	}
	defer file.Close()
	data, err := readBounded(file, maxBytes(options.MaxBytes))
	if err != nil {
		return Acquired{}, err
	}
	if strings.TrimSpace(sourceURL) == "" {
		sourceURL = "fixture:" + path
	}
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	return makeAcquired(data, sourceURL, AcquisitionLocal, mediaType, "", "", options.AcquiredAt), nil
}

func AcquireHTTPS(ctx context.Context, rawURL string, options AcquireOptions) (Acquired, error) {
	u, err := ValidateURL(rawURL)
	if err != nil {
		return Acquired{}, err
	}
	client := &http.Client{
		Timeout: 5 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 {
				return fmt.Errorf("%w: too many redirects", ErrInvalidSource)
			}
			_, err := ValidateURL(req.URL.String())
			return err
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Acquired{}, fmt.Errorf("%w: create request: %v", ErrInvalidSource, err)
	}
	if options.Accept != "" {
		req.Header.Set("Accept", options.Accept)
	}
	if options.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+options.BearerToken)
	}
	userAgent := options.UserAgent
	if userAgent == "" {
		userAgent = "openwatchlist-platform/catalog-source-acquirer-v0.1"
	}
	req.Header.Set("User-Agent", userAgent)
	response, err := client.Do(req)
	if err != nil {
		return Acquired{}, fmt.Errorf("%w: download: %v", ErrInvalidSource, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Acquired{}, fmt.Errorf("%w: HTTP status %s", ErrInvalidSource, response.Status)
	}
	data, err := readBounded(response.Body, maxBytes(options.MaxBytes))
	if err != nil {
		return Acquired{}, err
	}
	mediaType := response.Header.Get("Content-Type")
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	return makeAcquired(data, response.Request.URL.String(), AcquisitionHTTPS, mediaType, response.Header.Get("ETag"), response.Header.Get("Last-Modified"), options.AcquiredAt), nil
}

func ValidateURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: parse URL: %v", ErrInvalidSource, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("%w: source URL must use https", ErrInvalidSource)
	}
	if _, ok := approvedHosts[strings.ToLower(u.Hostname())]; !ok {
		return nil, fmt.Errorf("%w: host %q is not approved", ErrInvalidSource, u.Hostname())
	}
	if u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("%w: credentials and fragments are prohibited", ErrInvalidSource)
	}
	return u, nil
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	var buffer bytes.Buffer
	count, err := io.Copy(&buffer, io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read source: %v", ErrInvalidSource, err)
	}
	if count > limit {
		return nil, fmt.Errorf("%w: source exceeds %d bytes", ErrInvalidSource, limit)
	}
	if count == 0 {
		return nil, fmt.Errorf("%w: empty source", ErrInvalidSource)
	}
	return buffer.Bytes(), nil
}

func makeAcquired(data []byte, sourceURL string, method AcquisitionMethod, mediaType, etag, lastModified string, acquiredAt time.Time) Acquired {
	if acquiredAt.IsZero() {
		acquiredAt = time.Now().UTC()
	} else {
		acquiredAt = acquiredAt.UTC()
	}
	sum := sha256.Sum256(data)
	return Acquired{Bytes: data, SourceURL: sourceURL, Method: method, MediaType: mediaType, ETag: etag, LastModified: lastModified, AcquiredAt: acquiredAt, ContentSHA256: hex.EncodeToString(sum[:]), ContentLength: int64(len(data))}
}

func maxBytes(value int64) int64 {
	if value <= 0 {
		return DefaultMaxBytes
	}
	return value
}

func VerifyUpstreamChecksum(data []byte, algorithm, expected string) error {
	algorithm = strings.ToLower(strings.TrimSpace(algorithm))
	expected = strings.ToLower(strings.TrimSpace(expected))
	if expected == "" {
		return nil
	}
	var actual string
	switch algorithm {
	case "sha256":
		sum := sha256.Sum256(data)
		actual = hex.EncodeToString(sum[:])
	case "sha1":
		sum := sha1.Sum(data)
		actual = hex.EncodeToString(sum[:])
	default:
		return fmt.Errorf("%w: unsupported upstream checksum algorithm %q", ErrInvalidSource, algorithm)
	}
	if actual != expected {
		return fmt.Errorf("%w: upstream %s checksum mismatch: expected %s got %s", ErrInvalidSource, algorithm, expected, actual)
	}
	return nil
}
