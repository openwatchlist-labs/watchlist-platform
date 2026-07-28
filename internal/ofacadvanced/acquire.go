package ofacadvanced

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacsource"
)

const MaxSourceBytes int64 = 256 << 20

const officialOFACGovCloudHost = "wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com"

var ErrInvalidSource = errors.New("invalid OFAC Advanced XML source")

var allowedHosts = map[string]struct{}{
	"sanctionslistservice.ofac.treas.gov": {},
	"sanctionslist.ofac.treas.gov":        {},
	"ofac.treasury.gov":                   {},
	"www.treasury.gov":                    {},
	officialOFACGovCloudHost:              {},
}

func AcquireLocal(filePath, sourceURL string, acquiredAt time.Time) (Acquired, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return Acquired{}, fmt.Errorf("%w: open local source: %v", ErrInvalidSource, err)
	}
	defer f.Close()
	data, err := readBounded(f)
	if err != nil {
		return Acquired{}, err
	}
	if strings.TrimSpace(sourceURL) == "" {
		sourceURL = "fixture:" + filePath
	}
	return makeAcquired(data, sourceURL, ofacsource.AcquisitionLocal, "application/xml", "", "", acquiredAt), nil
}

func AcquireHTTP(ctx context.Context, rawURL string, acquiredAt time.Time) (Acquired, error) {
	u, err := validateOfficialURL(rawURL)
	if err != nil {
		return Acquired{}, err
	}
	client := &http.Client{
		Timeout: 120 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 {
				return fmt.Errorf("%w: too many redirects", ErrInvalidSource)
			}
			_, err := validateOfficialURL(req.URL.String())
			return err
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Acquired{}, fmt.Errorf("%w: create request: %v", ErrInvalidSource, err)
	}
	req.Header.Set("Accept", "application/xml,text/xml;q=0.9")
	req.Header.Set("User-Agent", "openwatchlist-platform/ofac-advanced-source-ingestor-v0.1.0")
	resp, err := client.Do(req)
	if err != nil {
		return Acquired{}, redactDownloadError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Acquired{}, fmt.Errorf("%w: HTTP status %s", ErrInvalidSource, resp.Status)
	}
	data, err := readBounded(resp.Body)
	if err != nil {
		return Acquired{}, err
	}
	media := resp.Header.Get("Content-Type")
	if media == "" {
		media = "application/xml"
	}
	// Preserve the stable SLS URL. The GovCloud redirect is signed and must not be persisted.
	return makeAcquired(data, u.String(), ofacsource.AcquisitionHTTP, media, resp.Header.Get("ETag"), resp.Header.Get("Last-Modified"), acquiredAt), nil
}

func validateOfficialURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: parse URL: %v", ErrInvalidSource, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("%w: source URL must use https", ErrInvalidSource)
	}
	host := strings.ToLower(u.Hostname())
	if _, ok := allowedHosts[host]; !ok {
		return nil, fmt.Errorf("%w: host %q is not approved", ErrInvalidSource, host)
	}
	if u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("%w: credentials and fragments are prohibited", ErrInvalidSource)
	}
	if host == officialOFACGovCloudHost {
		cleanPath := path.Clean(u.Path)
		if !strings.HasPrefix(cleanPath, "/Published/") || !strings.EqualFold(path.Base(cleanPath), "SDN_ADVANCED.XML") {
			return nil, fmt.Errorf("%w: GovCloud redirect path is not an OFAC SDN Advanced XML publication", ErrInvalidSource)
		}
	}
	return u, nil
}

func redactDownloadError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Errorf("%w: download %s: %v", ErrInvalidSource, redactURL(urlErr.URL), urlErr.Err)
	}
	return fmt.Errorf("%w: download: %v", ErrInvalidSource, err)
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[invalid-url]"
	}
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.User = nil
	return u.String()
}

func readBounded(r io.Reader) ([]byte, error) {
	var b bytes.Buffer
	n, err := io.Copy(&b, io.LimitReader(r, MaxSourceBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read: %v", ErrInvalidSource, err)
	}
	if n > MaxSourceBytes {
		return nil, fmt.Errorf("%w: source exceeds %d bytes", ErrInvalidSource, MaxSourceBytes)
	}
	if n == 0 {
		return nil, fmt.Errorf("%w: empty source", ErrInvalidSource)
	}
	return b.Bytes(), nil
}

func makeAcquired(data []byte, sourceURL string, method ofacsource.AcquisitionMethod, media, etag, last string, at time.Time) Acquired {
	if at.IsZero() {
		at = time.Now().UTC()
	} else {
		at = at.UTC()
	}
	sum := sha256.Sum256(data)
	return Acquired{
		Bytes: data, SourceURL: sourceURL, Method: method, MediaType: media,
		ETag: etag, LastModified: last, AcquiredAt: at,
		ContentSHA256: hex.EncodeToString(sum[:]), ContentLength: int64(len(data)),
	}
}
