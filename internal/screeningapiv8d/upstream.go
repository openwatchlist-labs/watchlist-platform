package screeningapiv8d

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Upstream interface {
	Post(ctx context.Context, path string, body []byte, correlationID, idempotencyKey string) (int, []byte, error)
	Ready(ctx context.Context) error
}

type HTTPUpstream struct {
	baseURL string
	client  *http.Client
}

func NewHTTPUpstream(baseURL string, client *http.Client) *HTTPUpstream {
	return &HTTPUpstream{baseURL: strings.TrimRight(baseURL, "/"), client: client}
}

func (u *HTTPUpstream) Post(ctx context.Context, path string, body []byte, correlationID, idempotencyKey string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, fmt.Errorf("build Phase 8B request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Correlation-ID", correlationID)
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("call Phase 8B screening API: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("read Phase 8B response: %w", err)
	}
	return resp.StatusCode, raw, nil
}

func (u *HTTPUpstream) Ready(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.baseURL+"/readyz", nil)
	if err != nil {
		return err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Phase 8B readiness returned HTTP %d", resp.StatusCode)
	}
	return nil
}
