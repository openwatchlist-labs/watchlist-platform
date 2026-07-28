package screeningapiv8f

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type upstream struct {
	baseURL string
	client  *http.Client
}

func newUpstream(baseURL string, client *http.Client) *upstream {
	return &upstream{baseURL: strings.TrimRight(baseURL, "/"), client: client}
}

func (u *upstream) post(ctx context.Context, path string, body []byte, correlationID, idempotencyKey string) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, u.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Correlation-ID", correlationID)
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	response, err := u.client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, nil, err
	}
	return response.StatusCode, raw, nil
}

func (u *upstream) ready(ctx context.Context, expectedActivationID string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.baseURL+"/readyz", nil)
	if err != nil {
		return err
	}
	response, err := u.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("backend readiness returned HTTP %d", response.StatusCode)
	}
	var document struct {
		Ready           bool `json:"ready"`
		ActivationTuple struct {
			ActivationID string `json:"activation_id"`
		} `json:"activation_tuple"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return fmt.Errorf("decode backend readiness: %w", err)
	}
	if !document.Ready {
		return fmt.Errorf("backend is not ready")
	}
	if document.ActivationTuple.ActivationID != expectedActivationID {
		return fmt.Errorf("backend activation mismatch: expected %q, found %q", expectedActivationID, document.ActivationTuple.ActivationID)
	}
	return nil
}
