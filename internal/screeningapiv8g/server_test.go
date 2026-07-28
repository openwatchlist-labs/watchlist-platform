package screeningapiv8g

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningledger"
)

type apiCaptureRunner struct{ calls int }

func (r *apiCaptureRunner) Run(_ context.Context, _ string, _ []string, _ []byte) ([]byte, error) {
	r.calls++
	return []byte("1\n"), nil
}

func TestDurableBeforeDeliveryAndIdempotency(t *testing.T) {
	upstreamBody := []byte(`{"request_id":"req-8g","activation_tuple":{"activation_id":"activation-phase8f","catalog_package_sha256":"cat","projection_package_sha256":"proj","scoring_policy_sha256":"policy","normalization_profile":"unicode-upper-alnum-space-v1"},"promotion":{"intent_id":"promotion-phase8f","phase":"promoted"},"candidates":[{"candidate_id":"cand-1","score":905,"band":"high_similarity","reason_codes":["name_exact"]}],"blockers":[]}`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/readyz" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ready":true}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upstreamBody)
	}))
	defer upstream.Close()

	keyPath := filepath.Join(t.TempDir(), "key.hex")
	key := bytes.Repeat([]byte{0x31}, 32)
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := Config{
		ListenAddress: "127.0.0.1:0", UpstreamBaseURL: upstream.URL,
		LedgerDirectory: filepath.Join(t.TempDir(), "ledger"), IdempotencyDirectory: filepath.Join(t.TempDir(), "idempotency"),
		InstanceID: "api-v8g-test", SnapshotKeyFile: keyPath, MaxBodyBytes: 2 * 1024 * 1024, RequestTimeoutMillis: 3000,
		Retention:   screeningledger.RetentionPolicy{Class: "screening-standard", RetentionDays: 2555, MaxSnapshotBytes: 2 * 1024 * 1024},
		PostgresDSN: "postgres://fixture", RequirePostgres: true,
	}
	server, err := NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	runner := &apiCaptureRunner{}
	server.postgres, err = screeningledger.NewPostgresSink(config.PostgresDSN, "psql", runner, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	requestBody := []byte(`{"request_id":"req-8g","name":"ALICE EXAMPLE"}`)
	perform := func(body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/screenings", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Correlation-ID", "corr-8g")
		req.Header.Set("Idempotency-Key", "idem-8g")
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, req)
		return recorder
	}
	first := perform(requestBody)
	if first.Code != http.StatusOK {
		t.Fatalf("first response %d: %s", first.Code, first.Body.String())
	}
	if !bytes.Equal(first.Body.Bytes(), upstreamBody) {
		t.Fatal("front door changed upstream response bytes")
	}
	if first.Header().Get("X-Screening-Ledger-Event-ID") == "" || first.Header().Get("X-Screening-Ledger-Event-SHA256") == "" {
		t.Fatal("missing ledger headers")
	}
	if first.Header().Get("X-Screening-Ledger-Postgres") != "persisted" || runner.calls == 0 {
		t.Fatal("response returned before PostgreSQL persistence")
	}

	replay := perform(requestBody)
	if replay.Code != http.StatusOK || replay.Header().Get("Idempotent-Replay") != "true" {
		t.Fatalf("idempotent replay failed: %d %s", replay.Code, replay.Body.String())
	}
	if replay.Header().Get("X-Screening-Ledger-Event-ID") != first.Header().Get("X-Screening-Ledger-Event-ID") {
		t.Fatal("replay returned different event")
	}
	events, err := server.ledger.ListEvents()
	if err != nil || len(events) != 1 {
		t.Fatalf("expected one durable event, got %d, %v", len(events), err)
	}

	conflict := perform([]byte(`{"request_id":"req-8g","name":"DIFFERENT"}`))
	if conflict.Code != http.StatusConflict || !strings.Contains(conflict.Body.String(), "idempotency_key_reused") {
		t.Fatalf("expected 409 conflict: %d %s", conflict.Code, conflict.Body.String())
	}

	readyReq := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	ready := httptest.NewRecorder()
	server.Handler().ServeHTTP(ready, readyReq)
	if ready.Code != http.StatusOK {
		raw, _ := io.ReadAll(ready.Body)
		t.Fatalf("ready failed: %d %s", ready.Code, raw)
	}
}
