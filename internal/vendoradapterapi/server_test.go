package vendoradapterapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/reviewauth"
	"github.com/openwatchlist-labs/watchlist-platform/internal/tenantctx"
)

// TestAPIReadinessAndReplay exercises the raw, unauthenticated s.Handler()
// directly to cover ingest+replay mechanics independent of auth (ADR-0006
// D1 wraps this mux in AuthenticatedHandler for real serving; auth_test.go
// covers that layer). Since D3 requires a bound tenant ahead of every write
// regardless of caller, the request context here is bound to tenant-a
// directly -- generic-json-v1's declared constants.tenant_id -- rather than
// going through a minted token, to keep this test's scope on replay
// mechanics rather than authentication.
func TestAPIReadinessAndReplay(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	cfg := Config{ListenAddress: "127.0.0.1:0", ProfilesDirectory: filepath.Join(root, "configs", "vendor-adapters"), StateDirectory: t.TempDir(), StreamID: "test", MaxBodyBytes: 4 << 20}
	s, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	bound, e := tenantctx.Resolve(reviewauth.Claims{TenantID: "tenant-a"})
	if e != nil {
		t.Fatal(e)
	}
	handler := s.Handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r.WithContext(tenantctx.NewContext(r.Context(), bound)))
	}))
	defer ts.Close()
	resp, e := http.Get(ts.URL + "/readyz")
	if e != nil || resp.StatusCode != 200 {
		t.Fatalf("ready %v %v", resp, e)
	}
	raw, _ := os.ReadFile(filepath.Join(root, "test", "fixtures", "vendor-adapters", "generic-alert.json"))
	for i, code := range []int{201, 200} {
		req, _ := http.NewRequest("POST", ts.URL+"/v1/vendor-alerts/generic-json-v1", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		r, e := http.DefaultClient.Do(req)
		if e != nil || r.StatusCode != code {
			t.Fatalf("run %d status=%v err=%v", i, r.StatusCode, e)
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		r.Body.Close()
		if _, ok := body["envelope"]; !ok {
			t.Fatal("missing envelope")
		}
	}
}
