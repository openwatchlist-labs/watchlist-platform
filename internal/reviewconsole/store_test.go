package reviewconsole

import (
	"encoding/json"
	"github.com/openwatchlist-labs/watchlist-platform/internal/alertcase"
	"os"
	"path/filepath"
	"testing"
)

func TestTenantFilter(t *testing.T) {
	d := t.TempDir()
	for _, x := range []alertcase.CaseProjection{{CaseID: "a", TenantID: "tenant-a", UpdatedAt: "1"}, {CaseID: "b", TenantID: "tenant-b", UpdatedAt: "2"}} {
		p := filepath.Join(d, "cases", x.CaseID, "projection.json")
		os.MkdirAll(filepath.Dir(p), 0755)
		b, _ := json.Marshal(x)
		os.WriteFile(p, b, 0600)
	}
	x, e := ListCases(d, "tenant-a", CaseFilter{})
	if e != nil || len(x) != 1 || x[0].CaseID != "a" {
		t.Fatal(e, x)
	}
}
