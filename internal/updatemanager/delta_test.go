package updatemanager

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogrefresh"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacsource"
)

func TestPrepareDeltaPromotionAndForceFull(t *testing.T) {
	base := deltaCatalog(t, "../../test/fixtures/catalog-refresh/sdn-delta-base.xml", "fixture:delta-base", 0)
	small := deltaCatalog(t, "../../test/fixtures/catalog-refresh/sdn-delta-small.xml", "fixture:delta-small", time.Minute)
	large := deltaCatalog(t, "../../test/fixtures/catalog-refresh/sdn-delta-large.xml", "fixture:delta-large", 2*time.Minute)
	policyData, err := os.ReadFile("../../test/fixtures/catalog-refresh/promotion-policy-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var policy catalogrefresh.PromotionPolicy
	if err = json.Unmarshal(policyData, &policy); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 7, 13, 20, 0, 0, 0, time.UTC)
	smallDelta, err := catalogrefresh.BuildDelta(base, small, 1, at)
	if err != nil {
		t.Fatal(err)
	}
	largeDelta, err := catalogrefresh.BuildDelta(base, large, 1, at)
	if err != nil {
		t.Fatal(err)
	}
	workers := []string{"worker-a"}
	manager := Manager{StateDir: t.TempDir(), ArchiveDir: t.TempDir(), Workers: []Worker{NewMemoryWorker("worker-a", "zone-a", true)}}

	spec, err := NewSpec("", "delta:"+smallDelta.DeltaID, at, at.Add(-time.Minute), workers, workers)
	if err != nil {
		t.Fatal(err)
	}
	record, artifact, decision, err := manager.PrepareDelta(spec, base, smallDelta, policy, 1, &small, at, at)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != StatusCompiled || decision.Outcome != catalogrefresh.OutcomePromoteDelta || len(artifact) == 0 || record.Staged == nil || record.Staged.Promotion == nil {
		t.Fatalf("unexpected promoted record: %#v", record)
	}
	for _, path := range []string{record.Staged.DeltaPath, record.Staged.PackagePath, filepath.Join(manager.StateDir, "promotion-decisions", decision.DecisionID+".json")} {
		if _, err = os.Stat(path); err != nil {
			t.Fatalf("missing persisted artifact %s: %v", path, err)
		}
	}

	largeSpec, err := NewSpec("", "delta:"+largeDelta.DeltaID, at.Add(time.Hour), at, workers, workers)
	if err != nil {
		t.Fatal(err)
	}
	largeRecord, artifact, largeDecision, err := manager.PrepareDelta(largeSpec, base, largeDelta, policy, 1, &large, at.Add(time.Hour), at.Add(time.Hour))
	if !errors.Is(err, ErrFullRebuildRequired) {
		t.Fatalf("expected full rebuild error, got %v", err)
	}
	if largeRecord.Status != StatusFullRebuildRequired || largeDecision.Outcome != catalogrefresh.OutcomeForceFull || len(artifact) != 0 {
		t.Fatalf("unexpected force-full result: %#v", largeRecord)
	}
}

func deltaCatalog(t *testing.T, path, sourceURL string, offset time.Duration) ofaccatalog.Catalog {
	t.Helper()
	at := time.Date(2026, 7, 13, 20, 0, 0, 0, time.UTC).Add(offset)
	acquired, err := ofacsource.AcquireLocal(path, sourceURL, at)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := ofacsource.Parse(acquired)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := ofaccatalog.Project(pkg)
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}
