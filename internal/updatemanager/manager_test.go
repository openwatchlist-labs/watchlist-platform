package updatemanager

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacsource"
)

func TestScheduledCanaryActivationAndRollback(t *testing.T) {
	root := t.TempDir()
	fixture := filepath.Join("..", "..", "test", "fixtures", "ofac", "sdn", "sdn-fixture.xml")
	fixture2 := filepath.Join("..", "..", "test", "fixtures", "ofac", "sdn", "sdn-fixture-v2.xml")
	workers := []Worker{NewMemoryWorker("worker-a", "us-east-1a", true), NewMemoryWorker("worker-b", "us-east-1b", true), NewMemoryWorker("worker-c", "us-east-1c", true)}
	m := Manager{StateDir: filepath.Join(root, "state"), ArchiveDir: filepath.Join(root, "archive"), Workers: workers}
	requested := time.Date(2026, 7, 13, 18, 0, 0, 0, time.UTC)
	scheduled := requested.Add(time.Hour)
	spec, err := NewSpec(fixture, "fixture:sdn-v1", scheduled, requested, []string{"worker-a"}, []string{"worker-a", "worker-b", "worker-c"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = m.Prepare(context.Background(), spec, scheduled.Add(-time.Second), scheduled); !errors.Is(err, ErrNotDue) {
		t.Fatalf("expected ErrNotDue, got %v", err)
	}
	update1, artifact1, err := m.Prepare(context.Background(), spec, scheduled, scheduled)
	if err != nil {
		t.Fatal(err)
	}
	activation1, err := m.Activate(context.Background(), update1, artifact1, scheduled.Add(time.Minute), scheduled.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if activation1.FleetEpoch != 1 || len(activation1.ActivationAcks) != 3 || activation1.ActivationAcks[0].Worker.WorkerID != "worker-a" {
		t.Fatalf("unexpected activation %#v", activation1)
	}
	spec2, err := NewSpec(fixture2, "fixture:sdn-v2", scheduled.Add(2*time.Hour), requested, []string{"worker-b"}, spec.RequiredWorkers)
	if err != nil {
		t.Fatal(err)
	}
	update2, artifact2, err := m.Prepare(context.Background(), spec2, spec2.ScheduledFor, spec2.ScheduledFor)
	if err != nil {
		t.Fatal(err)
	}
	activation2, err := m.Activate(context.Background(), update2, artifact2, spec2.ScheduledFor.Add(time.Minute), spec2.ScheduledFor.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if activation2.FleetEpoch != 2 {
		t.Fatalf("epoch=%d", activation2.FleetEpoch)
	}
	rollback, err := m.Rollback(context.Background(), activation2, update1, artifact1, "canary quality regression", spec2.ScheduledFor.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if rollback.FleetEpoch != 3 || rollback.ToPackageID != update1.Staged.PackageInfo.PackageID {
		t.Fatalf("bad rollback %#v", rollback)
	}
	pointer, err := (Store{Root: m.StateDir}).Active()
	if err != nil {
		t.Fatal(err)
	}
	if pointer.FleetEpoch != 3 || pointer.PackageID != update1.Staged.PackageInfo.PackageID {
		t.Fatalf("bad pointer %#v", pointer)
	}
	if err = ValidateAuditHistory(m.Audit); err != nil {
		t.Fatal(err)
	}
	if len(m.Audit.Events) < 15 {
		t.Fatalf("audit events=%d", len(m.Audit.Events))
	}
	if _, err = os.Stat(filepath.Join(m.StateDir, "fleet-activations", activation1.ActivationID+".json")); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(m.StateDir, "fleet-rollbacks", rollback.RollbackID+".json")); err != nil {
		t.Fatal(err)
	}
	_ = artifact2
	_ = ofacsource.OfficialSDNXMLURL
}

func TestCanaryFailureDoesNotAdvanceFleetPointer(t *testing.T) {
	root := t.TempDir()
	fixture := filepath.Join("..", "..", "test", "fixtures", "ofac", "sdn", "sdn-fixture.xml")
	bad := NewMemoryWorker("worker-a", "zone-a", true)
	bad.FailCanary = true
	m := Manager{StateDir: filepath.Join(root, "state"), ArchiveDir: filepath.Join(root, "archive"), Workers: []Worker{bad, NewMemoryWorker("worker-b", "zone-b", true)}}
	at := time.Date(2026, 7, 13, 20, 0, 0, 0, time.UTC)
	spec, _ := NewSpec(fixture, "fixture:sdn", at, at.Add(-time.Hour), []string{"worker-a"}, []string{"worker-a", "worker-b"})
	record, artifact, err := m.Prepare(context.Background(), spec, at, at)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := m.Activate(context.Background(), record, artifact, at.Add(time.Minute), at.Add(2*time.Minute))
	if !errors.Is(err, ErrCanaryFailed) {
		t.Fatalf("got %v", err)
	}
	if activation.State != FleetActivationFailed {
		t.Fatal("expected failed state")
	}
	pointer, _ := (Store{Root: m.StateDir}).Active()
	if pointer != nil {
		t.Fatalf("pointer advanced: %#v", pointer)
	}
}
