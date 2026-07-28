package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/updatemanager"
)

type scenarioResult struct {
	SchemaVersion  string                                `json:"schema_version"`
	ManagerVersion string                                `json:"manager_version"`
	Updates        []updatemanager.UpdateRecord          `json:"updates"`
	Activations    []updatemanager.FleetActivationRecord `json:"activations"`
	Rollback       updatemanager.FleetRollbackRecord     `json:"rollback"`
	Active         updatemanager.FleetPointer            `json:"active"`
	Audit          updatemanager.AuditHistory            `json:"audit"`
}

func main() {
	command := flag.String("command", "simulate", "simulate or history")
	sourceV1 := flag.String("source-v1", "test/fixtures/ofac/sdn/sdn-fixture.xml", "first SDN XML source")
	sourceV2 := flag.String("source-v2", "test/fixtures/ofac/sdn/sdn-fixture-v2.xml", "second SDN XML source")
	stateDir := flag.String("state-dir", "/tmp/openwatchlist-phase2c-state", "update-manager state directory")
	archiveDir := flag.String("archive-dir", "/tmp/openwatchlist-phase2c-archive", "immutable source archive directory")
	workersRaw := flag.String("workers", "worker-a:zone-a,worker-b:zone-b,worker-c:zone-c", "comma-separated worker:zone entries")
	canaryV1 := flag.String("canary-v1", "worker-a", "first update canary worker")
	canaryV2 := flag.String("canary-v2", "worker-b", "second update canary worker")
	baseRaw := flag.String("base-time", "2026-07-13T18:00:00Z", "deterministic RFC3339 base time")
	compact := flag.Bool("compact", false, "compact JSON output")
	flag.Parse()
	if flag.NArg() != 0 {
		usage()
	}
	base, err := time.Parse(time.RFC3339, *baseRaw)
	check(err, "parse --base-time")
	workers, ids, err := parseWorkers(*workersRaw)
	check(err, "parse --workers")
	manager := updatemanager.Manager{StateDir: *stateDir, ArchiveDir: *archiveDir, Workers: workers}
	switch *command {
	case "simulate":
		result, err := simulate(context.Background(), &manager, *sourceV1, *sourceV2, *canaryV1, *canaryV2, ids, base)
		check(err, "simulate update protocol")
		encode(result, *compact)
	case "history":
		fmt.Fprintln(os.Stderr, "history is emitted by simulate; use persisted audit/*.json for independent inspection")
		os.Exit(2)
	default:
		usage()
	}
}

func simulate(ctx context.Context, m *updatemanager.Manager, sourceV1, sourceV2, canaryV1, canaryV2 string, workers []string, base time.Time) (scenarioResult, error) {
	spec1, err := updatemanager.NewSpec(sourceV1, "fixture:sdn-v1", base.Add(time.Hour), base, []string{canaryV1}, workers)
	if err != nil {
		return scenarioResult{}, err
	}
	update1, artifact1, err := m.Prepare(ctx, spec1, spec1.ScheduledFor, spec1.ScheduledFor)
	if err != nil {
		return scenarioResult{}, err
	}
	activation1, err := m.Activate(ctx, update1, artifact1, spec1.ScheduledFor.Add(time.Minute), spec1.ScheduledFor.Add(2*time.Minute))
	if err != nil {
		return scenarioResult{}, err
	}
	spec2, err := updatemanager.NewSpec(sourceV2, "fixture:sdn-v2", base.Add(3*time.Hour), base, []string{canaryV2}, workers)
	if err != nil {
		return scenarioResult{}, err
	}
	update2, artifact2, err := m.Prepare(ctx, spec2, spec2.ScheduledFor, spec2.ScheduledFor)
	if err != nil {
		return scenarioResult{}, err
	}
	activation2, err := m.Activate(ctx, update2, artifact2, spec2.ScheduledFor.Add(time.Minute), spec2.ScheduledFor.Add(2*time.Minute))
	if err != nil {
		return scenarioResult{}, err
	}
	rollback, err := m.Rollback(ctx, activation2, update1, artifact1, "fixture canary quality regression", base.Add(4*time.Hour))
	if err != nil {
		return scenarioResult{}, err
	}
	active, err := (updatemanager.Store{Root: m.StateDir}).Active()
	if err != nil {
		return scenarioResult{}, err
	}
	return scenarioResult{SchemaVersion: "distributed-update-replay/v1alpha1", ManagerVersion: updatemanager.ManagerVersion, Updates: []updatemanager.UpdateRecord{update1, update2}, Activations: []updatemanager.FleetActivationRecord{activation1, activation2}, Rollback: rollback, Active: *active, Audit: m.Audit}, nil
}

func parseWorkers(raw string) ([]updatemanager.Worker, []string, error) {
	var workers []updatemanager.Worker
	var ids []string
	for _, item := range strings.Split(raw, ",") {
		parts := strings.SplitN(strings.TrimSpace(item), ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, nil, fmt.Errorf("invalid worker %q", item)
		}
		workers = append(workers, updatemanager.NewMemoryWorker(parts[0], parts[1], true))
		ids = append(ids, parts[0])
	}
	if len(workers) == 0 {
		return nil, nil, fmt.Errorf("at least one worker is required")
	}
	return workers, ids, nil
}
func encode(value any, compact bool) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if !compact {
		enc.SetIndent("", "  ")
	}
	check(enc.Encode(value), "encode output")
}
func check(err error, op string) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "%s: %v\n", op, err)
	os.Exit(1)
}
func usage() {
	fmt.Fprintln(os.Stderr, "usage: update-manager --command simulate [flags]")
	flag.PrintDefaults()
	os.Exit(2)
}
