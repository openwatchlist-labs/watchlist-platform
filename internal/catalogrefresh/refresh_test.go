package catalogrefresh

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacruntime"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacsource"
)

func TestDeltaPromotionAndParity(t *testing.T) {
	base, small, large, policy := fixtureSet(t)
	at := time.Date(2026, 7, 13, 19, 0, 0, 0, time.UTC)
	delta, err := BuildDelta(base, small, 1, at)
	if err != nil {
		t.Fatal(err)
	}
	decision, rebuilt, err := Evaluate(base, delta, policy, 1, at.Add(time.Minute), &small)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Outcome != OutcomePromoteDelta {
		t.Fatalf("outcome=%s reasons=%v", decision.Outcome, decision.Reasons)
	}
	if decision.Diff == nil || decision.Diff.Modified != 1 || decision.Diff.ChangeRatioBasisPoints != 1000 {
		t.Fatalf("unexpected diff: %#v", decision.Diff)
	}
	if rebuilt.CatalogChecksum != small.CatalogChecksum || !decision.FullRebuildVerified {
		t.Fatal("delta/full parity not proven")
	}
	a, infoA, err := ofacruntime.Compile(rebuilt)
	if err != nil {
		t.Fatal(err)
	}
	b, infoB, err := ofacruntime.Compile(small)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) || infoA.PackageID != infoB.PackageID {
		t.Fatal("compiled package parity failed")
	}

	largeDelta, err := BuildDelta(base, large, 1, at)
	if err != nil {
		t.Fatal(err)
	}
	largeDecision, _, err := Evaluate(base, largeDelta, policy, 1, at.Add(2*time.Minute), &large)
	if err != nil {
		t.Fatal(err)
	}
	if largeDecision.Outcome != OutcomeForceFull || largeDecision.Diff.ChangeRatioBasisPoints != 3000 {
		t.Fatalf("large delta decision=%#v", largeDecision)
	}
}

func TestExactThresholdForcesFullRebuild(t *testing.T) {
	base := loadFixtureCatalog(t, "../../test/fixtures/catalog-refresh/sdn-delta-base.xml", "fixture:delta-base", time.Date(2026, 7, 13, 19, 0, 0, 0, time.UTC))
	threshold := loadFixtureCatalog(t, "../../test/fixtures/catalog-refresh/sdn-delta-threshold.xml", "fixture:delta-threshold", time.Date(2026, 7, 13, 19, 2, 0, 0, time.UTC))
	_, _, _, policy := fixtureSet(t)
	at := time.Date(2026, 7, 13, 19, 0, 0, 0, time.UTC)
	delta, err := BuildDelta(base, threshold, 1, at)
	if err != nil {
		t.Fatal(err)
	}
	decision, _, err := Evaluate(base, delta, policy, 1, at.Add(time.Minute), &threshold)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Outcome != OutcomeForceFull || decision.Diff == nil || decision.Diff.ChangeRatioBasisPoints != 2000 {
		t.Fatalf("threshold decision=%#v", decision)
	}
}

func TestSequenceAndTamperGates(t *testing.T) {
	base, small, _, policy := fixtureSet(t)
	at := time.Date(2026, 7, 13, 19, 0, 0, 0, time.UTC)
	delta, err := BuildDelta(base, small, 1, at)
	if err != nil {
		t.Fatal(err)
	}
	decision, _, err := Evaluate(base, delta, policy, 2, at, nil)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Outcome != OutcomeReject || decision.Reasons[0].Code != "delta_sequence_gap" {
		t.Fatalf("unexpected gap decision: %#v", decision)
	}

	tampered := delta
	tampered.Operations[0].After.Remarks = "tampered"
	if ValidateDelta(tampered) == nil {
		t.Fatal("tampered delta accepted")
	}
}

func TestStrictJSONAndImmutableDecision(t *testing.T) {
	_, _, _, policy := fixtureSet(t)
	path := filepath.Join(t.TempDir(), "policy.json")
	data, _ := json.Marshal(policy)
	data = append(data[:len(data)-1], []byte(`,"unknown":true}`)...)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(path); err == nil {
		t.Fatal("unknown policy field accepted")
	}

	decision := PromotionDecision{SchemaVersion: DecisionSchemaVersion, DecisionID: "decision_test", Outcome: OutcomeReject}
	root := t.TempDir()
	first, err := PersistDecision(root, decision)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PersistDecision(root, decision)
	if err != nil || first != second {
		t.Fatal("idempotent decision persistence failed")
	}
	decision.Outcome = OutcomePromoteDelta
	if _, err = PersistDecision(root, decision); err == nil {
		t.Fatal("immutable decision collision not rejected")
	}
}

func fixtureSet(t *testing.T) (ofaccatalog.Catalog, ofaccatalog.Catalog, ofaccatalog.Catalog, PromotionPolicy) {
	t.Helper()
	base := loadFixtureCatalog(t, "../../test/fixtures/catalog-refresh/sdn-delta-base.xml", "fixture:delta-base", time.Date(2026, 7, 13, 19, 0, 0, 0, time.UTC))
	small := loadFixtureCatalog(t, "../../test/fixtures/catalog-refresh/sdn-delta-small.xml", "fixture:delta-small", time.Date(2026, 7, 13, 19, 1, 0, 0, time.UTC))
	large := loadFixtureCatalog(t, "../../test/fixtures/catalog-refresh/sdn-delta-large.xml", "fixture:delta-large", time.Date(2026, 7, 13, 19, 2, 0, 0, time.UTC))
	policyData, err := os.ReadFile("../../test/fixtures/catalog-refresh/promotion-policy-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var policy PromotionPolicy
	if err = json.Unmarshal(policyData, &policy); err != nil {
		t.Fatal(err)
	}
	if err = ValidatePolicy(policy); err != nil {
		t.Fatal(err)
	}
	return base, small, large, policy
}

func loadFixtureCatalog(t *testing.T, path, sourceURL string, at time.Time) ofaccatalog.Catalog {
	t.Helper()
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
