package ofacruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogruntime"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherrequest"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacsource"
)

func TestCompiledPackageDeterministicPortableAndEquivalent(t *testing.T) {
	catalog := loadGoldenCatalog(t)
	first, firstInfo, err := Compile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	second, secondInfo, err := Compile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || !reflect.DeepEqual(firstInfo, secondInfo) {
		t.Fatal("same catalog did not produce byte-identical runtime package")
	}
	loaded, err := Load(first)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Info.PackageID != firstInfo.PackageID || loaded.Payload.EntryCount == 0 || loaded.Payload.RecordCount != catalog.RecordCount {
		t.Fatalf("loaded package mismatch: %+v", loaded.Info)
	}

	batch := loadRequestBatch(t)
	directProvider, err := ofaccatalog.NewProvider(catalog)
	if err != nil {
		t.Fatal(err)
	}
	directRunner, _ := matcherprovider.NewRunner(directProvider)
	compiledRunner, _ := matcherprovider.NewRunner(loaded.Provider)
	directResults, err := directRunner.Execute(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	compiledResults, err := compiledRunner.Execute(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(directResults, compiledResults) {
		t.Fatal("compiled provider output differs from direct-list provider output")
	}

	tampered := append([]byte(nil), first...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := Load(tampered); err == nil {
		t.Fatal("tampered runtime package accepted")
	}
}

func TestReadinessRegistryActivationDrainRollbackAndStampedResults(t *testing.T) {
	catalogA := loadGoldenCatalog(t)
	artifactA, _, err := Compile(catalogA)
	if err != nil {
		t.Fatal(err)
	}
	loadedA, err := Load(artifactA)
	if err != nil {
		t.Fatal(err)
	}
	catalogB := loadFixtureCatalog(t, "sdn-fixture-v2.xml", time.Date(2026, 7, 14, 16, 30, 0, 0, time.UTC))
	artifactB, _, err := Compile(catalogB)
	if err != nil {
		t.Fatal(err)
	}
	loadedB, err := Load(artifactB)
	if err != nil {
		t.Fatal(err)
	}
	compiledA := time.Date(2026, 7, 13, 17, 0, 0, 0, time.UTC)
	compiledB := time.Date(2026, 7, 14, 17, 0, 0, 0, time.UTC)
	readyA, err := Readiness(loadedA, compiledA, compiledA.Add(time.Minute))
	if err != nil || !readyA.Ready {
		t.Fatalf("A not ready: %+v %v", readyA, err)
	}
	readyB, err := Readiness(loadedB, compiledB, compiledB.Add(time.Minute))
	if err != nil || !readyB.Ready {
		t.Fatalf("B not ready: %+v %v", readyB, err)
	}
	inputA, _ := ActivationInput(loadedA, compiledA)
	inputB, _ := ActivationInput(loadedB, compiledB)

	var registry catalogruntime.Registry
	activationA, retired, err := registry.ActivatePackage(inputA, loadedA.Provider, readyA.ReportID, compiledA.Add(2*time.Minute))
	if err != nil || retired != nil || activationA.Active.ActivationEpoch != 1 {
		t.Fatalf("activate A failed: retired=%v record=%+v err=%v", retired, activationA, err)
	}
	leaseA, err := registry.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	activationB, retiredA, err := registry.ActivatePackage(inputB, loadedB.Provider, readyB.ReportID, compiledB.Add(2*time.Minute))
	if err != nil || retiredA == nil || activationB.Active.ActivationEpoch != 2 {
		t.Fatalf("activate B failed: %+v err=%v", activationB, err)
	}
	leaseB, err := registry.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	stampA, _ := leaseA.Stamp()
	stampB, _ := leaseB.Stamp()
	if stampA.PackageID != loadedA.Info.PackageID || stampB.PackageID != loadedB.Info.PackageID {
		t.Fatal("leases not pinned to their starting runtime package")
	}

	batch := loadRequestBatch(t)
	runnerA, _ := matcherprovider.NewRunner(leaseA.Payload().(matcherprovider.Provider))
	resultsA, err := runnerA.ExecuteStamped(context.Background(), batch, stampA)
	if err != nil {
		t.Fatal(err)
	}
	if resultsA.RuntimeGeneration == nil || resultsA.RuntimeGeneration.GenerationID != stampA.GenerationID {
		t.Fatal("batch missing generation A stamp")
	}
	for _, result := range resultsA.Results {
		if result.RuntimeGeneration == nil || result.RuntimeGeneration.GenerationID != stampA.GenerationID {
			t.Fatal("candidate result missing generation A stamp")
		}
	}

	leaseA.Release()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := retiredA.WaitDrained(ctx); err != nil {
		t.Fatal(err)
	}
	leaseB.Release()
	rollbackActivation, rollback, _, err := registry.RollbackPackage(inputA, loadedA.Provider, readyA.ReportID, "rollback after canary regression", compiledB.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if rollbackActivation.Active.ActivationEpoch != 3 || rollback.TargetPackageID != loadedA.Info.PackageID || rollback.NewGeneration.GenerationID == stampA.GenerationID {
		t.Fatalf("rollback audit mismatch: %+v %+v", rollbackActivation, rollback)
	}
}

func loadGoldenCatalog(t *testing.T) ofaccatalog.Catalog {
	t.Helper()
	file, err := os.Open(filepath.Join("..", "..", "test", "golden", "ofac", "ofac-sdn-fixture.catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	catalog, err := ofaccatalog.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func loadFixtureCatalog(t *testing.T, name string, acquired time.Time) ofaccatalog.Catalog {
	t.Helper()
	path := filepath.Join("..", "..", "test", "fixtures", "ofac", "sdn", name)
	acquiredSource, err := ofacsource.AcquireLocal(path, ofacsource.OfficialSDNXMLURL, acquired)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := ofacsource.Parse(acquiredSource)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := ofaccatalog.Project(pkg)
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func loadRequestBatch(t *testing.T) matcherrequest.RequestBatch {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "golden", "iso20022", "pacs008", "pacs008-basic.matcher-requests.json"))
	if err != nil {
		t.Fatal(err)
	}
	var batch matcherrequest.RequestBatch
	if err := json.Unmarshal(data, &batch); err != nil {
		t.Fatal(err)
	}
	if err := matcherrequest.ValidateBatch(batch); err != nil {
		t.Fatal(err)
	}
	return batch
}
