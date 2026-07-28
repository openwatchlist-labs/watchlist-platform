package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogrefresh"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacruntime"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacsource"
)

func main() {
	command := flag.String("command", "simulate", "simulate, diff, build-delta, evaluate, or apply")
	baseCatalogPath := flag.String("base-catalog", "", "base direct-list catalog JSON")
	targetCatalogPath := flag.String("target-catalog", "", "target direct-list catalog JSON")
	fullTargetPath := flag.String("full-target", "", "optional independently rebuilt target catalog JSON")
	deltaPath := flag.String("delta", "", "delta JSON")
	policyPath := flag.String("policy", "test/fixtures/catalog-refresh/promotion-policy-v1.json", "promotion policy JSON")
	sequence := flag.Uint64("sequence", 1, "delta sequence")
	expectedSequence := flag.Uint64("expected-sequence", 1, "expected next delta sequence")
	generatedAtRaw := flag.String("generated-at", "2026-07-13T19:00:00Z", "RFC3339 delta generation time")
	evaluatedAtRaw := flag.String("evaluated-at", "2026-07-13T19:01:00Z", "RFC3339 evaluation time")
	baseXML := flag.String("base-xml", "test/fixtures/catalog-refresh/sdn-delta-base.xml", "simulate base SDN XML")
	smallXML := flag.String("small-xml", "test/fixtures/catalog-refresh/sdn-delta-small.xml", "simulate small target SDN XML")
	thresholdXML := flag.String("threshold-xml", "test/fixtures/catalog-refresh/sdn-delta-threshold.xml", "simulate threshold target SDN XML")
	largeXML := flag.String("large-xml", "test/fixtures/catalog-refresh/sdn-delta-large.xml", "simulate large target SDN XML")
	compact := flag.Bool("compact", false, "emit compact JSON")
	flag.Parse()
	generatedAt := mustTime(*generatedAtRaw)
	evaluatedAt := mustTime(*evaluatedAtRaw)

	var output any
	var err error
	switch *command {
	case "simulate":
		output, err = simulate(*baseXML, *smallXML, *thresholdXML, *largeXML, *policyPath, generatedAt)
	case "diff":
		output, err = catalogrefresh.Diff(mustCatalog(*baseCatalogPath), mustCatalog(*targetCatalogPath))
	case "build-delta":
		output, err = catalogrefresh.BuildDelta(mustCatalog(*baseCatalogPath), mustCatalog(*targetCatalogPath), *sequence, generatedAt)
	case "evaluate":
		base := mustCatalog(*baseCatalogPath)
		delta := mustDelta(*deltaPath)
		policy := mustPolicy(*policyPath)
		var full *ofaccatalog.Catalog
		if *fullTargetPath != "" {
			value := mustCatalog(*fullTargetPath)
			full = &value
		}
		var target ofaccatalog.Catalog
		output, target, err = catalogrefresh.Evaluate(base, delta, policy, *expectedSequence, evaluatedAt, full)
		_ = target
	case "apply":
		output, err = catalogrefresh.Apply(mustCatalog(*baseCatalogPath), mustDelta(*deltaPath), *expectedSequence)
	default:
		usage()
	}
	check(err, *command)
	encode(os.Stdout, output, *compact)
}

func simulate(basePath, smallPath, thresholdPath, largePath, policyPath string, at time.Time) (catalogrefresh.Replay, error) {
	base, err := xmlCatalog(basePath, "fixture:delta-base", at)
	if err != nil {
		return catalogrefresh.Replay{}, err
	}
	small, err := xmlCatalog(smallPath, "fixture:delta-small", at.Add(time.Minute))
	if err != nil {
		return catalogrefresh.Replay{}, err
	}
	threshold, err := xmlCatalog(thresholdPath, "fixture:delta-threshold", at.Add(2*time.Minute))
	if err != nil {
		return catalogrefresh.Replay{}, err
	}
	large, err := xmlCatalog(largePath, "fixture:delta-large", at.Add(3*time.Minute))
	if err != nil {
		return catalogrefresh.Replay{}, err
	}
	policy, err := catalogrefresh.LoadPolicy(policyPath)
	if err != nil {
		return catalogrefresh.Replay{}, err
	}
	smallDelta, err := catalogrefresh.BuildDelta(base, small, 1, at.Add(3*time.Minute))
	if err != nil {
		return catalogrefresh.Replay{}, err
	}
	smallDecision, accepted, err := catalogrefresh.Evaluate(base, smallDelta, policy, 1, at.Add(4*time.Minute), &small)
	if err != nil {
		return catalogrefresh.Replay{}, err
	}
	thresholdDelta, err := catalogrefresh.BuildDelta(base, threshold, 1, at.Add(5*time.Minute))
	if err != nil {
		return catalogrefresh.Replay{}, err
	}
	thresholdDecision, _, err := catalogrefresh.Evaluate(base, thresholdDelta, policy, 1, at.Add(6*time.Minute), &threshold)
	if err != nil {
		return catalogrefresh.Replay{}, err
	}
	largeDelta, err := catalogrefresh.BuildDelta(base, large, 1, at.Add(7*time.Minute))
	if err != nil {
		return catalogrefresh.Replay{}, err
	}
	largeDecision, _, err := catalogrefresh.Evaluate(base, largeDelta, policy, 1, at.Add(8*time.Minute), &large)
	if err != nil {
		return catalogrefresh.Replay{}, err
	}
	gapDecision, _, err := catalogrefresh.Evaluate(base, smallDelta, policy, 2, at.Add(9*time.Minute), nil)
	if err != nil {
		return catalogrefresh.Replay{}, err
	}
	_, info, err := ofacruntime.Compile(accepted)
	if err != nil {
		return catalogrefresh.Replay{}, err
	}
	return catalogrefresh.Replay{
		SchemaVersion:         catalogrefresh.ReplaySchemaVersion,
		EngineVersion:         catalogrefresh.EngineVersion,
		Policy:                policy,
		Base:                  catalogrefresh.CatalogReference(base),
		SmallDelta:            smallDelta,
		SmallDecision:         smallDecision,
		ThresholdDelta:        thresholdDelta,
		ThresholdDecision:     thresholdDecision,
		LargeDelta:            largeDelta,
		LargeDecision:         largeDecision,
		SequenceGapDecision:   gapDecision,
		AcceptedTarget:        catalogrefresh.CatalogReference(accepted),
		AcceptedPackageID:     info.PackageID,
		AcceptedPackageSHA256: info.PackageChecksum,
	}, nil
}

func xmlCatalog(path, sourceURL string, at time.Time) (ofaccatalog.Catalog, error) {
	acquired, err := ofacsource.AcquireLocal(path, sourceURL, at)
	if err != nil {
		return ofaccatalog.Catalog{}, err
	}
	pkg, err := ofacsource.Parse(acquired)
	if err != nil {
		return ofaccatalog.Catalog{}, err
	}
	return ofaccatalog.Project(pkg)
}

func mustCatalog(path string) ofaccatalog.Catalog {
	if path == "" {
		usage()
	}
	file, err := os.Open(path)
	check(err, "open catalog")
	defer file.Close()
	catalog, err := ofaccatalog.Load(file)
	check(err, "load catalog")
	return catalog
}
func mustDelta(path string) catalogrefresh.Delta {
	if path == "" {
		usage()
	}
	value, err := catalogrefresh.LoadDelta(path)
	check(err, "load delta")
	return value
}
func mustPolicy(path string) catalogrefresh.PromotionPolicy {
	value, err := catalogrefresh.LoadPolicy(path)
	check(err, "load policy")
	return value
}
func mustTime(raw string) time.Time {
	value, err := time.Parse(time.RFC3339, raw)
	check(err, "parse time")
	return value
}
func encode(w io.Writer, value any, compact bool) {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	if !compact {
		encoder.SetIndent("", "  ")
	}
	check(encoder.Encode(value), "encode output")
}
func check(err error, op string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", op, err)
		os.Exit(1)
	}
}
func usage() {
	fmt.Fprintln(os.Stderr, "usage: catalog-refresh --command simulate|diff|build-delta|evaluate|apply [flags]")
	flag.PrintDefaults()
	os.Exit(2)
}
