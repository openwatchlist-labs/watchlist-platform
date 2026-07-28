package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/openwatchlist-labs/watchlist-platform/internal/falsepositive"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
)

func main() {
	inputKind := flag.String("input", "observations", "input contract: observations or matcher-results")
	libraryPath := flag.String("pattern-library", "configs/false-positive-patterns/baseline-r1.json", "false-positive pattern library")
	countervailingPolicyPath := flag.String("countervailing-policy", "configs/false-positive-patterns/countervailing-evidence-r1.json", "primary/secondary countervailing evidence policy")
	sourceReference := flag.String("source-reference", "cli-input", "source reference used when adapting matcher results")
	flag.Parse()
	if flag.NArg() != 1 {
		fatalf("usage: false-positive-classify [flags] <input.json>")
	}
	data, err := os.ReadFile(flag.Arg(0))
	check(err, "read input")
	library, err := falsepositive.LoadPatternLibrary(*libraryPath)
	check(err, "load pattern library")
	countervailingPolicy, err := falsepositive.LoadCountervailingPolicy(*countervailingPolicyPath)
	check(err, "load countervailing evidence policy")
	classifier, err := falsepositive.NewClassifier(library, countervailingPolicy)
	check(err, "create classifier")

	var observations falsepositive.ObservationBatch
	switch *inputKind {
	case "observations":
		check(decodeStrict(data, &observations), "decode observation batch")
		observations = falsepositive.CanonicalizeObservationBatch(observations)
	case "matcher-results":
		var results matcherprovider.ResultBatch
		check(decodeStrict(data, &results), "decode matcher result batch")
		observations, err = falsepositive.ObservationsFromMatcherResults(results, *sourceReference)
		check(err, "adapt matcher results")
	default:
		fatalf("unsupported --input %q", *inputKind)
	}
	output, err := classifier.ClassifyBatch(observations)
	check(err, "classify")
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	check(encoder.Encode(output), "encode output")
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return err
	}
	return nil
}

func check(err error, action string) {
	if err != nil {
		fatalf("%s: %v", action, err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
