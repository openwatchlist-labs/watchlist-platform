package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/openwatchlist-labs/watchlist-platform/internal/adapters/iso20022"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherrequest"
	"github.com/openwatchlist-labs/watchlist-platform/internal/screening"
	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningplan"
)

func main() {
	planPath := flag.String("plan", "configs/screening-plans/iso20022-pacs008-cbprplus-v1.json", "path to screening-plan JSON")
	sourceRef := flag.String("source-ref", "", "immutable source payload reference; defaults to input path")
	outputKind := flag.String("output", "canonical", "JSON output: canonical, evidence, inspection, matcher-requests, or replay")
	compact := flag.Bool("compact", false, "emit compact JSON")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: iso20022-inspect [flags] <pacs.008 XML>")
		flag.PrintDefaults()
		os.Exit(2)
	}
	if *outputKind != "canonical" && *outputKind != "evidence" && *outputKind != "inspection" && *outputKind != "matcher-requests" && *outputKind != "replay" {
		fmt.Fprintf(os.Stderr, "unsupported --output %q; expected canonical, evidence, inspection, matcher-requests, or replay\n", *outputKind)
		os.Exit(2)
	}

	planFile, err := os.Open(*planPath)
	check(err, "open screening plan")
	defer planFile.Close()
	plan, err := screeningplan.Load(planFile)
	check(err, "load screening plan")
	compiled, err := screeningplan.Compile(plan)
	check(err, "compile screening plan")
	parser, err := iso20022.NewParser(compiled)
	check(err, "create parser")

	inputPath := flag.Arg(0)
	input, err := os.Open(inputPath)
	check(err, "open input")
	defer input.Close()
	reference := *sourceRef
	if reference == "" {
		reference = "file:" + inputPath
	}
	message, err := parser.Parse(reference, input)
	check(err, "parse input")

	var output any = message
	if *outputKind != "canonical" {
		executor, err := screening.NewExecutor(compiled)
		check(err, "create screening-plan executor")
		bundle, err := executor.Execute(message)
		check(err, "execute screening plan")
		switch *outputKind {
		case "evidence":
			output = bundle
		case "inspection":
			output = screening.InspectionOutput{
				SchemaVersion: screening.InspectionSchemaVersion,
				Canonical:     message,
				Evidence:      bundle,
			}
		case "matcher-requests":
			projector := matcherrequest.NewProjector()
			output, err = projector.Project(bundle)
			check(err, "project matcher requests")
		case "replay":
			projector := matcherrequest.NewProjector()
			output, err = projector.Replay(bundle)
			check(err, "build replay envelope")
		}
	}

	encoder := json.NewEncoder(os.Stdout)
	if !*compact {
		encoder.SetIndent("", "  ")
	}
	encoder.SetEscapeHTML(false)
	check(encoder.Encode(output), "encode JSON output")
}

func check(err error, operation string) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "%s: %v\n", operation, err)
	os.Exit(1)
}
