package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherrequest"
	"github.com/openwatchlist-labs/watchlist-platform/internal/screening"
)

func main() {
	outputKind := flag.String("output", "requests", "JSON output: requests or replay")
	compact := flag.Bool("compact", false, "emit compact JSON")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: matcher-project [flags] <screening evidence JSON>")
		flag.PrintDefaults()
		os.Exit(2)
	}
	if *outputKind != "requests" && *outputKind != "replay" {
		fmt.Fprintf(os.Stderr, "unsupported --output %q; expected requests or replay\n", *outputKind)
		os.Exit(2)
	}

	input, err := os.Open(flag.Arg(0))
	check(err, "open evidence input")
	defer input.Close()
	var bundle screening.EvidenceBundle
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()
	check(decoder.Decode(&bundle), "decode evidence input")
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("multiple JSON values are not allowed")
		}
		check(err, "decode evidence input")
	}

	projector := matcherrequest.NewProjector()
	var output any
	if *outputKind == "requests" {
		output, err = projector.Project(bundle)
		check(err, "project matcher requests")
	} else {
		output, err = projector.Replay(bundle)
		check(err, "build replay envelope")
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
