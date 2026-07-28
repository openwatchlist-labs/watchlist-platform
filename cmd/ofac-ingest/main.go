package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacsource"
)

func main() {
	input := flag.String("input", "", "local SDN.XML; omit to download official source")
	sourceURL := flag.String("source-url", ofacsource.OfficialSDNXMLURL, "official source URL")
	acquiredAtRaw := flag.String("acquired-at", "", "RFC3339 acquisition time")
	output := flag.String("output", "catalog", "manifest or catalog")
	archiveDir := flag.String("archive-dir", "", "immutable source archive root")
	compact := flag.Bool("compact", false, "compact JSON")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: ofac-ingest [flags]")
		flag.PrintDefaults()
		os.Exit(2)
	}
	var at time.Time
	var err error
	if *acquiredAtRaw != "" {
		at, err = time.Parse(time.RFC3339, *acquiredAtRaw)
		check(err, "parse --acquired-at")
	}
	var a ofacsource.Acquired
	if *input != "" {
		a, err = ofacsource.AcquireLocal(*input, *sourceURL, at)
	} else {
		a, err = ofacsource.AcquireHTTP(context.Background(), *sourceURL, at)
	}
	check(err, "acquire OFAC source")
	pkg, err := ofacsource.Parse(a)
	check(err, "parse OFAC source")
	if *archiveDir != "" {
		path, err := ofacsource.Archive(*archiveDir, a, pkg.Manifest)
		check(err, "archive source")
		fmt.Fprintf(os.Stderr, "archived immutable source at %s\n", path)
	}
	var value any
	switch *output {
	case "manifest":
		value = pkg.Manifest
	case "catalog":
		c, err := ofaccatalog.Project(pkg)
		check(err, "project catalog")
		value = c
	default:
		fmt.Fprintf(os.Stderr, "unsupported --output %q; expected manifest or catalog\n", *output)
		os.Exit(2)
	}
	enc := json.NewEncoder(os.Stdout)
	if !*compact {
		enc.SetIndent("", "  ")
	}
	enc.SetEscapeHTML(false)
	check(enc.Encode(value), "encode output")
}
func check(err error, op string) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "%s: %v\n", op, err)
	os.Exit(1)
}
