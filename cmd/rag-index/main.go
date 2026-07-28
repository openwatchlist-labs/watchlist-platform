package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/openwatchlist-labs/watchlist-platform/internal/rag"
)

func main() {
	manifestPath := flag.String("manifest", "", "path to corpus manifest JSON")
	outputPath := flag.String("output", "-", "output path or - for stdout")
	flag.Parse()
	if *manifestPath == "" {
		fatalf("--manifest is required")
	}
	manifest, err := rag.LoadManifest(*manifestPath)
	if err != nil {
		fatalf("load manifest: %v", err)
	}
	snapshot, err := rag.BuildSnapshot(*manifestPath, manifest)
	if err != nil {
		fatalf("build snapshot: %v", err)
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		fatalf("marshal snapshot: %v", err)
	}
	data = append(data, '\n')
	if *outputPath == "-" {
		_, _ = os.Stdout.Write(data)
		return
	}
	if err := os.WriteFile(*outputPath, data, 0o644); err != nil {
		fatalf("write output: %v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
