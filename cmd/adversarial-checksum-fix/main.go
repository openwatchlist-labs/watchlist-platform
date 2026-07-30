package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacsource"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: adversarial-checksum-fix <catalog.json>")
		os.Exit(2)
	}
	path := os.Args[1]
	raw, err := os.ReadFile(path)
	check(err)

	var catalog ofaccatalog.Catalog
	check(json.Unmarshal(raw, &catalog))

	manifest, err := ofacsource.AssignManifestID(catalog.SourceManifest)
	check(err)
	catalog.SourceManifest = manifest

	sum, err := ofaccatalog.Checksum(catalog)
	check(err)
	catalog.CatalogChecksum = sum

	out, err := json.MarshalIndent(catalog, "", "  ")
	check(err)
	check(os.WriteFile(path, out, 0o644))

	fmt.Printf("computed manifest_id: %s\n", manifest.ManifestID)
	fmt.Printf("computed checksum: %s\n", sum)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
