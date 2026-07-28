package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
	"github.com/openwatchlist-labs/watchlist-platform/internal/providerentity"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: provider-catalog <project|validate|compare|hybrid> [flags]")
	}
	switch os.Args[1] {
	case "project":
		project(os.Args[2:])
	case "validate":
		validate(os.Args[2:])
	case "compare":
		compare(os.Args[2:])
	case "hybrid":
		hybrid(os.Args[2:])
	default:
		fatalf("unsupported subcommand %q", os.Args[1])
	}
}

func project(args []string) {
	fs := flag.NewFlagSet("project", flag.ExitOnError)
	snapshotPath := fs.String("snapshot", "", "OpenSanctions-like snapshot JSON")
	outputPath := fs.String("output", "", "output provider-entity catalog JSON")
	fs.Parse(args)
	if *snapshotPath == "" {
		fatalf("--snapshot is required")
	}
	file, err := os.Open(*snapshotPath)
	check(err, "open snapshot")
	defer file.Close()
	snapshot, err := providerentity.LoadSnapshot(file)
	check(err, "load snapshot")
	catalog, err := providerentity.Project(snapshot)
	check(err, "project provider catalog")
	writeJSON(*outputPath, catalog)
}

func validate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	catalogPath := fs.String("catalog", "", "provider-entity catalog JSON")
	fs.Parse(args)
	if *catalogPath == "" {
		fatalf("--catalog is required")
	}
	file, err := os.Open(*catalogPath)
	check(err, "open catalog")
	defer file.Close()
	catalog, err := providerentity.LoadCatalog(file)
	check(err, "validate catalog")
	encode(map[string]any{"valid": true, "catalog_id": catalog.CatalogID, "catalog_checksum": catalog.CatalogChecksum, "record_count": catalog.RecordCount})
}

func compare(args []string) {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	providerPath := fs.String("provider", "", "provider-entity catalog JSON")
	directPath := fs.String("direct", "", "OFAC direct-list catalog JSON")
	outputPath := fs.String("output", "", "output comparison JSON")
	fs.Parse(args)
	if *providerPath == "" || *directPath == "" {
		fatalf("--provider and --direct are required")
	}
	providerCatalog := loadProvider(*providerPath)
	directCatalog := loadDirect(*directPath)
	comparison, err := providerentity.Compare(providerCatalog, directCatalog)
	check(err, "compare catalogs")
	writeJSON(*outputPath, comparison)
}

func hybrid(args []string) {
	fs := flag.NewFlagSet("hybrid", flag.ExitOnError)
	providerPath := fs.String("provider", "", "provider-entity catalog JSON")
	directPath := fs.String("direct", "", "OFAC direct-list catalog JSON")
	outputPath := fs.String("output", "", "output hybrid catalog descriptor JSON")
	fs.Parse(args)
	if *providerPath == "" || *directPath == "" {
		fatalf("--provider and --direct are required")
	}
	providerCatalog := loadProvider(*providerPath)
	directCatalog := loadDirect(*directPath)
	hybrid, err := providerentity.BuildHybridCatalog(providerCatalog, matcherprovider.CatalogReference{CatalogID: directCatalog.CatalogID, CatalogVersion: directCatalog.CatalogVersion, CatalogChecksum: directCatalog.CatalogChecksum, CatalogMode: directCatalog.CatalogMode})
	check(err, "build hybrid catalog")
	writeJSON(*outputPath, hybrid)
}

func loadProvider(path string) providerentity.Catalog {
	file, err := os.Open(path)
	check(err, "open provider catalog")
	defer file.Close()
	catalog, err := providerentity.LoadCatalog(file)
	check(err, "load provider catalog")
	return catalog
}
func loadDirect(path string) ofaccatalog.Catalog {
	file, err := os.Open(path)
	check(err, "open direct catalog")
	defer file.Close()
	catalog, err := ofaccatalog.Load(file)
	check(err, "load direct catalog")
	return catalog
}
func writeJSON(path string, value any) {
	if path == "" {
		encode(value)
		return
	}
	file, err := os.Create(path)
	check(err, "create output")
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	check(encoder.Encode(value), "encode output")
}
func encode(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	check(encoder.Encode(value), "encode output")
}
func check(err error, action string) {
	if err != nil {
		fatalf("%s: %v", action, err)
	}
}
func fatalf(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...); os.Exit(1) }
