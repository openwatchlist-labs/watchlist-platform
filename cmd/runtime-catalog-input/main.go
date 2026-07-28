package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/openwatchlist-labs/watchlist-platform/internal/runtimecataloginput"
)

func main() {
	catalogPath := flag.String("catalog", "", "official or provider catalog JSON")
	componentID := flag.String("component-id", "", "stable Phase 7C-B catalog component ID")
	outputPath := flag.String("output", "", "output deterministic .owcin compiler input")
	flag.Parse()
	if flag.NArg() != 0 || *catalogPath == "" || *componentID == "" || *outputPath == "" {
		usage()
	}
	file, err := os.Open(*catalogPath)
	check(err, "open catalog")
	defer file.Close()
	content, summary, err := runtimecataloginput.Export(file, *componentID)
	check(err, "export runtime catalog input")
	check(writeAtomic(*outputPath, content), "write compiler input")
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	check(encoder.Encode(summary), "encode summary")
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".runtime-input-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func check(err error, action string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", action, err)
		os.Exit(1)
	}
}
func usage() {
	fmt.Fprintln(os.Stderr, "usage: runtime-catalog-input --catalog <catalog.json> --component-id <catalog_component_...> --output <catalog.owcin>")
	flag.PrintDefaults()
	os.Exit(2)
}
