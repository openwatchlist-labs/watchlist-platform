package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertlistmapping"
	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogregistry"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: alert-list-mapping <init|register|resolve|resolve-batch|snapshot|verify|postgres-schema> [flags]")
	}
	switch os.Args[1] {
	case "init":
		initRegistry(os.Args[2:])
	case "register":
		register(os.Args[2:])
	case "resolve":
		resolve(os.Args[2:])
	case "resolve-batch":
		resolveBatch(os.Args[2:])
	case "snapshot":
		snapshot(os.Args[2:])
	case "verify":
		verify(os.Args[2:])
	case "postgres-schema":
		fmt.Print(alertlistmapping.PostgresMigration())
	default:
		fatalf("unsupported subcommand %q", os.Args[1])
	}
}

func initRegistry(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	storePath := fs.String("store", "", "alert-list mapping state directory")
	namespace := fs.String("namespace", "", "organization mapping namespace")
	fs.Parse(args)
	require(*storePath, "--store")
	require(*namespace, "--namespace")
	registry, err := (alertlistmapping.Store{Root: *storePath}).Initialize(*namespace)
	check(err, "initialize mapping registry")
	encode(registry)
}

func register(args []string) {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	storePath := fs.String("store", "", "alert-list mapping state directory")
	catalogStorePath := fs.String("catalog-registry-store", "", "catalog component registry state directory")
	inputPath := fs.String("input", "", "mapping input JSON")
	fs.Parse(args)
	require(*storePath, "--store")
	require(*catalogStorePath, "--catalog-registry-store")
	require(*inputPath, "--input")
	catalog := loadCatalog(*catalogStorePath)
	var input alertlistmapping.MappingInput
	readJSON(*inputPath, &input)
	version, registry, err := (alertlistmapping.Store{Root: *storePath}).Register(input, catalog)
	check(err, "register exact alert-list mapping")
	encode(map[string]any{
		"registered":                true,
		"mapping_version":           version,
		"mapping_registry_checksum": registry.RegistryChecksum,
	})
}

func resolve(args []string) {
	fs := flag.NewFlagSet("resolve", flag.ExitOnError)
	storePath := fs.String("store", "", "alert-list mapping state directory")
	catalogStorePath := fs.String("catalog-registry-store", "", "catalog component registry state directory")
	sourceSystemID := fs.String("source-system-id", "", "exact source-system identifier")
	rawListName := fs.String("raw-list-name", "", "exact raw alert list name")
	atRaw := fs.String("at", "", "RFC3339 resolution time; defaults to current UTC time")
	fs.Parse(args)
	require(*storePath, "--store")
	require(*catalogStorePath, "--catalog-registry-store")
	require(*sourceSystemID, "--source-system-id")
	if *rawListName == "" {
		fatalf("--raw-list-name is required")
	}
	at := parseOptionalTime(*atRaw)
	catalog := loadCatalog(*catalogStorePath)
	registry, err := (alertlistmapping.Store{Root: *storePath}).Load(catalog)
	check(err, "load mapping registry")
	result, err := alertlistmapping.Resolve(registry, catalog, alertlistmapping.ResolveRequest{
		SourceSystemID: *sourceSystemID,
		RawListName:    *rawListName,
		At:             at,
	})
	check(err, "resolve exact alert-list mapping")
	encode(result)
}

func resolveBatch(args []string) {
	fs := flag.NewFlagSet("resolve-batch", flag.ExitOnError)
	storePath := fs.String("store", "", "alert-list mapping state directory")
	catalogStorePath := fs.String("catalog-registry-store", "", "catalog component registry state directory")
	inputPath := fs.String("input", "", "batch input JSON")
	fs.Parse(args)
	require(*storePath, "--store")
	require(*catalogStorePath, "--catalog-registry-store")
	require(*inputPath, "--input")
	catalog := loadCatalog(*catalogStorePath)
	registry, err := (alertlistmapping.Store{Root: *storePath}).Load(catalog)
	check(err, "load mapping registry")
	var input alertlistmapping.BatchInput
	readJSON(*inputPath, &input)
	result, err := alertlistmapping.ResolveBatch(registry, catalog, input)
	check(err, "resolve alert-list mapping batch")
	encode(result)
}

func snapshot(args []string) {
	fs := flag.NewFlagSet("snapshot", flag.ExitOnError)
	storePath := fs.String("store", "", "alert-list mapping state directory")
	catalogStorePath := fs.String("catalog-registry-store", "", "catalog component registry state directory")
	outputPath := fs.String("output", "", "optional output JSON path")
	fs.Parse(args)
	require(*storePath, "--store")
	require(*catalogStorePath, "--catalog-registry-store")
	catalog := loadCatalog(*catalogStorePath)
	registry, err := (alertlistmapping.Store{Root: *storePath}).Load(catalog)
	check(err, "load mapping registry")
	if *outputPath == "" {
		encode(registry)
		return
	}
	writeJSON(*outputPath, registry)
}

func verify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	storePath := fs.String("store", "", "alert-list mapping state directory")
	catalogStorePath := fs.String("catalog-registry-store", "", "catalog component registry state directory")
	fs.Parse(args)
	require(*storePath, "--store")
	require(*catalogStorePath, "--catalog-registry-store")
	catalog := loadCatalog(*catalogStorePath)
	registry, err := (alertlistmapping.Store{Root: *storePath}).Load(catalog)
	check(err, "verify mapping registry")
	encode(map[string]any{
		"valid":                     true,
		"mapping_registry_id":       registry.RegistryID,
		"namespace":                 registry.Namespace,
		"mapping_key_count":         len(registry.Keys),
		"mapping_version_count":     len(registry.Versions),
		"last_sequence":             registry.LastSequence,
		"audit_head":                registry.AuditHead,
		"mapping_registry_checksum": registry.RegistryChecksum,
		"catalog_registry_id":       catalog.RegistryID,
		"catalog_registry_checksum": catalog.RegistryChecksum,
	})
}

func loadCatalog(path string) catalogregistry.Registry {
	catalog, err := (catalogregistry.Store{Root: path}).Load()
	check(err, "load catalog component registry")
	return catalog
}

func parseOptionalTime(value string) time.Time {
	if strings.TrimSpace(value) == "" {
		return time.Now().UTC()
	}
	parsed, err := time.Parse(time.RFC3339, value)
	check(err, "parse --at")
	return parsed.UTC()
}

func readJSON(path string, target any) {
	file, err := os.Open(path)
	check(err, "open "+path)
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	check(decoder.Decode(target), "decode "+path)
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			fatalf("decode %s: trailing JSON value", path)
		}
		fatalf("decode %s: %v", path, err)
	}
}

func writeJSON(path string, value any) {
	file, err := os.Create(path)
	check(err, "create "+path)
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	check(encoder.Encode(value), "encode "+path)
}

func encode(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	check(encoder.Encode(value), "encode output")
}

func require(value, flagName string) {
	if strings.TrimSpace(value) == "" {
		fatalf("%s is required", flagName)
	}
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
