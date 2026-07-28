package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogregistry"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: catalog-registry <init|register-component|register-version|activate|rollback|snapshot|verify|postgres-schema> [flags]")
	}
	switch os.Args[1] {
	case "init":
		initRegistry(os.Args[2:])
	case "register-component":
		registerComponent(os.Args[2:])
	case "register-version":
		registerVersion(os.Args[2:])
	case "activate":
		activate(os.Args[2:], catalogregistry.ActivationActionActivate)
	case "rollback":
		activate(os.Args[2:], catalogregistry.ActivationActionRollback)
	case "snapshot":
		snapshot(os.Args[2:])
	case "verify":
		verify(os.Args[2:])
	case "postgres-schema":
		fmt.Print(catalogregistry.PostgresMigration())
	default:
		fatalf("unsupported subcommand %q", os.Args[1])
	}
}

func initRegistry(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	storePath := fs.String("store", "", "catalog registry state directory")
	namespace := fs.String("namespace", "", "registry namespace")
	fs.Parse(args)
	require(*storePath, "--store")
	require(*namespace, "--namespace")
	registry, err := (catalogregistry.Store{Root: *storePath}).Initialize(*namespace)
	check(err, "initialize registry")
	encode(registry)
}

func registerComponent(args []string) {
	fs := flag.NewFlagSet("register-component", flag.ExitOnError)
	storePath := fs.String("store", "", "catalog registry state directory")
	inputPath := fs.String("input", "", "component input JSON")
	fs.Parse(args)
	require(*storePath, "--store")
	require(*inputPath, "--input")
	var input catalogregistry.ComponentInput
	readJSON(*inputPath, &input)
	component, err := catalogregistry.BuildComponent(input)
	check(err, "build component")
	registry, err := (catalogregistry.Store{Root: *storePath}).RegisterComponent(component)
	check(err, "register component")
	encode(map[string]any{
		"registered":        true,
		"component":         component,
		"registry_checksum": registry.RegistryChecksum,
	})
}

func registerVersion(args []string) {
	fs := flag.NewFlagSet("register-version", flag.ExitOnError)
	storePath := fs.String("store", "", "catalog registry state directory")
	inputPath := fs.String("input", "", "catalog version input JSON")
	fs.Parse(args)
	require(*storePath, "--store")
	require(*inputPath, "--input")
	store := catalogregistry.Store{Root: *storePath}
	registry, err := store.Load()
	check(err, "load registry")
	var input catalogregistry.VersionInput
	readJSON(*inputPath, &input)
	component, ok := componentByID(registry, input.ComponentID)
	if !ok {
		fatalf("component %q is not registered", input.ComponentID)
	}
	version, err := catalogregistry.BuildVersion(input, component)
	check(err, "build catalog version")
	registry, err = store.RegisterVersion(version)
	check(err, "register catalog version")
	encode(map[string]any{
		"registered":        true,
		"version":           version,
		"registry_checksum": registry.RegistryChecksum,
	})
}

func activate(args []string, action catalogregistry.ActivationAction) {
	fs := flag.NewFlagSet(string(action), flag.ExitOnError)
	storePath := fs.String("store", "", "catalog registry state directory")
	componentID := fs.String("component-id", "", "stable catalog component ID")
	versionID := fs.String("version-id", "", "registered catalog version ID")
	expected := fs.String("expected-current-version-id", "", "optional compare-and-set active version")
	actor := fs.String("actor", "", "activation actor")
	reason := fs.String("reason", "", "activation reason")
	atRaw := fs.String("at", "", "RFC3339 activation time; defaults to current UTC time")
	fs.Parse(args)
	require(*storePath, "--store")
	require(*componentID, "--component-id")
	require(*versionID, "--version-id")
	require(*actor, "--actor")
	require(*reason, "--reason")
	at := time.Now().UTC()
	if strings.TrimSpace(*atRaw) != "" {
		var err error
		at, err = time.Parse(time.RFC3339, *atRaw)
		check(err, "parse --at")
	}
	record, registry, err := (catalogregistry.Store{Root: *storePath}).Activate(catalogregistry.ActivationRequest{
		ComponentID:              *componentID,
		TargetVersionID:          *versionID,
		Action:                   action,
		ExpectedCurrentVersionID: *expected,
		Reason:                   *reason,
		ActivatedAt:              at,
		ActivatedBy:              *actor,
	})
	check(err, string(action)+" catalog version")
	encode(map[string]any{
		"applied":           true,
		"activation":        record,
		"registry_checksum": registry.RegistryChecksum,
	})
}

func snapshot(args []string) {
	fs := flag.NewFlagSet("snapshot", flag.ExitOnError)
	storePath := fs.String("store", "", "catalog registry state directory")
	outputPath := fs.String("output", "", "optional output JSON path")
	fs.Parse(args)
	require(*storePath, "--store")
	registry, err := (catalogregistry.Store{Root: *storePath}).Load()
	check(err, "load registry")
	if *outputPath == "" {
		encode(registry)
		return
	}
	writeJSON(*outputPath, registry)
}

func verify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	storePath := fs.String("store", "", "catalog registry state directory")
	fs.Parse(args)
	require(*storePath, "--store")
	registry, err := (catalogregistry.Store{Root: *storePath}).Load()
	check(err, "verify registry")
	encode(map[string]any{
		"valid":                  true,
		"registry_id":            registry.RegistryID,
		"namespace":              registry.Namespace,
		"component_count":        len(registry.Components),
		"version_count":          len(registry.Versions),
		"activation_count":       len(registry.Activations),
		"active_component_count": len(registry.Active),
		"audit_head":             registry.AuditHead,
		"registry_checksum":      registry.RegistryChecksum,
	})
}

func componentByID(registry catalogregistry.Registry, id string) (catalogregistry.Component, bool) {
	for _, component := range registry.Components {
		if component.ComponentID == id {
			return component, true
		}
	}
	return catalogregistry.Component{}, false
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
