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
	"github.com/openwatchlist-labs/watchlist-platform/internal/providerrefresh"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: provider-refresh <init|analyze|decide|promote|rollback|snapshot|verify|postgres-schema> [flags]")
	}
	switch os.Args[1] {
	case "init":
		initRegistry(os.Args[2:])
	case "analyze":
		analyze(os.Args[2:])
	case "decide":
		decide(os.Args[2:])
	case "promote":
		promote(os.Args[2:])
	case "rollback":
		rollback(os.Args[2:])
	case "snapshot":
		snapshot(os.Args[2:])
	case "verify":
		verify(os.Args[2:])
	case "postgres-schema":
		fmt.Print(providerrefresh.PostgresMigration())
	default:
		fatalf("unsupported subcommand %q", os.Args[1])
	}
}
func initRegistry(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	store := fs.String("store", "", "provider refresh state directory")
	catalogPath := fs.String("catalog-registry-store", "", "catalog registry state directory")
	namespace := fs.String("namespace", "", "organization namespace")
	fs.Parse(args)
	require(*store, "--store")
	require(*catalogPath, "--catalog-registry-store")
	require(*namespace, "--namespace")
	catalog := loadCatalog(*catalogPath)
	r, err := (providerrefresh.Store{Root: *store}).Initialize(*namespace, catalog)
	check(err, "initialize provider refresh registry")
	encode(r)
}
func analyze(args []string) {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	store := fs.String("store", "", "provider refresh state directory")
	catalogPath := fs.String("catalog-registry-store", "", "catalog registry state directory")
	mappingPath := fs.String("mapping-registry-store", "", "alert-list mapping state directory")
	inputPath := fs.String("input", "", "analysis input JSON")
	fs.Parse(args)
	require(*store, "--store")
	require(*catalogPath, "--catalog-registry-store")
	require(*mappingPath, "--mapping-registry-store")
	require(*inputPath, "--input")
	catalog := loadCatalog(*catalogPath)
	mappings, err := (alertlistmapping.Store{Root: *mappingPath}).Load(catalog)
	check(err, "load alert-list mapping registry")
	var input providerrefresh.AnalyzeInput
	readJSON(*inputPath, &input)
	candidate, err := providerrefresh.Analyze(input, catalog, mappings)
	check(err, "analyze provider refresh")
	registry, err := (providerrefresh.Store{Root: *store}).AddCandidate(candidate, catalog)
	check(err, "persist refresh candidate")
	encode(map[string]any{"candidate": candidate, "refresh_registry_checksum": registry.RegistryChecksum})
}
func decide(args []string) {
	fs := flag.NewFlagSet("decide", flag.ExitOnError)
	store := fs.String("store", "", "provider refresh state directory")
	catalogPath := fs.String("catalog-registry-store", "", "catalog registry state directory")
	candidate := fs.String("candidate-id", "", "refresh candidate ID")
	action := fs.String("action", "", "approve or reject")
	reason := fs.String("reason", "", "decision reason")
	actor := fs.String("actor", "", "decision actor")
	at := fs.String("at", "", "RFC3339 decision time")
	fs.Parse(args)
	for n, v := range map[string]string{"--store": *store, "--catalog-registry-store": *catalogPath, "--candidate-id": *candidate, "--action": *action, "--reason": *reason, "--actor": *actor, "--at": *at} {
		require(v, n)
	}
	catalog := loadCatalog(*catalogPath)
	d, r, err := (providerrefresh.Store{Root: *store}).Decide(providerrefresh.DecisionInput{CandidateID: *candidate, Action: providerrefresh.DecisionAction(*action), Reason: *reason, DecidedAt: parseTime(*at), DecidedBy: *actor}, catalog)
	check(err, "record promotion decision")
	encode(map[string]any{"decision": d, "refresh_registry_checksum": r.RegistryChecksum})
}
func promote(args []string) {
	fs := flag.NewFlagSet("promote", flag.ExitOnError)
	store := fs.String("store", "", "provider refresh state directory")
	catalogPath := fs.String("catalog-registry-store", "", "catalog registry state directory")
	candidate := fs.String("candidate-id", "", "approved refresh candidate ID")
	reason := fs.String("reason", "", "promotion reason")
	actor := fs.String("actor", "", "promotion actor")
	at := fs.String("at", "", "RFC3339 execution time")
	fs.Parse(args)
	for n, v := range map[string]string{"--store": *store, "--catalog-registry-store": *catalogPath, "--candidate-id": *candidate, "--reason": *reason, "--actor": *actor, "--at": *at} {
		require(v, n)
	}
	e, r, c, err := (providerrefresh.Store{Root: *store}).Promote(providerrefresh.PromoteInput{CandidateID: *candidate, Reason: *reason, ExecutedAt: parseTime(*at), ExecutedBy: *actor}, catalogregistry.Store{Root: *catalogPath})
	check(err, "promote provider refresh")
	encode(map[string]any{"execution": e, "refresh_registry_checksum": r.RegistryChecksum, "catalog_registry_checksum": c.RegistryChecksum})
}
func rollback(args []string) {
	fs := flag.NewFlagSet("rollback", flag.ExitOnError)
	store := fs.String("store", "", "provider refresh state directory")
	catalogPath := fs.String("catalog-registry-store", "", "catalog registry state directory")
	component := fs.String("component-id", "", "stable catalog component ID")
	target := fs.String("target-version-id", "", "previous version ID")
	expected := fs.String("expected-current-version-id", "", "current version CAS precondition")
	reason := fs.String("reason", "", "rollback reason")
	actor := fs.String("actor", "", "rollback actor")
	at := fs.String("at", "", "RFC3339 execution time")
	fs.Parse(args)
	for n, v := range map[string]string{"--store": *store, "--catalog-registry-store": *catalogPath, "--component-id": *component, "--target-version-id": *target, "--expected-current-version-id": *expected, "--reason": *reason, "--actor": *actor, "--at": *at} {
		require(v, n)
	}
	e, r, c, err := (providerrefresh.Store{Root: *store}).Rollback(providerrefresh.RollbackInput{ComponentID: *component, TargetVersionID: *target, ExpectedCurrentVersionID: *expected, Reason: *reason, ExecutedAt: parseTime(*at), ExecutedBy: *actor}, catalogregistry.Store{Root: *catalogPath})
	check(err, "rollback provider catalog")
	encode(map[string]any{"execution": e, "refresh_registry_checksum": r.RegistryChecksum, "catalog_registry_checksum": c.RegistryChecksum})
}
func snapshot(args []string) {
	fs := flag.NewFlagSet("snapshot", flag.ExitOnError)
	store := fs.String("store", "", "provider refresh state directory")
	catalogPath := fs.String("catalog-registry-store", "", "catalog registry state directory")
	output := fs.String("output", "", "optional output path")
	fs.Parse(args)
	require(*store, "--store")
	require(*catalogPath, "--catalog-registry-store")
	catalog := loadCatalog(*catalogPath)
	r, err := (providerrefresh.Store{Root: *store}).Load(catalog)
	check(err, "load provider refresh registry")
	if *output == "" {
		encode(r)
	} else {
		writeJSON(*output, r)
	}
}
func verify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	store := fs.String("store", "", "provider refresh state directory")
	catalogPath := fs.String("catalog-registry-store", "", "catalog registry state directory")
	fs.Parse(args)
	require(*store, "--store")
	require(*catalogPath, "--catalog-registry-store")
	catalog := loadCatalog(*catalogPath)
	r, err := (providerrefresh.Store{Root: *store}).Load(catalog)
	check(err, "verify provider refresh registry")
	encode(map[string]any{"valid": true, "registry_id": r.RegistryID, "namespace": r.Namespace, "candidate_count": len(r.Candidates), "decision_count": len(r.Decisions), "execution_count": len(r.Executions), "last_sequence": r.LastSequence, "audit_head": r.AuditHead, "registry_checksum": r.RegistryChecksum, "catalog_registry_checksum": catalog.RegistryChecksum})
}
func loadCatalog(path string) catalogregistry.Registry {
	r, err := (catalogregistry.Store{Root: path}).Load()
	check(err, "load catalog registry")
	return r
}
func parseTime(v string) time.Time {
	t, err := time.Parse(time.RFC3339, v)
	check(err, "parse time")
	return t.UTC()
}
func readJSON(path string, target any) {
	f, err := os.Open(path)
	check(err, "open "+path)
	defer f.Close()
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	check(d.Decode(target), "decode "+path)
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		fatalf("decode %s: trailing JSON value", path)
	}
}
func writeJSON(path string, v any) {
	f, err := os.Create(path)
	check(err, "create "+path)
	defer f.Close()
	e := json.NewEncoder(f)
	e.SetIndent("", "  ")
	e.SetEscapeHTML(false)
	check(e.Encode(v), "encode "+path)
}
func encode(v any) {
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	e.SetEscapeHTML(false)
	check(e.Encode(v), "encode output")
}
func require(v, n string) {
	if strings.TrimSpace(v) == "" {
		fatalf("%s is required", n)
	}
}
func check(err error, action string) {
	if err != nil {
		fatalf("%s: %v", action, err)
	}
}
func fatalf(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }
