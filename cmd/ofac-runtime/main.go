package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogruntime"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacruntime"
)

func main() {
	command := flag.String("command", "inspect", "compile, inspect, readiness, activate, or rollback")
	catalogPath := flag.String("catalog", "", "OFAC direct-list catalog JSON for compile")
	packagePath := flag.String("package", "", "compiled .owpcat package path")
	stateDir := flag.String("state-dir", "", "runtime activation state directory")
	compiledAtRaw := flag.String("compiled-at", "", "RFC3339 compilation time for readiness and activation records")
	checkedAtRaw := flag.String("checked-at", "", "RFC3339 readiness-check time")
	activatedAtRaw := flag.String("activated-at", "", "RFC3339 activation time")
	reason := flag.String("reason", "", "rollback reason")
	compact := flag.Bool("compact", false, "emit compact JSON")
	flag.Parse()
	if flag.NArg() != 0 {
		usage("unexpected positional arguments")
	}

	var output any
	switch *command {
	case "compile":
		if *catalogPath == "" || *packagePath == "" {
			usage("compile requires --catalog and --package")
		}
		catalogFile, err := os.Open(*catalogPath)
		check(err, "open catalog")
		catalog, err := ofaccatalog.Load(catalogFile)
		_ = catalogFile.Close()
		check(err, "load catalog")
		artifact, info, err := ofacruntime.Compile(catalog)
		check(err, "compile runtime package")
		check(writeAtomic(*packagePath, artifact, 0o644), "write runtime package")
		output = info
	case "inspect":
		loaded := loadPackage(*packagePath)
		output = loaded.Info
	case "readiness":
		loaded := loadPackage(*packagePath)
		compiledAt := parseTime(*compiledAtRaw, "--compiled-at")
		checkedAt := parseTime(*checkedAtRaw, "--checked-at")
		report, err := ofacruntime.Readiness(loaded, compiledAt, checkedAt)
		check(err, "evaluate readiness")
		output = report
	case "activate":
		if *stateDir == "" {
			usage("activate requires --state-dir")
		}
		data, loaded := loadPackageBytes(*packagePath)
		compiledAt := parseTime(*compiledAtRaw, "--compiled-at")
		checkedAt := parseTime(*checkedAtRaw, "--checked-at")
		activatedAt := parseTime(*activatedAtRaw, "--activated-at")
		report, err := ofacruntime.Readiness(loaded, compiledAt, checkedAt)
		check(err, "evaluate readiness")
		input, err := ofacruntime.ActivationInput(loaded, compiledAt)
		check(err, "prepare activation input")
		store := catalogruntime.StateStore{Root: *stateDir}
		_, err = store.PersistPackage(loaded.Info.PackageID, loaded.Info.PackageChecksum, ".owpcat", data)
		check(err, "stage immutable package")
		_, err = store.PersistReadiness(report)
		check(err, "persist readiness")
		record, err := store.Activate(input, report, activatedAt)
		check(err, "activate package")
		output = record
	case "rollback":
		if *stateDir == "" || *reason == "" {
			usage("rollback requires --state-dir and --reason")
		}
		data, loaded := loadPackageBytes(*packagePath)
		compiledAt := parseTime(*compiledAtRaw, "--compiled-at")
		checkedAt := parseTime(*checkedAtRaw, "--checked-at")
		activatedAt := parseTime(*activatedAtRaw, "--activated-at")
		report, err := ofacruntime.Readiness(loaded, compiledAt, checkedAt)
		check(err, "evaluate readiness")
		input, err := ofacruntime.ActivationInput(loaded, compiledAt)
		check(err, "prepare rollback input")
		store := catalogruntime.StateStore{Root: *stateDir}
		_, err = store.PersistPackage(loaded.Info.PackageID, loaded.Info.PackageChecksum, ".owpcat", data)
		check(err, "stage immutable package")
		_, err = store.PersistReadiness(report)
		check(err, "persist readiness")
		envelope, err := store.Rollback(input, report, *reason, activatedAt)
		check(err, "rollback package")
		output = envelope
	default:
		usage(fmt.Sprintf("unsupported --command %q", *command))
	}

	encoder := json.NewEncoder(os.Stdout)
	if !*compact {
		encoder.SetIndent("", "  ")
	}
	encoder.SetEscapeHTML(false)
	check(encoder.Encode(output), "encode output")
}

func loadPackage(path string) *ofacruntime.LoadedPackage {
	_, loaded := loadPackageBytes(path)
	return loaded
}

func loadPackageBytes(path string) ([]byte, *ofacruntime.LoadedPackage) {
	if path == "" {
		usage("--package is required")
	}
	data, err := os.ReadFile(path)
	check(err, "read runtime package")
	loaded, err := ofacruntime.Load(data)
	check(err, "load runtime package")
	return data, loaded
}

func parseTime(value, flagName string) time.Time {
	if value == "" {
		usage(flagName + " is required")
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	check(err, "parse "+flagName)
	return parsed.UTC()
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".runtime-package-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
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
	return os.Rename(tmpPath, path)
}

func usage(message string) {
	fmt.Fprintln(os.Stderr, message)
	fmt.Fprintln(os.Stderr, "usage: ofac-runtime [flags]")
	flag.PrintDefaults()
	os.Exit(2)
}

func check(err error, operation string) {
	if err == nil || err == io.EOF {
		return
	}
	fmt.Fprintf(os.Stderr, "%s: %v\n", operation, err)
	os.Exit(1)
}
