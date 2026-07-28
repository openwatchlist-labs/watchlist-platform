package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/openwatchlist-labs/watchlist-platform/internal/projectionpackage"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "compile":
		err = runCompile(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "inspect":
		err = runVerify(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "projection-package:", err)
		os.Exit(1)
	}
}

func runCompile(args []string) error {
	flags := flag.NewFlagSet("compile", flag.ContinueOnError)
	descriptorPath := flags.String("catalog-descriptor", "", "catalog package descriptor JSON")
	inputPath := flags.String("input", "", "canonical projection input JSON")
	outputRoot := flags.String("output-root", "", "checksum-addressed package root")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *descriptorPath == "" || *inputPath == "" || *outputRoot == "" {
		return fmt.Errorf("--catalog-descriptor, --input, and --output-root are required")
	}
	descriptor, err := projectionpackage.LoadCatalogDescriptor(*descriptorPath)
	if err != nil {
		return err
	}
	input, err := projectionpackage.LoadCanonicalInput(*inputPath)
	if err != nil {
		return err
	}
	pkg, err := projectionpackage.Compile(descriptor, input, *outputRoot)
	if err != nil {
		return err
	}
	return printPackage(pkg)
}

func runVerify(args []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	packagePath := flags.String("package", "", "checksum-addressed projection package directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *packagePath == "" {
		return fmt.Errorf("--package is required")
	}
	pkg, err := projectionpackage.LoadPackage(*packagePath)
	if err != nil {
		return err
	}
	return printPackage(pkg)
}

func printPackage(pkg projectionpackage.Package) error {
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status":                 "ok",
		"package_directory":      pkg.Directory,
		"package_sha256":         pkg.PackageSHA256,
		"catalog_package_sha256": pkg.Manifest.CatalogPackageSHA256,
		"component_id":           pkg.Manifest.ComponentID,
		"component_version":      pkg.Manifest.ComponentVersion,
		"normalization_profile":  pkg.Manifest.NormalizationProfile,
		"projection_count":       pkg.Manifest.ProjectionCount,
		"projections_sha256":     pkg.Manifest.ProjectionsSHA256,
	})
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: projection-package <compile|verify|inspect> [options]")
	os.Exit(2)
}
