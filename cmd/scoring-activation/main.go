package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/openwatchlist-labs/watchlist-platform/internal/scoringactivation"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "activate":
		err = runActivate(os.Args[2:])
	case "status":
		err = runStatus(os.Args[2:])
	case "rollback":
		err = runRollback(os.Args[2:])
	case "recover":
		err = runRecover(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "scoring-activation:", err)
		os.Exit(1)
	}
}

func managerFlag(args []string, name string) (*scoringactivation.Manager, *flag.FlagSet, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	stateDirectory := flags.String("state-dir", "", "activation state directory")
	if err := flags.Parse(args); err != nil {
		return nil, flags, err
	}
	manager, err := scoringactivation.NewManager(*stateDirectory)
	return manager, flags, err
}

func runActivate(args []string) error {
	flags := flag.NewFlagSet("activate", flag.ContinueOnError)
	stateDirectory := flags.String("state-dir", "", "activation state directory")
	activationID := flags.String("activation-id", "", "immutable activation ID")
	descriptor := flags.String("catalog-descriptor", "", "catalog package descriptor")
	projectionPackage := flags.String("projection-package", "", "checksum-addressed projection package")
	policy := flags.String("policy", "", "scoring policy")
	if err := flags.Parse(args); err != nil {
		return err
	}
	manager, err := scoringactivation.NewManager(*stateDirectory)
	if err != nil {
		return err
	}
	snapshot, err := manager.Activate(scoringactivation.ActivateRequest{
		ActivationID: *activationID, CatalogDescriptorPath: *descriptor,
		ProjectionPackagePath: *projectionPackage, ScoringPolicyPath: *policy,
	})
	if err != nil {
		return err
	}
	return printSnapshot(snapshot)
}

func runStatus(args []string) error {
	manager, _, err := managerFlag(args, "status")
	if err != nil {
		return err
	}
	snapshot, err := manager.LoadActive()
	if err != nil {
		return err
	}
	return printSnapshot(snapshot)
}

func runRollback(args []string) error {
	manager, _, err := managerFlag(args, "rollback")
	if err != nil {
		return err
	}
	snapshot, err := manager.Rollback()
	if err != nil {
		return err
	}
	return printSnapshot(snapshot)
}

func runRecover(args []string) error {
	manager, _, err := managerFlag(args, "recover")
	if err != nil {
		return err
	}
	result, err := manager.Recover()
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "ok", "recovery": result})
}

func printSnapshot(snapshot scoringactivation.Snapshot) error {
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status":                    "ok",
		"activation_id":             snapshot.Activation.ActivationID,
		"previous_activation_id":    snapshot.Activation.PreviousActivationID,
		"catalog_package_sha256":    snapshot.Activation.Catalog.CatalogPackageSHA256,
		"projection_package_sha256": snapshot.Activation.Projection.PackageSHA256,
		"scoring_policy_sha256":     snapshot.Activation.Policy.PolicySHA256,
		"component_id":              snapshot.Activation.Catalog.ComponentID,
		"component_version":         snapshot.Activation.Catalog.ComponentVersion,
		"normalization_profile":     snapshot.Activation.Catalog.NormalizationProfile,
	})
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: scoring-activation <activate|status|rollback|recover> [options]")
	os.Exit(2)
}
