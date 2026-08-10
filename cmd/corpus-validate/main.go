package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

type Corpus struct {
	SchemaVersion string `json:"schema_version"`
	Coverage      struct {
		ArchetypeCount            int `json:"archetype_count"`
		MinimumCoreScenarios      int `json:"minimum_core_scenarios"`
		MinimumProviderExecutions int `json:"minimum_provider_mode_executions"`
	} `json:"coverage_requirements"`
	Archetypes []Archetype `json:"archetypes"`
}

type Archetype struct {
	ID                  string `json:"id"`
	SourceExampleNumber int    `json:"source_example_number"`
	Title               string `json:"title"`
	RealDataBinding     struct {
		Required                       bool   `json:"required"`
		ProviderSource                 string `json:"provider_source"`
		OpensanctionsCrosswalkRequired bool   `json:"opensanctions_crosswalk_required"`
	} `json:"real_data_binding"`
	SyntheticTransactionRecipe struct {
		SyntheticInnocentSideRequired bool `json:"synthetic_innocent_side_required"`
	} `json:"synthetic_transaction_recipe"`
	Expected struct {
		ProviderLineageRequired          bool     `json:"provider_lineage_required"`
		CatalogActivationLineageRequired bool     `json:"catalog_activation_lineage_required"`
		RegulatoryDisposition            string   `json:"regulatory_disposition"`
		ForbiddenOutcomes                []string `json:"forbidden_outcomes"`
	} `json:"expected_invariants"`
	RequiredControls []string `json:"required_controls"`
	ProviderModes    []string `json:"provider_modes"`
}

type Bindings struct {
	SchemaVersion string `json:"schema_version"`
	Bindings      []struct {
		ArchetypeID string `json:"archetype_id"`
		Status      string `json:"status"`
	} `json:"bindings"`
}

func requireSet(values []string, expected []string, label string) error {
	got := map[string]bool{}
	for _, v := range values {
		got[v] = true
	}
	for _, v := range expected {
		if !got[v] {
			return fmt.Errorf("%s missing %q", label, v)
		}
	}
	return nil
}

func readJSON(path string, out any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func main() {
	root, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	corpusPath := filepath.Join(root, "test", "corpus", "false-positive-archetypes", "archetypes.v1.json")
	bindingPath := filepath.Join(root, "test", "corpus", "false-positive-archetypes", "bindings", "real-ofac-bindings.v1.template.json")

	var corpus Corpus
	if err := readJSON(corpusPath, &corpus); err != nil {
		fail(err)
	}
	if corpus.SchemaVersion != "openwatchlist.homelab.false-positive-archetypes.v1" {
		fail(errors.New("unexpected corpus schema_version"))
	}
	if len(corpus.Archetypes) != 35 || corpus.Coverage.ArchetypeCount != 35 {
		fail(fmt.Errorf("expected 35 archetypes, got %d", len(corpus.Archetypes)))
	}
	if corpus.Coverage.MinimumCoreScenarios < 105 {
		fail(errors.New("minimum_core_scenarios must be at least 105"))
	}
	if corpus.Coverage.MinimumProviderExecutions < 315 {
		fail(errors.New("minimum_provider_mode_executions must be at least 315"))
	}

	ids := map[string]bool{}
	numbers := map[int]bool{}
	requiredControls := []string{"false_positive", "true_positive", "near_negative"}
	requiredModes := []string{"native_ofac", "opensanctions_ofac", "dual_provider"}
	requiredForbidden := []string{"regulatory_clearance", "regulatory_release", "auto_release", "confirmed_false_positive"}

	for i, a := range corpus.Archetypes {
		expectedID := fmt.Sprintf("fp-%03d", i+1)
		if a.ID != expectedID {
			fail(fmt.Errorf("archetype index %d has id %q, expected %q", i, a.ID, expectedID))
		}
		if a.SourceExampleNumber != i+1 {
			fail(fmt.Errorf("%s source example is %d", a.ID, a.SourceExampleNumber))
		}
		if a.Title == "" {
			fail(fmt.Errorf("%s title is empty", a.ID))
		}
		if ids[a.ID] || numbers[a.SourceExampleNumber] {
			fail(fmt.Errorf("duplicate archetype identity %s", a.ID))
		}
		ids[a.ID], numbers[a.SourceExampleNumber] = true, true
		if !a.RealDataBinding.Required || a.RealDataBinding.ProviderSource != "frozen_real_ofac_snapshot" || !a.RealDataBinding.OpensanctionsCrosswalkRequired {
			fail(fmt.Errorf("%s does not require real OFAC plus OpenSanctions crosswalk", a.ID))
		}
		if !a.SyntheticTransactionRecipe.SyntheticInnocentSideRequired {
			fail(fmt.Errorf("%s does not require synthetic innocent side", a.ID))
		}
		if !a.Expected.ProviderLineageRequired || !a.Expected.CatalogActivationLineageRequired {
			fail(fmt.Errorf("%s lineage requirements incomplete", a.ID))
		}
		if a.Expected.RegulatoryDisposition != "not_provided" {
			fail(fmt.Errorf("%s provides regulatory disposition", a.ID))
		}
		if err := requireSet(a.RequiredControls, requiredControls, a.ID+" controls"); err != nil {
			fail(err)
		}
		if err := requireSet(a.ProviderModes, requiredModes, a.ID+" provider modes"); err != nil {
			fail(err)
		}
		if err := requireSet(a.Expected.ForbiddenOutcomes, requiredForbidden, a.ID+" forbidden outcomes"); err != nil {
			fail(err)
		}
	}

	var bindings Bindings
	if err := readJSON(bindingPath, &bindings); err != nil {
		fail(err)
	}
	if bindings.SchemaVersion != "openwatchlist.homelab.real-ofac-bindings.v1" {
		fail(errors.New("unexpected binding schema_version"))
	}
	if len(bindings.Bindings) != 35 {
		fail(fmt.Errorf("expected 35 binding template entries, got %d", len(bindings.Bindings)))
	}
	bindingIDs := make([]string, 0, len(bindings.Bindings))
	for _, b := range bindings.Bindings {
		bindingIDs = append(bindingIDs, b.ArchetypeID)
	}
	sort.Strings(bindingIDs)
	for i, id := range bindingIDs {
		expected := fmt.Sprintf("fp-%03d", i+1)
		if id != expected {
			fail(fmt.Errorf("binding id %q expected %q", id, expected))
		}
	}

	fmt.Printf("False-positive archetype corpus: PASS\n")
	fmt.Printf("Archetypes: %d\n", len(corpus.Archetypes))
	fmt.Printf("Minimum scenarios: %d\n", corpus.Coverage.MinimumCoreScenarios)
	fmt.Printf("Minimum provider-mode executions: %d\n", corpus.Coverage.MinimumProviderExecutions)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "False-positive archetype corpus: FAIL")
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
