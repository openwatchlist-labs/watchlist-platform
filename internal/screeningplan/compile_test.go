package screeningplan

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompileAndResolvePacs008Plan(t *testing.T) {
	file, err := os.Open(filepath.Join(repoRoot(t), "configs", "screening-plans", "iso20022-pacs008-cbprplus-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	plan, err := Load(file)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile(plan)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.EntryCount() < 30 {
		t.Fatalf("entry count = %d, expected at least 30", compiled.EntryCount())
	}
	entry, err := compiled.Resolve("pacs.008.001.08", "/Document/FIToFICstmrCdtTrf/CdtTrfTxInf[4]/Dbtr/Nm")
	if err != nil {
		t.Fatal(err)
	}
	if entry.SemanticRole != "debtor.name" {
		t.Fatalf("semantic role = %q", entry.SemanticRole)
	}
	if _, err := compiled.Resolve("pacs.008.001.08", "/Document/Unknown"); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("expected ErrNoMatch, got %v", err)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	_, err := Load(strings.NewReader(`{"schema_version":"screening-plan/v1alpha1","id":"x","version":"1","message_definitions":["pacs.008.001.08"],"entries":[],"unexpected":true}`))
	if err == nil {
		t.Fatal("expected unknown field error")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	current, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			t.Fatal("repository root not found")
		}
		current = parent
	}
}
