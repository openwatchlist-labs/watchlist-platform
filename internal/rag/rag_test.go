package rag

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFixtureSnapshotAndRetrieval(t *testing.T) {
	root := filepath.Join("..", "..")
	manifestPath := filepath.Join(root, "test", "fixtures", "rag", "corpus-manifest.json")
	manifest, err := LoadManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := BuildSnapshot(manifestPath, manifest)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := LoadPolicy(filepath.Join(root, "configs", "rag", "retrieval-policy-r1.json"))
	if err != nil {
		t.Fatal(err)
	}
	query, err := LoadQuery(filepath.Join(root, "test", "fixtures", "rag", "entity-type-query.json"))
	if err != nil {
		t.Fatal(err)
	}
	retriever, err := NewRetriever(snapshot, policy)
	if err != nil {
		t.Fatal(err)
	}
	first, err := retriever.Retrieve(query)
	if err != nil {
		t.Fatal(err)
	}
	second, err := retriever.Retrieve(query)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("retrieval is not deterministic")
	}
	if first.Summary.ExcludedInstructionLikeChunks != 1 {
		t.Fatalf("expected one instruction-like exclusion, got %+v", first.Summary)
	}
	if first.Summary.ExcludedUnapprovedOrIneffective != 3 {
		t.Fatalf("expected three unapproved/ineffective documents, got %+v", first.Summary)
	}
	if len(first.Citations) != policy.MaxResults {
		t.Fatalf("expected %d citations, got %d", policy.MaxResults, len(first.Citations))
	}
	if first.Citations[0].SourceID != "validated-cases-r1" {
		t.Fatalf("unexpected top citation: %s", first.Citations[0].SourceID)
	}
	for _, citation := range first.Citations {
		if citation.SourceID == "draft-policy-r1" || citation.SourceID == "institution-policy-old" || citation.SourceID == "hostile-content-r1" {
			t.Fatalf("prohibited source returned: %s", citation.SourceID)
		}
		if citation.Excerpt == "" {
			t.Fatal("empty citation excerpt")
		}
	}
}

func TestManifestChecksumAndStrictJSON(t *testing.T) {
	root := filepath.Join("..", "..")
	path := filepath.Join(root, "test", "fixtures", "rag", "corpus-manifest.json")
	manifest, err := LoadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	manifest.CorpusVersion = "changed"
	if err := ValidateManifest(manifest); err == nil {
		t.Fatal("checksum drift was accepted")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	raw["unknown_field"] = true
	changed, _ := json.Marshal(raw)
	tmp := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(tmp, changed, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(tmp); err == nil {
		t.Fatal("unknown manifest field was accepted")
	}
}

func TestTenantIsolation(t *testing.T) {
	root := filepath.Join("..", "..")
	manifestPath := filepath.Join(root, "test", "fixtures", "rag", "corpus-manifest.json")
	manifest, _ := LoadManifest(manifestPath)
	snapshot, _ := BuildSnapshot(manifestPath, manifest)
	policy, _ := LoadPolicy(filepath.Join(root, "configs", "rag", "retrieval-policy-r1.json"))
	query, _ := LoadQuery(filepath.Join(root, "test", "fixtures", "rag", "entity-type-query.json"))
	query.TenantID = "tenant-b"
	query.QueryID = stableQueryID(query)
	retriever, _ := NewRetriever(snapshot, policy)
	pkg, err := retriever.Retrieve(query)
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Summary.ExcludedTenantOrScope == 0 {
		t.Fatal("expected tenant-scoped documents to be excluded")
	}
	for _, citation := range pkg.Citations {
		if citation.TenantID == "tenant-a" {
			t.Fatal("cross-tenant citation leak")
		}
	}
}
