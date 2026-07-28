package iso20022coverage

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestPhase9DGoldensAndOrderedBatch(t *testing.T) {
	m := testMatrix(t)
	fixtureDir := filepath.Join("..", "..", "test", "fixtures", "iso20022-phase9d")
	goldenDir := filepath.Join("..", "..", "test", "golden", "iso20022-phase9d")
	files, err := filepath.Glob(filepath.Join(fixtureDir, "*.xml"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	docs := make([]EvidenceEnvelope, 0, len(files))
	for _, path := range files {
		base := filepath.Base(path)
		stem := base[:len(base)-len(filepath.Ext(base))]
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		env, err := Parse(m, "fixture:"+base, data)
		if err != nil {
			t.Fatalf("%s: %v", base, err)
		}
		evidence, err := MarshalCanonical(env)
		if err != nil {
			t.Fatal(err)
		}
		wantEvidence, err := os.ReadFile(filepath.Join(goldenDir, stem+".evidence.json"))
		if err != nil {
			t.Fatal(err)
		}
		if string(evidence) != string(wantEvidence) {
			t.Fatalf("%s evidence golden mismatch", base)
		}
		projection, err := MarshalCanonical(Project(env))
		if err != nil {
			t.Fatal(err)
		}
		wantProjection, err := os.ReadFile(filepath.Join(goldenDir, stem+".projection.json"))
		if err != nil {
			t.Fatal(err)
		}
		if string(projection) != string(wantProjection) {
			t.Fatalf("%s projection golden mismatch", base)
		}
		docs = append(docs, *env)
	}
	batch, err := MarshalCanonical(BuildBatch(docs))
	if err != nil {
		t.Fatal(err)
	}
	wantBatch, err := os.ReadFile(filepath.Join(goldenDir, "all-families.batch.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(batch) != string(wantBatch) {
		t.Fatal("ordered batch golden mismatch")
	}
}
