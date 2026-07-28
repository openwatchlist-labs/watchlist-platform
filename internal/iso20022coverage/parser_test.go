package iso20022coverage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testMatrix(t *testing.T) *Matrix {
	t.Helper()
	m, err := LoadMatrix(filepath.Join("..", "..", "configs", "iso20022", "family-matrix-r1.json"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSupportMatrixHasExplicitCompleteProfileSet(t *testing.T) {
	m := testMatrix(t)
	if got, want := len(m.Families), 14; got != want {
		t.Fatalf("families=%d want=%d", got, want)
	}
	needed := []string{"pacs.008.001.08", "pacs.009.001.08", "pacs.009.001.08.cov", "pacs.004.001.09", "pacs.002.001.12", "camt.056.001.08", "camt.029.001.09", "pain.001.001.09", "pain.002.001.10", "camt.053.001.08", "camt.054.001.08", "camt.026.001.09", "camt.027.001.09", "camt.028.001.11"}
	seen := map[string]bool{}
	for _, f := range m.Families {
		seen[f.ProfileID] = true
	}
	for _, id := range needed {
		if !seen[id] {
			t.Fatalf("missing profile %s", id)
		}
	}
}

func TestAllFixturesParseAndProject(t *testing.T) {
	m := testMatrix(t)
	files, err := filepath.Glob(filepath.Join("..", "..", "test", "fixtures", "iso20022-phase9d", "*.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 14 {
		t.Fatalf("fixtures=%d want=14", len(files))
	}
	seen := map[string]bool{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		env, err := Parse(m, "fixture:"+filepath.Base(f), data)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		seen[env.ProfileID] = true
		if env.EnvelopeSHA256 == "" || env.ElementCount == 0 || env.ScreenableCount == 0 {
			t.Fatalf("%s incomplete envelope: %+v", f, env)
		}
		p := Project(env)
		if len(p.Requests) != env.ScreenableCount || p.ProjectionSHA256 == "" {
			t.Fatalf("%s incomplete projection", f)
		}
		if err := VerifyEnvelope(m, env); err != nil {
			t.Fatalf("%s verify: %v", f, err)
		}
	}
	if len(seen) != 14 {
		t.Fatalf("detected profiles=%d want=14", len(seen))
	}
}

func TestPacs009COVDiscriminator(t *testing.T) {
	m := testMatrix(t)
	data, _ := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", "iso20022-phase9d", "pacs009-cov.xml"))
	env, err := Parse(m, "fixture:pacs009-cov.xml", data)
	if err != nil {
		t.Fatal(err)
	}
	if env.ProfileID != "pacs.009.001.08.cov" {
		t.Fatalf("profile=%s", env.ProfileID)
	}
}

func TestDeterministicOutputAndRepeatedTransactionPaths(t *testing.T) {
	m := testMatrix(t)
	data, _ := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", "iso20022-phase9d", "pacs008.xml"))
	a, err := Parse(m, "fixture:pacs008.xml", data)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse(m, "fixture:pacs008.xml", data)
	if err != nil {
		t.Fatal(err)
	}
	ab, _ := MarshalCanonical(a)
	bb, _ := MarshalCanonical(b)
	if string(ab) != string(bb) {
		t.Fatal("parse output is not deterministic")
	}
	foundIndexed := false
	for _, e := range a.Elements {
		if strings.Contains(e.FieldPath, "CdtTrfTxInf[2]") {
			foundIndexed = true
		}
	}
	if !foundIndexed || a.TransactionCount != 2 {
		t.Fatalf("transaction indexing failed: count=%d", a.TransactionCount)
	}
}

func TestRejectsDirectivesAndUnsupportedProfiles(t *testing.T) {
	m := testMatrix(t)
	bad := []byte(`<!DOCTYPE x [<!ENTITY y "boom">]><Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08"><FIToFICstmrCdtTrf><X>&y;</X></FIToFICstmrCdtTrf></Document>`)
	if _, err := Parse(m, "bad", bad); err == nil {
		t.Fatal("expected directive rejection")
	}
	unsupported := []byte(`<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.999.001.01"><Unknown><Nm>TEST</Nm></Unknown></Document>`)
	if _, err := Parse(m, "unsupported", unsupported); err == nil {
		t.Fatal("expected unsupported profile rejection")
	}
}
