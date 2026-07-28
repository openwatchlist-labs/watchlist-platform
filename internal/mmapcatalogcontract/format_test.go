package mmapcatalogcontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/runtimecataloginput"
)

func TestReferenceCompilerDeterministic(t *testing.T) {
	root := filepath.Join("..", "..")
	catalog, err := os.ReadFile(filepath.Join(root, "test/golden/ofac-advanced/ofac-sdn-catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	input, _, err := runtimecataloginput.Export(bytes.NewReader(catalog), "catalog_component_ed835720fdb2b3a505927488")
	if err != nil {
		t.Fatal(err)
	}
	first, info, err := Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	second, info2, err := Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || info != info2 {
		t.Fatal("package compilation is not deterministic")
	}
	if string(first[:8]) != Magic || info.RecordCount != 3 || info.PackageLength != uint64(len(first)) {
		t.Fatalf("unexpected package info: %+v", info)
	}
	sum := sha256.Sum256(first)
	if info.PackageSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("package checksum mismatch")
	}
}

func TestNormalizationV1(t *testing.T) {
	if got := NormalizeName("  ACME---HOLDINGS, S.A. "); got != "acme holdings s a" {
		t.Fatalf("name=%q", got)
	}
	if got := NormalizeIdentifier(" P-12 34/56 "); got != "P123456" {
		t.Fatalf("identifier=%q", got)
	}
	if got := NormalizeName("МОСКВА Bank"); got != "МОСКВА bank" {
		t.Fatalf("unicode preservation=%q", got)
	}
}
