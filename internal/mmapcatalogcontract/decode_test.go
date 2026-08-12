package mmapcatalogcontract

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/openwatchlist-labs/watchlist-platform/internal/runtimecataloginput"
)

// TestReadNormalizationProfileRoundTrip proves the decoder reads back
// exactly the profile a fresh compile wrote, without invoking the Rust
// runtime worker (ADR-0004 §8, §10 item 5: a Go-side read of a value the
// mmap header already stores).
func TestReadNormalizationProfileRoundTrip(t *testing.T) {
	root := filepath.Join("..", "..")
	catalog, err := os.ReadFile(filepath.Join(root, "test/golden/ofac-advanced/ofac-sdn-catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	input, _, err := runtimecataloginput.Export(bytes.NewReader(catalog), "catalog_component_ed835720fdb2b3a505927488")
	if err != nil {
		t.Fatal(err)
	}
	artifact, info, err := Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadNormalizationProfile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if got != info.NormalizationProfile || got == "" {
		t.Fatalf("normalization_profile = %q, want %q (non-empty)", got, info.NormalizationProfile)
	}
}

// TestReadNormalizationProfileRealFixture reads the profile directly out of
// the real compiled runtime package screening-api serves
// (test/golden/runtime-mmap/ofac-fixture.owmmap), cross-checked against its
// companion .info.json -- the artifact ADR-0004 §10 requires DOM-3's
// fixtures to be built against.
func TestReadNormalizationProfileRealFixture(t *testing.T) {
	root := filepath.Join("..", "..")
	raw, err := os.ReadFile(filepath.Join(root, "test/golden/runtime-mmap/ofac-fixture.owmmap"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadNormalizationProfile(raw)
	if err != nil {
		t.Fatal(err)
	}
	const want = "openwatchlist-runtime-normalization/ascii-v1"
	if got != want {
		t.Fatalf("normalization_profile = %q, want %q", got, want)
	}
}

func TestReadNormalizationProfileRejectsGarbage(t *testing.T) {
	cases := [][]byte{
		nil,
		[]byte("too short"),
		append([]byte("NOTMAGIC"), make([]byte, 56)...),
	}
	for _, raw := range cases {
		if _, err := ReadNormalizationProfile(raw); err == nil {
			t.Fatalf("expected error for input %q", raw)
		}
	}
}
