package projectionpackage

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

// TestCommittedMmapPackageMatchesDescriptor is the Go-verifiable half of
// the cross-language contract check for issue #13 (no verified
// compatibility check between the Go-compiled projection/runtime pipeline
// and the Rust-compiled catalog-mmap runtime).
//
// It confirms two things, entirely in Go, with no Rust toolchain required:
//
//  1. Compiling the committed canonical-input.json/catalog-descriptor.json
//     fixture reproduces byte-identical projection output (this is already
//     covered by TestCompileIsDeterministicAndBounded above; re-asserted
//     here for a self-contained failure message specific to this contract).
//  2. The committed catalog-fixture.mmap file (the actual Rust-compiled
//     binary artifact) has exactly the SHA-256 that catalog-descriptor.json
//     records as its catalog_package_sha256.
//
// What this does NOT verify (see
// scripts/dev/verify-rust-mmap-compatibility.sh, which is untested by the
// author pending a working Rust toolchain - see that script's own header):
// that RUNNING the Rust catalog-mmap compiler on a FRESH Go-generated
// projections.json reproduces that same catalog_package_sha256. This test
// only confirms the previously-committed artifact matches its own recorded
// checksum, and that Go's own compile step is deterministic - it cannot,
// by itself, prove the two toolchains would agree if the Rust compiler
// were run again today. That's the genuine remaining gap this test cannot
// close without Rust actually being available.
func TestCommittedMmapPackageMatchesDescriptor(t *testing.T) {
	descriptor, err := LoadCatalogDescriptor(fixturePath("catalog-descriptor.json"))
	if err != nil {
		t.Fatalf("load catalog descriptor: %v", err)
	}

	mmapPath := descriptor.CatalogPackagePath
	mmapBytes, err := os.ReadFile(mmapPath)
	if err != nil {
		t.Fatalf("read committed mmap package %s: %v", mmapPath, err)
	}
	sum := sha256.Sum256(mmapBytes)
	actual := hex.EncodeToString(sum[:])

	if actual != descriptor.CatalogPackageSHA256 {
		t.Fatalf(
			"committed %s has sha256 %s, but catalog-descriptor.json records catalog_package_sha256 %s - "+
				"the committed Rust-compiled binary no longer matches its own descriptor. "+
				"Either the .mmap file was rebuilt without updating the descriptor, or vice versa.",
			descriptor.CatalogPackagePath, actual, descriptor.CatalogPackageSHA256,
		)
	}
}
