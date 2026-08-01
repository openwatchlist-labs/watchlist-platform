#!/usr/bin/env bash
#
# verify-rust-mmap-compatibility.sh
#
# ============================================================================
# HONESTY NOTICE, READ BEFORE RUNNING OR TRUSTING THIS SCRIPT
# ============================================================================
# This script was written by an assistant that does NOT have a working Rust
# toolchain matching this repo's requirement (rust-toolchain.toml specifies
# channel = "stable"; only Rust 1.75.0 was available via apt in that
# environment, and rustup/static.rust-lang.org were not reachable due to
# network restrictions). Every command below is designed carefully and
# grounded in reading the actual Rust source
# (runtime/catalog-mmap/src/bin/catalog-mmap.rs) and the actual committed
# fixtures, but IT HAS NEVER BEEN RUN END TO END BY ITS AUTHOR. Treat it as
# a well-reasoned draft, not a verified tool, until you've run it yourself
# and it's produced the PASS output below.
#
# What IS independently verified already, with no Rust required (see
# internal/projectionpackage/rust_compat_test.go, part of the normal
# `go test ./...` suite):
#   1. Go's projection-package compiler is deterministic and reproduces the
#      committed test/fixtures/projection-package/packages/.../projections.json
#      byte-for-byte.
#   2. The committed test/fixtures/projection-package/catalog-fixture.mmap
#      (the actual Rust-compiled binary) has exactly the SHA-256 that
#      catalog-descriptor.json records for it.
#
# What this script attempts to close - the one remaining, genuinely
# unverified link: does running the ACTUAL Rust catalog-mmap compiler
# TODAY, against a FRESH Go-generated projections.json, reproduce that
# same recorded checksum? If yes, that's about as strong a cross-language
# compatibility proof as this contract can offer. If no, that's a real,
# important finding - either genuine format drift, or the original fixture
# was built with a different Rust compiler version than what's installed
# now (also worth knowing).
# ============================================================================
#
# Usage:
#   ./verify-rust-mmap-compatibility.sh /path/to/local/watchlist-platform
#
set -euo pipefail

log()  { printf '\n\033[1;34m==>\033[0m %s\n' "$1"; }
fail() { printf '\n\033[1;31mERROR:\033[0m %s\n' "$1" >&2; exit 1; }
warn() { printf '\n\033[1;33mWARNING:\033[0m %s\n' "$1"; }

REPO_DIR="${1:-}"
[ -n "$REPO_DIR" ] || fail "Usage: $0 /path/to/local/watchlist-platform"
[ -d "$REPO_DIR" ] || fail "Directory not found: $REPO_DIR"
cd "$REPO_DIR"

log "Checking this is actually a watchlist-platform clone"
[ -f go.mod ] || fail "$REPO_DIR has no go.mod - is this really the repo root?"
grep -q "module github.com/openwatchlist-labs/watchlist-platform" go.mod \
  || fail "go.mod module path doesn't match github.com/openwatchlist-labs/watchlist-platform - refusing to proceed."
[ -f Cargo.toml ] || fail "No Cargo.toml at repo root - expected the catalog-mmap Rust workspace here."

log "Checking Rust toolchain"
command -v cargo >/dev/null 2>&1 || fail "cargo not found on PATH. Install Rust (see rust-toolchain.toml for the expected channel) before running this script."
echo "cargo: $(cargo --version)"
echo "rustc: $(rustc --version 2>/dev/null || echo 'not found separately - check cargo above')"
if [ -f rust-toolchain.toml ]; then
  echo "Repo's rust-toolchain.toml requirement:"
  cat rust-toolchain.toml
fi

log "Checking Go toolchain (needed to regenerate projections.json)"
command -v go >/dev/null 2>&1 || fail "go not found on PATH."

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
echo "Working directory: $WORKDIR"

log "Step 1: regenerate the projection package fresh via Go (already independently verified deterministic)"
go run ./cmd/projection-package compile \
  -catalog-descriptor test/fixtures/projection-package/catalog-descriptor.json \
  -input test/fixtures/projection-package/canonical-input.json \
  -output-root "$WORKDIR/go-output" \
  || fail "Go projection-package compile failed - stop here, this should always succeed (see internal/projectionpackage/rust_compat_test.go, which passes independently of this script)."

PROJECTIONS_JSON=$(find "$WORKDIR/go-output" -name projections.json)
[ -n "$PROJECTIONS_JSON" ] || fail "Could not find generated projections.json under $WORKDIR/go-output"
echo "Generated: $PROJECTIONS_JSON"

log "Step 2: build the Rust catalog-mmap compiler (release mode, matching production)"
cargo build --release --manifest-path runtime/catalog-mmap/Cargo.toml \
  || fail "cargo build failed. If this is a Rust version mismatch against rust-toolchain.toml, that's itself useful information about the compatibility question this script exists to answer - don't just retry with a different toolchain without noting that."

CATALOG_MMAP_BIN="target/release/catalog-mmap"
[ -x "$CATALOG_MMAP_BIN" ] || fail "Expected built binary not found at $CATALOG_MMAP_BIN after cargo build."

log "Step 3: compile the fresh Go-generated projections.json via the Rust compiler"
FRESH_MMAP="$WORKDIR/fresh.mmap"
"$CATALOG_MMAP_BIN" compile --input "$PROJECTIONS_JSON" --output "$FRESH_MMAP" \
  || fail "catalog-mmap compile failed against the Go-generated projections.json - this itself may be the incompatibility issue #13 is asking about. Do not treat this failure as a script bug without first checking whether the Rust compiler's expected input schema has diverged from what internal/projectionpackage currently emits."

log "Step 4: compare against the recorded and previously-committed checksums"
EXPECTED_SHA=$(python3 -c "import json; print(json.load(open('test/fixtures/projection-package/catalog-descriptor.json'))['catalog_package_sha256'])")
FRESH_SHA=$(sha256sum "$FRESH_MMAP" | awk '{print $1}')
COMMITTED_SHA=$(sha256sum test/fixtures/projection-package/catalog-fixture.mmap | awk '{print $1}')

echo "Recorded in catalog-descriptor.json:        $EXPECTED_SHA"
echo "Committed test fixture catalog-fixture.mmap: $COMMITTED_SHA"
echo "Freshly Rust-compiled from Go output today:  $FRESH_SHA"

if [ "$FRESH_SHA" = "$EXPECTED_SHA" ]; then
  echo
  echo "PASS: fresh Rust compilation of today's Go projection output reproduces"
  echo "the exact checksum recorded in catalog-descriptor.json. This is real,"
  echo "positive evidence that the Go projection pipeline and the Rust"
  echo "catalog-mmap compiler agree on this fixture, verified end to end today."
else
  warn "MISMATCH: fresh Rust compilation produced a DIFFERENT checksum than
what's recorded and committed. This does not necessarily mean the two
toolchains are incompatible - possible explanations, in rough order of
likelihood, worth checking before concluding anything:
  1. The installed Rust/cargo version differs from whatever produced the
     original committed catalog-fixture.mmap - mmap binary formats can
     be sensitive to exact toolchain version even for 'the same' logical
     content (e.g. struct padding, endianness assumptions baked in at
     compile time).
  2. Genuine format drift between internal/projectionpackage's current
     output and what runtime/catalog-mmap/src/input.rs currently expects.
  3. This script itself has a bug - it was never run end to end before
     being handed off (see the honesty notice at the top of this file)."
fi

log "Step 5 (bonus, not pass/fail): a few lookup queries against the freshly compiled package, for manual inspection"
echo "--- lookup-name 'Acme Trading LLC' (exact) ---"
"$CATALOG_MMAP_BIN" lookup-name --package "$FRESH_MMAP" --query "ACME TRADING LLC" || warn "lookup-name failed - inspect manually"
echo "--- lookup-name 'Jane Doe' (exact) ---"
"$CATALOG_MMAP_BIN" lookup-name --package "$FRESH_MMAP" --query "JANE DOE" || warn "lookup-name failed - inspect manually"
echo "--- inspect package info ---"
"$CATALOG_MMAP_BIN" inspect --package "$FRESH_MMAP" || warn "inspect failed - inspect manually"

log "Done. Read the PASS/MISMATCH result above carefully - this script does not auto-fix anything or file any issue on your behalf."
