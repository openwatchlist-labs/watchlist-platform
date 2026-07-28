#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd); . "$SCRIPT_DIR/common.sh"
VERSION=""; VCS_REF=""; SOURCE_DATE_EPOCH=""; OUT=""
while [ "$#" -gt 0 ]; do case "$1" in --version) VERSION=${2:-};shift 2;; --vcs-ref) VCS_REF=${2:-};shift 2;; --source-date-epoch) SOURCE_DATE_EPOCH=${2:-};shift 2;; --output) OUT=${2:-};shift 2;; *) release_fail "unknown argument: $1";; esac; done
for tool in git go cargo rustc gzip shasum python3; do release_require "$tool"; done
[ -n "$VERSION" ] && [ -n "$VCS_REF" ] && [ -n "$SOURCE_DATE_EPOCH" ] || release_fail "version, vcs ref, and source date epoch required"
case "$SOURCE_DATE_EPOCH" in ''|*[!0-9]*) release_fail "source date epoch must be an integer";; esac
release_require_empty "$OUT"
mkdir -p "$OUT/source" "$OUT/bin" "$OUT/dependencies"
FULL_REF=$(git rev-parse "$VCS_REF^{commit}")
[ "$FULL_REF" = "$VCS_REF" ] || release_fail "vcs-ref must be a full commit SHA"
[ "$(git rev-parse HEAD)" = "$FULL_REF" ] || release_fail "vcs-ref must equal checkout HEAD"
BUILD_DATE=$(release_iso_utc "$SOURCE_DATE_EPOCH")
PREFIX="openwatchlist-${VERSION}/"
git archive --format=tar --prefix="$PREFIX" "$FULL_REF" | gzip -n -9 >"$OUT/source/openwatchlist-${VERSION}.tar.gz"
COMMANDS="platform-api platform-ops release-qualification release-benchmark release-artifact container-healthcheck"
for target in linux/amd64 linux/arm64 darwin/arm64; do
  OS=${target%/*}; ARCH=${target#*/}; mkdir -p "$OUT/bin/$OS-$ARCH"
  for command_name in $COMMANDS; do
    [ -d "cmd/$command_name" ] || release_fail "missing command: cmd/$command_name"
    CGO_ENABLED=0 GOOS=$OS GOARCH=$ARCH SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH \
      go build -trimpath -buildvcs=false -ldflags '-s -w' \
      -o "$OUT/bin/$OS-$ARCH/$command_name" "./cmd/$command_name"
  done
done
RUST_TARGET=$(mktemp -d "${TMPDIR:-/tmp}/openwatchlist-rust-target.XXXXXX")
trap 'rm -rf "$RUST_TARGET"' EXIT HUP INT TERM
CARGO_INCREMENTAL=0 SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH CARGO_TARGET_DIR="$RUST_TARGET" \
  cargo build --manifest-path runtime/catalog-mmap/Cargo.toml --locked --release --bin catalog-mmap
HOST=$(rustc -vV | awk -F': ' '$1=="host"{print $2}')
[ -n "$HOST" ] || release_fail "unable to determine Rust host triple"
mkdir -p "$OUT/bin/rust-$HOST"
cp "$RUST_TARGET/release/catalog-mmap" "$OUT/bin/rust-$HOST/catalog-mmap"
go list -m -f '{{if not .Main}}{{.Path}} {{.Version}} {{.Sum}}{{end}}' all | LC_ALL=C sort >"$OUT/dependencies/go-modules.txt"
cargo tree --manifest-path runtime/catalog-mmap/Cargo.toml --locked --prefix none | LC_ALL=C sort -u >"$OUT/dependencies/cargo-tree.txt"
GO_VERSION=$(go version); RUST_VERSION=$(rustc --version); CARGO_VERSION=$(cargo --version)
python3 - "$OUT/manifest.json" "$VERSION" "$FULL_REF" "$SOURCE_DATE_EPOCH" "$BUILD_DATE" "$HOST" "$GO_VERSION" "$RUST_VERSION" "$CARGO_VERSION" <<'PY_ASSET_MANIFEST'
import json,sys,pathlib
out={'schema':'openwatchlist.public-prerelease-assets.v2','version':sys.argv[2],'vcs_ref':sys.argv[3],'source_date_epoch':int(sys.argv[4]),'build_date':sys.argv[5],'go_targets':['linux/amd64','linux/arm64','darwin/arm64'],'rust_host':sys.argv[6],'toolchains':{'go':sys.argv[7],'rustc':sys.argv[8],'cargo':sys.argv[9]},'publication_performed':False}
pathlib.Path(sys.argv[1]).write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
PY_ASSET_MANIFEST
(cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256) >"$OUT/SHA256SUMS"
echo "PASS: deterministic prerelease asset set built"
echo "Output: $OUT"
