# Contributing

## Getting started

Toolchain requirements, from this repo's own version files (check
`go.mod` / `rust-toolchain.toml` directly if this drifts):

- **Go 1.23+** (`go.mod` currently requires `go 1.23.0`) - needed for
  everything Go: the matching engine, all `cmd/` tools, and the test
  suite.
- **Rust 1.97.1** (`rust-toolchain.toml` currently pins this exact
  version) - only needed if you're working on `runtime/catalog-mmap` or
  verifying `scripts/dev/verify-rust-mmap-compatibility.sh` (see issue
  #13). Not needed for ordinary Go development, `go build ./...`, or
  `go test ./...` - the Go side has no Rust dependency at build or test
  time.

Build and test:

```bash
go build ./...
go test ./...
```

A concrete example that actually works, so you have something visibly
running within your first few minutes (this exact command is
independently verified in `docs/TEST_DATA.md`, not just described here):

```bash
go run ./cmd/matcher-run \
  -provider ofac-baseline \
  -catalog test/golden/ofac/ofac-sdn-fixture.runtime.owpcat \
  -matcher-profiles configs/matcher-profiles/ofac-name-baseline-r1.json \
  -input requests -output results \
  test/golden/iso20022/pacs008/pacs008-basic.matcher-requests.json
```

This feeds a real, committed request batch through the actual
fuzzy-matching engine against a synthetic OFAC fixture and reproduces the
committed golden result. See `docs/TEST_DATA.md` for more entry points
into this repo's fixture data, and `docs/ARCHITECTURE.md` for how the
pieces fit together before making a larger change.

`./scripts/ci/run-ci.sh` is the full pre-merge check this project's CI
runs - heavier than the above (it also needs Python 3, and runs
release-qualification and clean-restart verification steps), not
something you need for ordinary day-to-day development.

## Contribution checklist

1. Create a focused branch and keep generated secrets and release evidence out of Git.
2. Run `gofmt` on Go files and `go test ./...`.
3. Run `./scripts/ci/run-ci.sh`; add focused package tests for the behavior being changed.
4. Add deterministic fixtures and negative tests for changed behavior.
5. Preserve canonical IDs, checksums, replay parity, immutable lineage, tenant isolation, four-eyes controls, and advisory-only LLM boundaries.
6. Document migrations, deployment changes, operational risks, and rollback steps.

Pull requests that weaken false-negative protection, allow LLM decisions to override policy, store complete licensed catalogs in PostgreSQL, bypass audit integrity, or remove release-blocking evidence will not be accepted.
