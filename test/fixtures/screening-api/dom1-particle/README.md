# DOM-1 particle/compound regression fixture

`sdn-particle-fixture.xml` is a synthetic, single-record OFAC Advanced XML fixture (individual
"Klaas van der Berg", carrying the genuine two-word name particle "van der"). It exists because
none of the 3 records in the shared `test/golden/ofac-advanced/ofac-sdn-catalog.json` /
`test/golden/runtime-mmap/ofac-fixture.owmmap` fixture contain a true name particle, so
`internal/screeningapi/dom1_unsupported_regression_test.go`'s "Name particles and compounds
(AL, BIN, VAN DER)" Table 1 regression case previously used an unrelated real vessel record as a
stand-in -- see that file's comments for the full history (issue #115's parent DOM-1 scoping
investigation).

`dom1-particle-fixture.owmmap` is the compiled package the live Rust `catalog-mmap` worker binds
to for that one test. It is a separate, dedicated package rather than an addition to the shared
`ofac-fixture.owmmap`, because that package's exact `package_sha256` is pinned in many places
outside this test (production config, scoring-activation fixtures, `.clean-restart/`
import-manifest.json, and others) that a "small, isolated fix" should not need to touch.

Regenerate deterministically with:

```bash
go run ./cmd/live-catalog-sync ofac \
  --input test/fixtures/screening-api/dom1-particle/sdn-particle-fixture.xml \
  --acquired-at 2026-08-14T00:00:00Z --output-dir <dir>
go run ./cmd/runtime-catalog-input \
  --catalog <dir>/ofac-sdn-catalog.json \
  --component-id catalog_component_b1bed6f60480cb3272a9cf77 \
  --output <dir>/dom1-particle-fixture.owcin
cargo run --manifest-path runtime/catalog-mmap/Cargo.toml --bin catalog-mmap -- \
  compile --input <dir>/dom1-particle-fixture.owcin \
  --output test/fixtures/screening-api/dom1-particle/dom1-particle-fixture.owmmap
```

The fixture is synthetic and does not represent a production sanctions list.
