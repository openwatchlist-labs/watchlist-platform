# Contributing

1. Create a focused branch and keep generated secrets and release evidence out of Git.
2. Run `gofmt` on Go files and `go test ./...`.
3. Run `./scripts/ci/run-ci.sh`; add focused package tests for the behavior being changed.
4. Add deterministic fixtures and negative tests for changed behavior.
5. Preserve canonical IDs, checksums, replay parity, immutable lineage, tenant isolation, four-eyes controls, and advisory-only LLM boundaries.
6. Document migrations, deployment changes, operational risks, and rollback steps.

Pull requests that weaken false-negative protection, allow LLM decisions to override policy, store complete licensed catalogs in PostgreSQL, bypass audit integrity, or remove release-blocking evidence will not be accepted.
