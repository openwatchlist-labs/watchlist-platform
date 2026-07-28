# OpenWatchlist Platform

OpenWatchlist is a field-aware sanctions and watchlist screening and alert-review
platform. This clean canonical repository begins from a curated, byte-preserving
import of reviewed production code and accepted test fixtures from the preserved
legacy repository.

## Clean-restart status

This baseline is **OpenWatchlist Clean Restart R1.6**. It contains:

- the canonical Go module and Rust workspace;
- production application, runtime, configuration, migration, fixture, and
  golden code selected by the reviewed import policy;
- an exact Rust `1.97.1` toolchain declaration;
- fresh CI, CodeQL, Dependabot, provenance, and legacy-exclusion controls;
- exact, source-bound governance for inherited whitespace and Rust formatting
  debt without rewriting accepted source bytes.

It does not carry forward legacy Git history, inherited GitHub workflows, Phase
11 release orchestration, fixed-host homelab deployment, H1 qualification
scripts, generated candidates, evidence, results, materialized selectors, or
movable legacy toolchain declarations.

No release, deployment, homelab qualification, or regulatory disposition is
claimed by this baseline. Those capabilities must be rebuilt and qualified in
later governed changes.

## Developer validation

```bash
./scripts/ci/verify-clean-restart.sh
./scripts/ci/run-ci.sh
```

Normal CI validates durable provenance without freezing legitimate changes.
Exact inherited exceptions remain active only while the corresponding imported
file hash is unchanged. Once a file is reviewed, changed, and clean, its
exception retires automatically. New whitespace and new Rust formatting drift
remain prohibited.

## Provenance

Bootstrap provenance under `.clean-restart/` includes the immutable legacy
commit and tree, every imported source hash, the complete import plan, the
historical staged-baseline hashes, source-bound inherited-debt baselines, and
the bootstrap journal.

## Security and governance

LLM output is advisory and cannot replace deterministic screening evidence,
policy controls, four-eyes review, or human decision ownership. Do not commit
credentials, private keys, customer information, generated qualification
evidence, or runtime data. See `SECURITY.md` and
`docs/governance/clean-restart-r1.md`.

## Public fixture and dependency posture

Committed watchlist and provider fixtures are synthetic. Deterministic key-like
test vectors are documented in `test/fixtures/README.md` and are prohibited from
production use. Third-party format and licensing references are described in
`THIRD_PARTY_NOTICES.md`.

## License

Apache License 2.0. See `LICENSE`, `NOTICE`, and `THIRD_PARTY_NOTICES.md`.
