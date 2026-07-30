# OpenWatchlist Platform

OpenWatchlist is a field-aware sanctions and watchlist screening and alert-review
platform. This clean canonical repository begins from a curated, byte-preserving
import of reviewed production code and accepted test fixtures from the preserved
legacy repository.

## Current governed status

The public repository has progressed beyond its clean-restart baseline:

- **Clean Restart R1.6** established the curated Go module, Rust workspace,
  provenance controls, and inherited-debt governance.
- **R2.1–R2.3** reconstructed public repository governance, CodeQL, release
  qualification, and prerelease publication.
- **`v0.1.0-rc.4`** is the current governed prerelease, built from commit
  `210dc3c00d43f4f4e9ceae6905c24c9c9ea99584`.
- **R2.4 r1.8.3.4** completed controlled four-role homelab deployment, smoke
  testing, full rollback qualification, and controlled reactivation.

The R2.4 result is a controlled homelab qualification, not a production,
customer, regulatory, or compliance certification. The catalog runtime was
qualified with the repository's three-record synthetic conformance fixture, not
with a full production watchlist catalog.

See:

- `docs/governance/public-release-lineage.md`
- `docs/governance/legacy-repository.md`
- `docs/governance/legacy-qualification-lineage.md`
- `docs/homelab/r2-4/README.md`
- `scripts/deployment/r2-4/README.md`

## Clean-restart foundation

The R1.6 baseline contains:

- the canonical Go module and Rust workspace;
- production application, runtime, configuration, migration, fixture, and
  golden code selected by the reviewed import policy;
- an exact Rust `1.97.1` toolchain declaration;
- fresh CI, CodeQL, Dependabot, provenance, and legacy-exclusion controls;
- exact, source-bound governance for inherited whitespace and Rust formatting
  debt without rewriting accepted source bytes.

It does not carry forward legacy Git history, inherited GitHub workflows,
generated qualification evidence, customer data, private credentials, runtime
state, or fixed private-network configuration.

## Developer validation

```bash
./scripts/ci/verify-clean-restart.sh
./scripts/ci/verify-homelab-r2-4-publication.sh
python3 ./scripts/ci/verify-legacy-lineage.py
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

Public R2.4 documentation records release identities, role boundaries,
qualification contracts, synthetic fixture identities, and sanitized closure
results. The preserved pre-clean-restart repository is governed as a private,
read-only archive; only sanitized lineage and current reproducible controls are
carried into this canonical repository. Private host addresses, usernames, secret material, container IDs,
absolute workstation paths, and generated evidence directories are excluded.

## Security and governance

LLM output is advisory and cannot replace deterministic screening evidence,
policy controls, four-eyes review, or human decision ownership. Do not commit
credentials, private keys, customer information, generated qualification
evidence, or runtime data. See `SECURITY.md`,
`docs/governance/clean-restart-r1.md`, and
`docs/homelab/r2-4/publication-boundary.md`.

## Public fixture and dependency posture

Committed watchlist and provider fixtures are synthetic. Deterministic key-like
test vectors are documented in `test/fixtures/README.md` and are prohibited from
production use. Third-party format and licensing references are described in
`THIRD_PARTY_NOTICES.md`.

## License

Apache License 2.0. See `LICENSE`, `NOTICE`, and `THIRD_PARTY_NOTICES.md`.
