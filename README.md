# OpenWatchlist Platform

OpenWatchlist is a field-aware sanctions and watchlist screening and alert-review
platform. This clean canonical repository begins from a curated, byte-preserving
import of reviewed production code and accepted test fixtures from the preserved
legacy repository.

## Current matching capability

**Table 1 — Matching capability**

| Variant class | Live path | Notes |
| --- | --- | --- |
| Exact normalized name | Supported | Punctuation-stripped, ASCII case-folded |
| Name prefix | Supported | Client-controlled |
| Typed identifier exact | Supported | No scheme validation yet |
| Record ID | Supported | |
| Typo / character transposition | Not supported | Engine exists in internal/matcherbaseline, off the production path; DOM-1 Stage 2 |
| Token reordering | Supported | DOM-1 Stage 1 (ADR-0008): token-sorted query expansion + existing token_set scoring shape |
| Name particles and compounds (AL, BIN, VAN DER) | Supported | DOM-1 Stage 1 (ADR-0008 addendum AD2/AD3): first-token prefix probe + particle_stripped scoring shape |
| Concatenation splitting (KRAYINVESTBANK ↔ KRAY INVEST BANK) | Supported | DOM-1 Stage 1 (ADR-0008 addendum 2 AD4/AD5): single-space-insertion query expansion + concatenation_normalized scoring shape; two-word concatenations only |
| Transliteration / cross-script | Not supported | DOM-1 Stage 2 |
| Phonetic | Not supported | DOM-1 Stage 2 |
| Non-ASCII case variants (Cyrillic, Greek, Arabic) | Not supported | normalize_ascii folds only bytes < 0x80; DOM-13, not DOM-1 (ADR-0008 D4) |

**Table 2 — Supported lists**

| List | Status |
| --- | --- |
| OFAC SDN | Supported |
| OFAC Consolidated (non-SDN) | Not supported |
| OFAC SSI (Sectoral) | Not supported |
| UN | Not supported |
| EU | Not supported |
| UK OFSI | Not supported |
| AU DFAT | Not supported |
| PEP | Not supported |
| Adverse media | Not supported |

Corroborating evidence (date of birth, nationality, sanctions program, place
of birth) is extracted during ingestion but is not carried into the compiled
runtime package, so it is not available on live candidates. See the
[consolidated issue register](docs/backlog/README.md) for tracked work.

## Current scoring capability

**Scoring is now wired into the live HTTP path.** As of ADR-0004 (DOM-3), the
screening API returns scored candidates ranked by relevance over `POST
/v1/screenings` and `POST /v1/screenings/batch`. The `ScreeningResponse`
carries four scoring fields per matched candidate:

- `score` — integer evidence weight across matching rules
- `strength_band` — confidence category (`WEAK`, `MEDIUM`, `STRONG`)
- `reason_codes` — array identifying which rules fired
- `components` — detailed evidence breakdown with per-rule scores

The response also includes a `policy` object with the policy's SHA256 digest
and normalization profile, enabling audit replay against immutable content.

**Critical limitation:** Matching capability remains exact name and prefix only
(Table 1). Scoring applies only to retrieval hits; it does not enable new
matches. Real fuzzy matching in `internal/matcherbaseline` remains off the
production path (DOM-1 gap still open). Corroborating evidence fields
(nationality, dates of birth) cannot be supplied over the HTTP request and
therefore cannot contribute to scoring (half the policy vocabulary is
unreachable — see ADR-0004 §11).

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

**Five security and architecture ADRs have merged since R2.4:**

- **ADR-0001 (SEC-1):** Tenant isolation is now enforced via forced row-level
  security across sixteen Postgres relations, with a verified tenant bound to
  every transaction. Idempotency keys are scoped per tenant.
- **ADR-0002 (REL-10):** The screening API variants (v8d–v8g) have been
  consolidated. `cmd/screening-api` is now the sole screening entrypoint.
- **ADR-0003 (SEC-1b):** Both `alertcaseapi` and `screeningapi` now require
  authenticated bearer tokens (JWT, verified against `reviewauth`). Tenant
  identity is extracted from token claims and validated against request data.
- **ADR-0004 (DOM-3):** Candidate scoring is wired into the live screening
  HTTP path and returns scored, ranked candidates.
- **ADR-0007 (SEC-7):** The audit chain is now HMAC-keyed (PRs #106–#107–#109,
  three stages) and anchored to a separate, role-isolated `screening_ledger_anchor`
  table that a filesystem-write-only or chain-key-holding attacker cannot forge.
  An accepted residual remains: the audit sub-chain specifically has no
  anchor-level protection against an adversary holding the chain key; only the
  event chain is cross-checked against the anchor (ADR-0007 §10 R7: "the audit
  chain has no anchor-level protection against an adversary holding `K_chain`;
  only the event chain does").

The R2.4 result is a controlled homelab qualification, not a production,
customer, regulatory, or compliance certification. The catalog runtime was
qualified with the repository's three-record synthetic conformance fixture, not
with a full production watchlist catalog. The platform remains at zero deployed
traffic anywhere (ADR-0002 §10 finding, unchanged).

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
