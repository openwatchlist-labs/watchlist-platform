# Restored legacy design documentation

**Status:** historical record — not living documentation.

These documents were written in the pre-restart legacy repository
(`watchlist-platform-legacy`, frozen at commit
`31aa23f516018f7577f4dcec95142f981142a6f8`) and were dropped during the
clean restart because the import only pulled from `docs/architecture/`,
`docs/design/`, and `docs/security/`, while the legacy repo kept this
material flat at `docs/*.md`. They were restored under SAL-4, SAL-5,
SAL-6, and SAL-9 as byte-preserving copies of the frozen legacy source,
with one documented exception: 12 metadata lines across 6 files used a
Markdown hard-line-break (two trailing spaces) that trips this
repository's whitespace CI gate on new content (see `CLAUDE.md`, "Markdown
hard-line-breaks trip the whitespace gate on new content"). Those
hard-breaks were replaced with an ordinary blank-line paragraph break
between the affected metadata fields — not simply stripped — so the
fields still render on separate lines; only the raw byte-for-byte
whitespace changed, not any wording. Nothing else here was rewritten,
re-wrapped, or fact-checked against the current codebase.

**Read these as intent, not as fact.** They describe what each phase was
*designed* to do at the time it was written. Large parts of that intent
were never built, were built and later removed, or were built differently
from what's described here — most notably, the matching and persistence
layers described across the Phase 3–9 documents are explicitly **not**
production-capable today (see the top-level `CLAUDE.md`). Do not use these
documents to answer "does the system currently do X" — use the issue
register (`DOM-*`, `SEC-*`, `REL-*`, `SAL-*`, `DOC-*`) and the current
source tree for that.

`docs/design/architecture-legacy.md` is the legacy repo's `architecture.md`
renamed to avoid colliding with the current, maintained
[`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) — the two describe different
systems at different points in time and should not be conflated.

**Superseded instruction:** [`docs/design/phase8-runtime-operations.md`](phase8-runtime-operations.md)
(§ topology, around line 27) instructs new deployment work to "target
`screening-api-v8g` as the public boundary." That instruction is stale by
construction — see
[ADR-0002 §2](../adr/0002-screening-api-consolidation.md#2-record-correction-which-document-is-authoritative)
— and superseded by ADR-0002, which deletes `v8d`–`v8g` under REL-10 and
establishes `internal/screeningapi` / `cmd/screening-api` as the sole
screening implementation. The file itself is left unedited to preserve its
byte-for-byte fidelity to the restored legacy source (see above); this note
is the correction of record.

**Database copies guidance:** [`docs/design/deployment.md`](deployment.md)
(§ backup and recovery) describes legacy procedures for database copies, clones,
and restores. For current, correct guidance aligned with SEC-7's audit chain
integrity requirements, see [`docs/operations/sec7-database-copies.md`](../operations/sec7-database-copies.md).
The deployment.md file itself is left unedited to preserve its byte-for-byte
fidelity to the restored legacy source (see above); this note is the current
guidance of record.

## Restored documents

| File | Subject | Phase / subsystem |
| --- | --- | --- |
| [`docs/design/architecture-legacy.md`](architecture-legacy.md) | Architecture | Overall system architecture (legacy) |
| [`docs/design/deployment.md`](deployment.md) | Deployment guide | Deployment |
| [`docs/design/iso20022-screening.md`](iso20022-screening.md) | ISO 20022 Screening Architecture | ISO 20022 screening |
| [`docs/design/list-provider-strategy.md`](list-provider-strategy.md) | List Provider Strategy | List provider strategy |
| [`docs/design/list-update-architecture.md`](list-update-architecture.md) | List update architecture | List update architecture |
| [`docs/design/llm-governance.md`](llm-governance.md) | LLM Governance | LLM governance |
| [`docs/design/phase1-iso20022-canonical.md`](phase1-iso20022-canonical.md) | Phase 1: ISO 20022 Canonical Model and Screening-Plan Engine | Phase 1 |
| [`docs/design/phase10-evaluation-release-qualification.md`](phase10-evaluation-release-qualification.md) | Phase 10 — Evaluation and Release Qualification | Phase 10 |
| [`docs/design/phase11-github-release-rc2.md`](phase11-github-release-rc2.md) | Phase 11 GitHub release and post-release homelab qualification | Phase 11 |
| [`docs/design/phase11-open-source-release-packaging.md`](phase11-open-source-release-packaging.md) | Phase 11 — open-source release packaging and deployment | Phase 11 |
| [`docs/design/phase1b-screening-evidence.md`](phase1b-screening-evidence.md) | Phase 1B: Screening-Plan Execution and Evidence Bundles | Phase 1B |
| [`docs/design/phase1c-matcher-requests-replay.md`](phase1c-matcher-requests-replay.md) | Phase 1C: Matcher Request Projection and Replay Contracts | Phase 1C |
| [`docs/design/phase1d-matcher-provider-results.md`](phase1d-matcher-provider-results.md) | Phase 1D: Matcher provider and candidate-result contracts | Phase 1D |
| [`docs/design/phase2a-ofac-ingestion.md`](phase2a-ofac-ingestion.md) | Phase 2A: OFAC ingestion and direct-list catalogs | Phase 2A |
| [`docs/design/phase2b-compiled-runtime-activation.md`](phase2b-compiled-runtime-activation.md) | Phase 2B: compiled OFAC runtime packages and activation records | Phase 2B |
| [`docs/design/phase2c-update-manager-distributed-activation.md`](phase2c-update-manager-distributed-activation.md) | Phase 2C — Update manager and distributed activation | Phase 2C |
| [`docs/design/phase2d-delta-refresh-promotion.md`](phase2d-delta-refresh-promotion.md) | Phase 2D — Delta refresh, catalog diff, and promotion policy | Phase 2D |
| [`docs/design/phase3a-deterministic-name-matcher.md`](phase3a-deterministic-name-matcher.md) | Phase 3A: Deterministic name matcher baseline | Phase 3A |
| [`docs/design/phase3b-contextual-geography-remittance.md`](phase3b-contextual-geography-remittance.md) | Phase 3B — Contextual geography and remittance matching | Phase 3B |
| [`docs/design/phase4a-false-positive-classifier.md`](phase4a-false-positive-classifier.md) | Phase 4A — deterministic false-positive classifier | Phase 4A |
| [`docs/design/phase4a-r2-countervailing-evidence-repair.md`](phase4a-r2-countervailing-evidence-repair.md) | Phase 4A-r2 — countervailing evidence repair | Phase 4A |
| [`docs/design/phase5a-configurable-policy.md`](phase5a-configurable-policy.md) | Phase 5A — Configurable scoring and threshold policy | Phase 5A |
| [`docs/design/phase6a-rag-analyst-note.md`](phase6a-rag-analyst-note.md) | Phase 6A — Immutable RAG and governed analyst-note v1 | Phase 6A |
| [`docs/design/phase6b-review-orchestration.md`](phase6b-review-orchestration.md) | Phase 6B — Deterministic review orchestration and immutable case bundle | Phase 6B |
| [`docs/design/phase7a-provider-ready-catalog.md`](phase7a-provider-ready-catalog.md) | Phase 7A — Provider-ready catalog and hybrid official overlay | Phase 7A |
| [`docs/design/phase7b-live-source-provenance.md`](phase7b-live-source-provenance.md) | Phase 7B — Live-source acquisition and provenance | Phase 7B |
| [`docs/design/phase7ca-ofac-advanced-xml.md`](phase7ca-ofac-advanced-xml.md) | Phase 7C-A — OFAC Advanced XML production source | Phase 7C-A |
| [`docs/design/phase7cb-catalog-component-registry.md`](phase7cb-catalog-component-registry.md) | Phase 7C-B — Stable catalog component registry and activation metadata | Phase 7C-B |
| [`docs/design/phase7cc-exact-alert-list-mapping.md`](phase7cc-exact-alert-list-mapping.md) | Phase 7C-C: exact alert-list mapping | Phase 7C-C |
| [`docs/design/phase7cd-provider-refresh-governance.md`](phase7cd-provider-refresh-governance.md) | Phase 7C-D — Provider Refresh Governance | Phase 7C-D |
| [`docs/design/phase8-completion.md`](phase8-completion.md) | Phase 8 completion baseline | Phase 8 |
| [`docs/design/phase8-runtime-operations.md`](phase8-runtime-operations.md) | Phase 8 runtime operations | Phase 8 |
| [`docs/design/phase8a-runtime-package-boundary.md`](phase8a-runtime-package-boundary.md) | Phase 8A boundary — Rust memory-mapped catalog runtime | Phase 8A |
| [`docs/design/phase8a-rust-memory-mapped-runtime.md`](phase8a-rust-memory-mapped-runtime.md) | Phase 8A — Rust compiled memory-mapped catalog package and runtime | Phase 8A |
| [`docs/design/phase8b-realtime-batch-screening-api.md`](phase8b-realtime-batch-screening-api.md) | Phase 8B — real-time and batch screening API | Phase 8B |
| [`docs/design/phase8c-deterministic-candidate-scoring.md`](phase8c-deterministic-candidate-scoring.md) | Phase 8C — deterministic candidate scoring and evidence projection | Phase 8C |
| [`docs/design/phase8d-scoring-integrated-screening-api.md`](phase8d-scoring-integrated-screening-api.md) | Phase 8D — Scoring-integrated screening API and policy-bound response contract | Phase 8D |
| [`docs/design/phase8e-catalog-derived-projections-and-atomic-activation.md`](phase8e-catalog-derived-projections-and-atomic-activation.md) | Phase 8E — catalog-derived projection packages and atomic scoring activation | Phase 8E |
| [`docs/design/phase8f-controlled-promotion-canary-audit.md`](phase8f-controlled-promotion-canary-audit.md) | Phase 8F — Controlled activation promotion, canary rollout and immutable operational audit | Phase 8F |
| [`docs/design/phase8g-durable-screening-ledger-postgres-audit.md`](phase8g-durable-screening-ledger-postgres-audit.md) | Phase 8G — Durable screening ledger, reproducible snapshots, and PostgreSQL audit storage | Phase 8G |
| [`docs/design/phase9-plan.md`](phase9-plan.md) | Phase 9 implementation plan | Phase 9 |
| [`docs/design/phase9ab-deterministic-alert-case-backend.md`](phase9ab-deterministic-alert-case-backend.md) | Phase 9A–9B: deterministic alert and case-management backend | Phase 9A-9B |
| [`docs/design/phase9c-governed-rag-larger-model-assistance.md`](phase9c-governed-rag-larger-model-assistance.md) | Phase 9C: governed RAG and larger-model analyst assistance | Phase 9C |
| [`docs/design/phase9d-complete-iso20022-message-family-coverage.md`](phase9d-complete-iso20022-message-family-coverage.md) | Phase 9D — complete supported ISO 20022 message-family coverage | Phase 9D |
| [`docs/design/phase9e-governed-vendor-adapters.md`](phase9e-governed-vendor-adapters.md) | Phase 9E r1 — governed vendor adapter framework | Phase 9E |
| [`docs/design/phase9f-auth-rbac-review-console.md`](phase9f-auth-rbac-review-console.md) | Phase 9F r1 — authenticated multi-tenant review console | Phase 9F |
| [`docs/design/phase9g-production-hardening-resilience-observability-recovery.md`](phase9g-production-hardening-resilience-observability-recovery.md) | Phase 9G r1 — Production hardening, resilience, observability, and recovery | Phase 9G |
| [`docs/design/rag-architecture.md`](rag-architecture.md) | RAG Architecture | RAG architecture |
| [`docs/design/release-process.md`](release-process.md) | Release process | Release process |
| [`docs/testing/homelab-binding-candidate-v1-audit.md`](../testing/homelab-binding-candidate-v1-audit.md) | Homelab binding candidate v1 audit | Homelab test harness / qualification |
| [`docs/testing/homelab-complete-v2-binding-rematerialization.md`](../testing/homelab-complete-v2-binding-rematerialization.md) | H1 r1.13.11 complete-v2 binding rematerialization and planner closure | Homelab test harness / qualification |
| [`docs/testing/homelab-frozen-source-lock-finalization.md`](../testing/homelab-frozen-source-lock-finalization.md) | Homelab frozen source-lock finalization | Homelab test harness / qualification |
| [`docs/testing/homelab-governed-binding-recommendations.md`](../testing/homelab-governed-binding-recommendations.md) | H1 r1.13.2 governed selection recommendations | Homelab test harness / qualification |
| [`docs/testing/homelab-governed-binding-selection.md`](../testing/homelab-governed-binding-selection.md) | H1 governed real-source binding selection and acceptance | Homelab test harness / qualification |
| [`docs/testing/homelab-h1-deployment-test-harness.md`](../testing/homelab-h1-deployment-test-harness.md) | Homelab H1: fixed-host deployment and functional-test harness | Homelab test harness / qualification |
| [`docs/testing/homelab-h1-r2-clean-room-reset.md`](../testing/homelab-h1-r2-clean-room-reset.md) | H1 r2.0.1 clean-room reset and bootstrap | Homelab test harness / qualification |
| [`docs/testing/homelab-h1-r2-provider-activation.md`](../testing/homelab-h1-r2-provider-activation.md) | H1 r2.3.4 historical Go-evidence quarantine repair | Homelab test harness / qualification |
| [`docs/testing/homelab-h1-r2-provider-contract-lineage.md`](../testing/homelab-h1-r2-provider-contract-lineage.md) | H1 r2.2 provider-mode request contract and active source-lineage discovery | Homelab test harness / qualification |
| [`docs/testing/homelab-h1-r2-runtime-topology.md`](../testing/homelab-h1-r2-runtime-topology.md) | Homelab H1 r2.1 — Clean Runtime Topology and Authentic Service Identity | Homelab test harness / qualification |
| [`docs/testing/homelab-load-context-v2-resolution.md`](../testing/homelab-load-context-v2-resolution.md) | H1 r1.13.5 load-context governed-v2 resolution repair | Homelab test harness / qualification |
| [`docs/testing/homelab-ofac-opensanctions-functional-test-plan.md`](../testing/homelab-ofac-opensanctions-functional-test-plan.md) | Homelab OFAC and OpenSanctions Functional Test Plan | Homelab test harness / qualification |
| [`docs/testing/homelab-planner-candidate-resolution.md`](../testing/homelab-planner-candidate-resolution.md) | H1 planner candidate-pack resolution | Homelab test harness / qualification |
| [`docs/testing/homelab-promoted-binding-source-lock-alignment.md`](../testing/homelab-promoted-binding-source-lock-alignment.md) | H1 r1.13.8 promoted-binding source-lock alignment | Homelab test harness / qualification |
| [`docs/testing/homelab-real-source-binding-review.md`](../testing/homelab-real-source-binding-review.md) | Homelab real-source binding candidate and review gate | Homelab test harness / qualification |
| [`docs/governance/openwatchlist-clean-restart-r0.md`](../governance/openwatchlist-clean-restart-r0.md) | OpenWatchlist Clean Restart R0.3 | Clean-restart migration governance |
| [`docs/governance/openwatchlist-secret-retirement-checklist.md`](../governance/openwatchlist-secret-retirement-checklist.md) | OpenWatchlist secret-retirement checklist | Clean-restart migration governance |
| [`docs/product/product-positioning.md`](../product/product-positioning.md) | Product Positioning | Product positioning |

67 documents restored: 49 phase/subsystem design documents, 15 homelab testing documents, 2 migration/governance documents, and 1 product-positioning document.
