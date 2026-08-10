# Product Positioning

**Status:** Phase 0 architecture baseline

**Product:** OpenWatchlist Platform

**Repository:** `openwatchlist-labs/watchlist-platform`

## Positioning statement

OpenWatchlist Platform is an open-source, field-aware sanctions and watchlist screening and alert-review platform for financial institutions and compliance engineering teams that need to reduce avoidable false positives without weakening evidence, auditability, or escalation controls.

Unlike generic AI compliance assistants, the platform preserves native transaction structure, separates deterministic decisions from generated analysis, and keeps list-source, policy, retrieval, and model lineage in a replayable evidence bundle.

## Market lane

The platform is designed to augment—not initially replace—existing screening and case ecosystems such as:

- transaction and payment screening engines;
- customer and counterparty screening systems;
- alert exports from enterprise platforms;
- internal sanctions services;
- official and commercial watchlist feeds; and
- analyst case-management workflows.

The initial integration posture is **post-screening review and re-evaluation**, with a shared matcher that can later support direct screening.

## Primary users

### Compliance engineering teams

Need a transparent system for parsing messages, integrating lists, tuning field-aware policies, replaying alerts, and validating changes before deployment.

### Sanctions operations and alert-triage teams

Need better evidence organization, false-positive typology support, consistent reason codes, and grounded analyst-note assistance.

### Model risk, validation, and audit teams

Need reproducible fixtures, versioned policies, immutable lineage, model and prompt traceability, and promotion reports.

### Fintechs and smaller institutions

Need a deployable open foundation that does not require proprietary decision logic or an externally hosted LLM.

### Researchers and solution integrators

Need stable canonical contracts for experimenting with matching, transliteration, retrieval, policy, and analyst-assistance approaches.

## Jobs to be done

The platform should help users:

1. ingest an ISO 20022 payment or an alert exported by an existing screening engine;
2. identify exactly which message element triggered a candidate;
3. compare the field's semantic role with the candidate's entity type and identifiers;
4. retrieve authoritative list and policy evidence with source lineage;
5. apply institution-specific scoring, blockers, and decision routes;
6. recognize deterministic false-positive patterns;
7. draft a concise, evidence-grounded analyst note;
8. replay the case under a new parser, list version, policy, corpus, prompt, or model; and
9. explain why the outcome changed—or prove that it did not.

## Differentiation

### Field-aware rather than blob-based

ISO 20022 fields are mapped to semantic roles and explicit screening routes. A party name, BIC, account identifier, country, reference, and remittance narrative are not treated as interchangeable text.

### Enterprise-shaped open source

The first implementation is intentionally broader than a toy matcher. It combines message parsing, list evidence, matching, policy, regression, RAG, and governed LLM notes in one coherent architecture.

### Deterministic governance

The LLM cannot clear, block, release, or escalate a case. It may summarize evidence and draft notes only after a deterministic route exists.

### Provider-ready evidence model

The system begins with OFAC direct-list records while preserving contracts for provider-consolidated entities and hybrid overlays.

### Replay as a product feature

Every material input is versioned so behavior can be reconstructed and compared across releases.

## Initial use cases

- review alerts produced by existing payment-screening systems;
- screen and explain `pacs.008` payment fields;
- distinguish party-name hits from reference, account, BIC, country, and narrative collisions;
- retrieve an OFAC profile and its aliases, identifiers, programs, addresses, and source assertions;
- identify entity-type and field-type conflicts;
- apply configurable false-positive patterns and escalation blockers;
- retrieve policy guidance and similar historical cases; and
- generate a validated analyst-note draft with explicit evidence citations.

## Explicit non-goals for early releases

OpenWatchlist Platform will not initially:

- replace a financial institution's legal or compliance judgment;
- guarantee sanctions compliance or regulatory acceptance;
- make autonomous customer-impacting decisions;
- hide decision logic inside an LLM prompt;
- treat a screening score as proof of identity;
- flatten structured payment messages into undifferentiated text;
- redistribute commercial provider data without appropriate rights;
- claim complete coverage of all sanctions regimes or payment formats; or
- provide a full enterprise case-management suite in v0.1.

## Product boundaries

```text
Upstream systems
  payment gateways
  transaction screeners
  customer screeners
  official/provider list feeds
  policy and guidance repositories

OpenWatchlist Platform
  canonical adapters
  list catalog and lineage
  matcher and evidence
  deterministic policy review
  retrieval and analyst assistance
  replay and evaluation

Downstream systems
  alert/case management
  audit and model-risk reporting
  analyst workbench
  operational APIs and batch exports
```

## Success criteria for v0.1

The initial public release is credible when it can:

- parse representative `pacs.008` fixtures without losing XML path or namespace/version context;
- ingest a real OFAC list snapshot and reproduce its source lineage;
- route different semantic fields through different match policies;
- produce deterministic decisions and reason codes from versioned policy configuration;
- demonstrate a regression suite covering representative true-match and false-positive cases;
- retrieve cited policy passages and prior cases;
- generate an analyst note that contains no unsupported claim and cannot override the route; and
- run locally in API, batch, and replay modes.

## Open-source and commercial boundary

The architectural baseline assumes a substantial open-source core:

- canonical adapters and ISO 20022 parsing;
- OFAC ingestion and provider contracts;
- deterministic matching and evidence;
- policy and false-positive engines;
- basic RAG and local-model support;
- replay, fixtures, and evaluation tooling.

Potential later commercial offerings may include managed data refresh, proprietary provider adapters, enterprise identity and access management, deployment automation, validated policy packs, operational dashboards, support, and implementation services. Commercial features must not compromise the auditability of core decisions.

## Product language

Prefer:

- field-aware screening;
- evidence-grounded review;
- deterministic policy;
- replayable decisions;
- analyst assistance;
- provider-ready list catalog.

Avoid:

- autonomous compliance;
- AI decides sanctions matches;
- guaranteed false-positive elimination;
- replacement for legal review;
- black-box risk score.
