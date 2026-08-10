# Phase 6A — Immutable RAG and governed analyst-note v1

**Status:** implementation baseline

**Authority boundary:** retrieval and generated prose never own the deterministic screening disposition

## 1. Objective

Phase 6A connects the Phase 5A decision trace to an immutable, citation-bearing retrieval layer and an optional local-model analyst-note workflow. The implementation is deliberately fail-closed: corpus or model failures may remove analyst assistance, but they cannot alter `clear`, `investigate`, or `escalate`.

## 2. Pipeline

```text
Phase 5A decision
    │
    ├── structured retrieval query
    │     tenant, effective time, policy, route, blockers,
    │     required evidence, message type, semantic role
    │
    ▼
immutable corpus snapshot
    │
    ├── metadata/effective-date filters
    ├── lexical overlap
    ├── deterministic hashed-vector similarity
    ├── tenant/access isolation
    └── instruction-like-content exclusion
    │
    ▼
allowlisted citation package
    │
    ├── fixture provider for deterministic regression
    └── optional Ollama `/api/chat` provider with JSON schema
    │
    ▼
strict analyst-note validator
    ├── route and disposition lock
    ├── citation allowlist enforcement
    ├── claim-level citations
    ├── prohibited-phrase gate
    └── immutable invocation lineage
```

## 3. Immutable corpus

The manifest uses `rag-corpus-manifest/v1alpha1` and records a checksum over ordered source metadata. Every document is loaded from a path relative to the manifest and stamped with a content checksum. Markdown is split by heading hierarchy and paragraph blocks; chunks retain the heading path, locator, normalized token set, checksum, and prompt-injection indicators.

The resulting `rag-corpus-snapshot/v1alpha1` is immutable and has a content-derived `snapshot_id`. Rebuilding the same manifest and source bytes produces byte-identical output.

Required source metadata includes:

```text
source_id
path
publisher and title
source tier
document type
jurisdiction
publication and effective dates
approval status
tenant scope
access scope
```

The included corpus is synthetic. It contains approved policy, published guidance, validated cases, a superseded policy, an unapproved draft, and prompt-injection fixtures.

## 4. Retrieval policy

`configs/rag/retrieval-policy-r1.json` is checksum protected. The baseline allows tiers A, B, and C with `approved`, `published`, or `validated` status. It excludes:

- tenant-scoped documents belonging to another tenant;
- ineffective or superseded documents;
- unapproved sources;
- tier-D exploratory material; and
- instruction-like chunks even when embedded in an otherwise approved document.

The deterministic score is:

```text
metadata score × 3000 / 10000
lexical score  × 5000 / 10000
vector score   × 2000 / 10000
```

The vector component is a deterministic 64-bucket hashed-token representation with integer normalization. It is a replaceable baseline behind the public retrieval contract; later Qdrant or embedding adapters must preserve the citation and policy boundaries.

## 5. Structured decision adapter

`rag.QueryFromDecision` converts a validated Phase 5A decision into `rag-retrieval-query/v1alpha1`. It copies immutable facts rather than accepting a free-form prompt as authority:

```text
decision ID
disposition
review route
reason codes
escalation blockers
required evidence
message type
semantic role
policy ID
effective timestamp
tenant ID
```

## 6. Citation package

`rag-citation-package/v1alpha1` contains:

```text
citation ID
source ID, tier, title, publisher
approval and effective-date metadata
tenant scope
section/block locator
verbatim excerpt
content checksum
corpus snapshot ID
retrieval methods and component scores
```

The citation-package ID is content derived. Unknown or mutated citation IDs are rejected by the analyst-note validator.

## 7. Governed analyst note

`cmd/analyst-note` supports:

```text
--provider fixture
--provider ollama
```

The fixture provider is deterministic and is used for regression gates. The Ollama provider sends a non-streaming `/api/chat` request with a JSON schema in `format`, temperature zero, and a bounded prompt containing only the immutable decision and allowlisted citations.

The generated `analyst-note/v1alpha1` is always a draft. It must:

- copy the deterministic disposition and review route exactly;
- cite only citation IDs present in the supplied package;
- attach at least one citation to every material claim;
- preserve missing-evidence requirements;
- avoid prohibited legal or system-override phrases; and
- stamp provider, model, profile, prompt, decision, citation, and invocation lineage.

An attempted route change, unknown citation, invalid JSON, empty response, or prohibited phrase rejects the note. The Phase 5A decision remains available independently.

## 8. Commands

Build the corpus snapshot:

```bash
go run ./cmd/rag-index \
  --manifest test/fixtures/rag/corpus-manifest.json \
  --output /tmp/openwatchlist-rag-snapshot.json
```

Retrieve from a Phase 5A decision:

```bash
go run ./cmd/rag-query \
  --snapshot /tmp/openwatchlist-rag-snapshot.json \
  --retrieval-policy configs/rag/retrieval-policy-r1.json \
  --decision-batch test/golden/policy/pattern-decisions.json \
  --case-id fp-03-entity-type-mismatch \
  --tenant-id tenant-a \
  --effective-at 2026-07-14T12:00:00Z
```

Generate the deterministic regression note:

```bash
go run ./cmd/analyst-note \
  --decision-batch test/golden/policy/pattern-decisions.json \
  --case-id fp-03-entity-type-mismatch \
  --citations test/golden/rag/entity-type-decision-citations.json \
  --profile configs/models/granite-analyst-note-r1.json \
  --provider fixture
```

Use a local Ollama endpoint:

```bash
go run ./cmd/analyst-note \
  --decision-batch test/golden/policy/pattern-decisions.json \
  --case-id fp-03-entity-type-mismatch \
  --citations test/golden/rag/entity-type-decision-citations.json \
  --profile configs/models/granite-analyst-note-r1.json \
  --provider ollama \
  --ollama-base-url http://ai-g732:11434
```

## 9. Phase boundary

Phase 6A does not yet add production Qdrant/Neo4j adapters, external authoritative documents, prior-case PII handling, model promotion orchestration, or an analyst review API. Those remain subsequent Phase 6 deliverables behind the contracts established here.
