# Phase 9C: governed RAG and larger-model analyst assistance

Phase 9C attaches governed, cited analyst assistance to the accepted Phase 9A–9B case-management contract. It is deliberately non-dispositive: model output cannot change a deterministic policy route, propose or approve a case decision, modify the case event chain, or create a customer-impacting action.

## Runtime roles

The Phase 9C profile replaces the earlier tiny Granite experiment with three larger, explicit roles:

| Role | Default Ollama model | Permitted use |
|---|---|---|
| Primary | `granite4.1:8b` | Structured RAG summaries, evidence findings, missing-evidence questions, and bounded next steps |
| Reasoning | `qwen3:14b` | Explicitly requested higher-capacity synthesis for difficult cases |
| Guardian | `granite4.1-guardian:8b` | Independent groundedness, relevance, safety, unsupported-claim, and citation assessment |

The primary and reasoning roles are mutually exclusive for a request. Guardian evaluation is always a separate model invocation after draft generation. The default profile uses `keep_alive: 0`, a 16,384-token context limit, deterministic temperature zero, and one model role at a time so the G732 does not need all three models resident simultaneously.

Recommended Ollama process settings on `ai-g732`:

```text
OLLAMA_MAX_LOADED_MODELS=1
OLLAMA_NUM_PARALLEL=1
OLLAMA_CONTEXT_LENGTH=16384
```

Install the model profile:

```bash
ssh mindseye73@ai-g732
ollama pull granite4.1:8b
ollama pull qwen3:14b
ollama pull granite4.1-guardian:8b
ollama list
```

Validate the live models from the repository:

```bash
PHASE9C_OLLAMA_BASE_URL=http://ai-g732:11434 \
  ./scripts/validate_phase9c_ollama.sh
```

The live-model gate serially invokes each role with `keep_alive: 0`; it does not create or modify cases.

## Immutable corpus boundary

`rag-corpus compile` converts a strict manifest into an immutable corpus snapshot. Compilation is deterministic:

- documents are sorted by stable document ID;
- text is normalized into bounded paragraphs;
- every passage has a content-derived ID and SHA-256;
- the manifest and complete snapshot are checksum addressed;
- an identical manifest produces byte-identical output.

Corpus kinds are:

- `policy` — shared or tenant-scoped policy;
- `guidance` — shared or tenant-scoped operational guidance;
- `prior_case` — always tenant scoped.

A `prior_case` document cannot use tenant `*`. Retrieval includes only globally authorized policy/guidance and exact-tenant documents. Cross-tenant fallback is prohibited.

```bash
go run ./cmd/rag-corpus compile \
  --manifest test/fixtures/case-assistance/corpus/manifest.json \
  --output /tmp/phase9c-corpus.json

go run ./cmd/rag-corpus verify --snapshot /tmp/phase9c-corpus.json
```

## Deterministic retrieval

The retrieval query is built only from a verified Phase 9A–9B case projection and its immutable alert records. It includes bounded case state, policy reason codes, blockers, false-positive classifications, candidate IDs, bands, and source field context.

Retrieval uses deterministic integer scoring and canonical tie-breaking. The returned package contains:

- corpus ID and version;
- snapshot SHA-256;
- tenant ID;
- canonical query terms;
- bounded passages with source references and passage hashes;
- deterministic scores and matched terms;
- package SHA-256.

The language model cannot select hidden corpus content or issue an independent database query.

## Structured assistance contract

Generation must return `openwatchlist.analyst-assistance-draft.v1` with only:

- `summary`;
- `evidence_findings`;
- `missing_evidence_questions`;
- `suggested_next_steps`.

Every evidence finding requires one or more retrieved `passage_id` citations. Unknown fields, unresolved citations, oversized output, or prohibited disposition language make the model output invalid.

The draft contract intentionally contains no route, decision, approval, clearance, disposition, customer action, or case-state field.

## Guardian contract

The Guardian returns `openwatchlist.guardian-assessment.v1` and independently assesses:

- groundedness;
- relevance;
- safety;
- citation validity;
- unsupported claims.

A draft is `completed` only when all checks pass and there are no unsupported claims. Otherwise it is retained immutably with `rejected_guardrail` or another explicit failure status and cannot be accepted as a governed draft.

## Fail-soft behavior

Model and retrieval failures do not make the deterministic alert or case unavailable. Phase 9C records explicit statuses such as:

- `retrieval_empty`;
- `model_unavailable`;
- `invalid_model_output`;
- `guardian_unavailable`;
- `invalid_guardian_output`;
- `rejected_guardrail`;
- `completed`.

These records preserve hashes and failure lineage for evaluation. No failure path invokes the Phase 9A–9B case-event mutation API.

## Analyst review

A human may accept or reject only the assistance artifact. Review is an immutable, idempotent event linked to the case and assistance record. Accepting a draft does not approve a case decision and does not update the deterministic case projection.

## HTTP API

`case-assistance-api` exposes:

```text
GET  /healthz
GET  /readyz
GET  /v1/models
POST /v1/corpus/query
POST /v1/cases/{case_id}/assistance
GET  /v1/cases/{case_id}/assistance/{assistance_id}
POST /v1/cases/{case_id}/assistance/{assistance_id}/review
```

POST operations require idempotency keys. Reusing a key with different normalized request bytes returns a conflict.

## PostgreSQL persistence

Migration `009c_governed_rag_ai_assistance.sql` adds append-only storage for:

- immutable corpus snapshots;
- case-assistance records;
- analyst acceptance/rejection events;
- durable idempotency receipts;
- hash-chained assistance audit events.

The database stores bounded retrieval passages and case evidence already present in the assistance record. It does not store full watchlist catalog rows. When PostgreSQL is required, snapshot, assistance, receipt, and audit persistence must complete before the API returns the artifact.

Run the disposable database gate only against a temporary database:

```bash
createdb temporary_phase9c_db
PHASE9C_POSTGRES_DSN="postgresql:///temporary_phase9c_db?user=$(whoami)" \
  ./scripts/validate_phase9c_postgres.sh
dropdb temporary_phase9c_db
```

## Validation

```bash
./scripts/validate_phase9c.sh

go run ./cmd/case-assistance check \
  --config configs/case-assistance/phase9c-example.json

go run ./cmd/case-assistance-api check \
  --config configs/case-assistance/phase9c-example.json
```

The default configuration uses fixture model responses so repository validation is deterministic and does not depend on network or GPU availability. Live Ollama and disposable PostgreSQL checks are explicit separate gates.
