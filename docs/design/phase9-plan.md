# Phase 9 implementation plan

Phase 9 is delivered in bounded, complete increments rather than repeated feature slices.

## Accepted

- **Phase 9A–9B r1:** complete deterministic alert creation, policy orchestration, case workflow, four-eyes decisions, PostgreSQL persistence, replay, and immutable audit.

## Current deliverable

- **Phase 9C r1:** governed RAG and larger-model analyst assistance on the accepted case API and database contract.
  - immutable checksum-addressed corpus snapshots;
  - deterministic tenant-safe retrieval;
  - `granite4.1:8b` primary structured assistance;
  - `qwen3:14b` explicit reasoning role;
  - `granite4.1-guardian:8b` independent guardrail assessment;
  - immutable case-linked assistance and review audit;
  - fail-soft model operation that cannot change deterministic routes or human decisions.

## Remaining

- **Phase 9D:** supported ISO 20022 message-family completion matrix.
- **Phase 9E:** Fircosoft, Actimize, and generic vendor-adapter completion.
- **Phase 9F:** analyst UI, authentication, tenant administration, and RBAC.
- **Phase 9G:** production observability, performance, security, HA, and disaster recovery.

Phase 9C is the only AI integration deliverable in this sequence. It must not be subdivided into repeated feature packages. Validation repairs, if required, should remain narrowly scoped to defects rather than new Phase 9C functionality.
