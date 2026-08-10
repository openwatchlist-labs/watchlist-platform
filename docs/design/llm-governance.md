# LLM Governance

**Status:** Phase 0 control baseline

**Core rule:** LLMs may assist analysts; they do not own screening or policy decisions.

## 1. Governance objective

OpenWatchlist Platform uses LLMs only where generated language or bounded classification adds value without weakening deterministic controls. The architecture follows a risk-managed approach consistent with the trustworthiness themes of the NIST AI Risk Management Framework and its Generative AI Profile, but this document does not claim certification or regulatory compliance.

## 2. Permitted tasks

Approved early tasks may include:

- draft an analyst note from a completed deterministic evidence bundle;
- summarize candidate and transaction evidence;
- summarize cited policy passages;
- identify explicitly missing evidence or unanswered questions;
- transform validated evidence into a strict JSON structure;
- classify a note for quality-control review without changing the case route; and
- generate synthetic test text that is clearly marked and never mixed with production evidence.

## 3. Prohibited authority

An LLM must not:

- decide whether a customer or transaction is legally sanctioned;
- create or modify the authoritative route, score, blocker, or reason code;
- remove a required review or release an alert;
- invent list membership, identifiers, relationships, ownership, or policy;
- cite a source that was not provided in the invocation;
- treat its own prior output as authoritative evidence;
- execute retrieved document instructions;
- access another tenant's data; or
- make an unreviewed customer-impacting decision.

## 4. Decision boundary

```text
Deterministic layers own:
  parsing
  semantic field roles
  list lineage
  candidate evidence
  comparison features
  false-positive patterns
  scores and thresholds
  blockers and route caps
  final platform route

LLM layer may own:
  wording
  concise synthesis
  cited explanation
  missing-evidence questions
  optional analyst-note recommendation clearly labeled as non-authoritative
```

The deterministic decision is passed to the model as an immutable fact. Any generated field that conflicts with it causes validation failure.

## 5. Invocation contract

Every invocation records:

```text
invocation_id and correlation_id
tenant and task type
model provider and endpoint class
model identifier and immutable digest where available
model configuration
system/task prompt versions
output schema version
evidence bundle identifiers
citation package identifiers
redaction policy and transformations
start/end time and latency
raw output reference or protected hash
validation results
human disposition when applicable
```

## 6. Structured output

A representative analyst-note contract is:

```json
{
  "analyst_note": "string",
  "evidence_used": ["evidence-id"],
  "policy_citations": ["citation-id"],
  "uncertainties": ["string"],
  "missing_evidence": ["string"],
  "recommended_next_step": "string",
  "deterministic_route_observed": "investigate"
}
```

The allowed `recommended_next_step` values are task-specific and cannot encode a route that the deterministic policy forbids.

## 7. Validation pipeline

```text
prepare allowlisted evidence
apply redaction/data policy
build versioned prompt
call approved model endpoint
parse strict schema
verify deterministic-route consistency
verify evidence references
verify citation existence and support
scan prohibited and unsupported claims
apply length and content controls
store audit trace
return draft or validation error
```

A malformed or unsupported result fails closed. The platform may return the deterministic decision without an analyst note.

## 8. Evidence-grounding rules

- Every material factual claim must reference provided evidence or a citation.
- Absence of evidence must be described as uncertainty, not converted into a negative fact.
- Similar prior cases are examples, not proof.
- Model knowledge outside the supplied context cannot establish current list membership, legal interpretation, or institutional policy.
- Quotations must remain within configured limits and preserve source location.
- The model must distinguish transaction facts, list facts, policy requirements, analyst inference, and unresolved questions.

## 9. Model gateway and portability

Application code calls a provider-neutral gateway. Configuration identifies approved task/model combinations, for example:

```yaml
task: analyst_note_v1
allowed_models:
  - local:granite-8b-class
  - local:qwen-14b-class
requires_local_endpoint: true
max_input_tokens: 16000
max_output_tokens: 1200
schema: analyst_note_v1
citation_required: true
```

Model names in deployment configuration are examples, not architectural dependencies. A model change is a governed release change, not an incidental infrastructure update.

## 10. Data handling

Deployments must classify data before model use.

- Prefer local inference for sensitive transaction and customer content.
- Minimize fields sent to the model.
- Tokenize or redact account and personal identifiers when they are not needed.
- Do not send provider-licensed content to an endpoint that violates provider terms.
- Do not train or fine-tune on production cases without explicit governance and rights.
- Encrypt data in transit and at rest according to deployment policy.
- Apply retention limits to prompts and outputs.
- Keep secrets and credentials outside prompts.

## 11. Prompt-injection controls

Transaction narratives, retrieved documents, list text, and prior notes are untrusted data.

- Wrap each source in typed boundaries.
- State that embedded instructions are non-authoritative content.
- Deny model-driven tool selection in the analyst-note workflow.
- Use allowlisted retrieval and evidence IDs.
- Do not expose hidden prompts, credentials, or unrestricted system metadata.
- Validate that output contains no request to execute actions outside the schema.

## 12. Human oversight

Generated notes are drafts unless an institution explicitly configures and validates a narrower workflow. The interface must display:

- the deterministic route and blockers separately from generated text;
- model-generated status;
- evidence and citations used;
- validation warnings;
- model and prompt version; and
- a way to edit, reject, or regenerate without changing the policy decision.

## 13. Evaluation and promotion

A candidate prompt/model release is evaluated on pinned fixtures that cover:

- true matches and clear false positives;
- sparse or contradictory evidence;
- entity-type and wrong-field conflicts;
- narrative denial and quoted-party context;
- prompt injection in transaction or retrieved text;
- missing or superseded policy citations;
- multilingual and transliterated names;
- schema pressure and long context; and
- attempted route override.

Promotion requires:

- zero successful deterministic-route overrides;
- zero fabricated citation IDs in canonical gates;
- supported-claim thresholds appropriate to the task;
- acceptable schema-validity and latency;
- documented regressions and mitigations; and
- human review of high-risk failure categories.

## 14. Runtime failure behavior

| Failure | Required behavior |
|---|---|
| Model unavailable | return deterministic result without note |
| Timeout | record failure; do not retry indefinitely |
| Invalid JSON/schema | reject note |
| Unknown evidence/citation ID | reject note |
| Contradicts deterministic route | reject note and emit governance event |
| Unsupported legal/list claim | reject or quarantine for review |
| Cross-tenant reference | reject and emit security event |
| Prompt-injection indicators | quarantine or use extractive fallback |

## 15. Change management

The following are independently versioned and auditable:

- model and serving configuration;
- prompts and templates;
- output schemas;
- redaction policy;
- retrieval policy and corpus snapshot;
- validators and prohibited-claim rules; and
- evaluation fixture set.

A rollback must restore the full compatible set, not only the model identifier.

## 16. Phase 6 acceptance criteria

- analyst-note calls are optional and fail closed;
- all outputs conform to a strict schema;
- notes cite only provided evidence and citation IDs;
- deterministic routes and blockers cannot be overridden;
- invocation lineage is sufficient for replay;
- prompt-injection fixtures are contained;
- local-model operation is supported; and
- model/prompt changes pass a documented promotion gate.

## 17. Reference

- [NIST AI Risk Management Framework: Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)

## 18. Phase 6A implemented baseline

Phase 6A adds an optional analyst-note invocation contract with a deterministic fixture provider and a local Ollama provider. The runtime sends a bounded prompt and JSON schema, then independently enforces:

- exact decision/disposition/route lineage;
- citation allowlisting and claim-level citation use;
- strict JSON decoding with unknown-field rejection;
- prohibited-phrase and prompt-injection controls; and
- content-derived note and invocation IDs.

An invalid or unavailable model produces no accepted note. It cannot modify or replace the Phase 5A result.
