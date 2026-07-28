# Phase 6A RAG and analyst-note goldens

These files are deterministic regression artifacts generated from synthetic source material:

- `corpus-snapshot.json` — immutable hierarchical corpus snapshot;
- `entity-type-citations.json` — retrieval from an explicit structured query fixture;
- `entity-type-decision-citations.json` — retrieval adapted directly from a Phase 5A decision; and
- `entity-type-analyst-note.json` — governed fixture-provider invocation with claim-level citations.

The corpus intentionally contains superseded, draft, tier-D, and embedded prompt-injection material. None may appear in the allowlisted citations for the accepted query.
