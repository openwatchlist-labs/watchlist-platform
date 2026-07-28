# Phase 5A policy decision goldens

These files lock deterministic policy behavior over the accepted Phase 4A-r2 classification batches.

- `pattern-decisions.json`: baseline policy over 16 canonical false-positive classifications; expected 6 clear, 8 investigate, 2 escalate.
- `phase3b-contextual-decisions.json`: baseline policy over the accepted Phase 3B adaptation; expected 1 clear, 14 investigate, 1 escalate.
- `pattern-decisions-conservative-overlay.json`: the same 16 classifications with the synthetic conservative tenant overlay; automatic clear and escalation are disabled, so all 16 investigate.

The policy and overlay references, checksums, ordered score components, thresholds, blockers, reasons, and rule traces are part of the golden contract.
