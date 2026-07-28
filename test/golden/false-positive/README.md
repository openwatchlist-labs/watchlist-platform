# Phase 4A false-positive classifier goldens

- `pattern-classifications.json` covers 16 canonical observations, all ten baseline false-positive pattern families, primary exact LEI/BIC evidence, and non-escalating exact date/account support.
- `phase3b-contextual-classifications.json` proves adaptation from the accepted Phase 3B matcher result batch and verifies that only its exact LEI candidate-alert observation remains escalation eligible.

Both files are deterministic, content-addressed outputs of `false-positive-classifier/v0.1.1` using:

- `configs/false-positive-patterns/baseline-r1.json`; and
- `configs/false-positive-patterns/countervailing-evidence-r1.json`.
