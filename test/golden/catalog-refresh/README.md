# Phase 2D golden contracts

These files use synthetic OFAC-shaped records and are not actual designations.

- `base.catalog.json`: ten-record immutable base catalog.
- `small.catalog.json`: one modified record; 10% change ratio.
- `threshold.catalog.json`: two modified records; exactly 20%.
- `large.catalog.json`: three modified records; 30%.
- `small.delta.json`: accepted sequence-1 delta.
- `threshold.delta.json`: valid delta forced to a full rebuild at the exact threshold.
- `large.delta.json`: valid delta forced to a full rebuild above threshold.
- `small.diff.json`: semantic diff for the accepted delta.
- `*.decision.json`: immutable policy decisions.
- `catalog-refresh-replay.json`: deterministic combined replay including promote, force-full, and reject outcomes.
