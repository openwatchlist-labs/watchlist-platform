# Phase 2C update-manager golden contract

`distributed-update-replay.json` locks a deterministic two-update, three-worker scenario:

- source and package A activate at fleet epoch 1 with `worker-a` as canary;
- source and package B activate at fleet epoch 2 with `worker-b` as canary;
- package A is reactivated by rollback at fleet epoch 3;
- all required worker readiness and activation acknowledgements are retained;
- the final active pointer references package A at epoch 3;
- the append-only update audit history contains a valid hash chain.

The sources and workers are synthetic fixtures. This golden file validates protocol and lineage, not production sanctions-screening behavior.
