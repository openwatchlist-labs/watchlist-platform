# H1 r2.0.1 clean-room reset and bootstrap

## Scope

This boundary preserves the accepted real-source lifecycle and base homelab platform while removing the superseded r1.14 execution harness.

Preserved:

- frozen OFAC and OpenSanctions sources;
- binding candidate packs and governed selection/acceptance state;
- complete-v2 promoted binding;
- accepted planner;
- PostgreSQL, gateway, platform API, configuration, secrets files, runtime data, and release artifacts;
- all historical harness material in local and per-node backup archives.

Archived and removed from active paths:

- r1.14 distributed execution, adapter, fixture, runtime-binding, smoke, and assertion scripts;
- r1.14 schemas and packaged regression fixtures;
- generated scenario corpus and runtime binding;
- `h1-r114-qualification` state and evidence;
- r1.14 installation, staging, preflight, discovery, and diagnostic evidence;
- corresponding staged harness files on opt1, g732, and opt2.

## Recreated baseline

The rebuild command reruns the accepted `h1-stage.sh` and `h1-plan-tests.sh`, then requires a fresh plan with:

- 35 archetypes;
- 105 scenarios;
- 315 provider-mode executions;
- 315 ready;
- 0 blocked;
- provider modes `dual_provider`, `native_ofac`, and `opensanctions_ofac`.

It writes `var/homelab/harness-v2/baseline-state.v1.json`. It does not create runtime routes, scenario fixtures, attempt directories, or launch readiness.

## Safety

- Reset aborts unless the accepted lifecycle hashes match.
- Reset aborts if any qualification attempt or `attempt-*` evidence exists.
- Every active r1.14 path is archived before removal.
- Every node backup is downloaded before any remote active path is removed.
- Failure restores local and already-cleaned remote paths.
- Base containers and data are never stopped or deleted.

## Security action

Terminal output exposed a PostgreSQL credential and the OpenWatchlist signing key. Rotate both before deploying a new runtime harness. The reset does not newly collect `.env`, secret files, container environment, or database contents. Existing diagnostic logs are moved into the local mode-0700 backup; remove those logs after rotating the exposed credentials.


## Fresh-plan normalization repair

The parser recursively consumes JSON, JSONL, and NDJSON evidence. It supports
both scenario rows with plural provider modes and already-expanded execution
rows with a singular provider mode. The exact captured `executions.ndjson`
shape from the accepted 315-entry plan is retained as a regression fixture.
Planner stdout and parsed evidence counts must independently agree.
