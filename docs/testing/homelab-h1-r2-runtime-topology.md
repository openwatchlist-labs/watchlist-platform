# Homelab H1 r2.1 — Clean Runtime Topology and Authentic Service Identity

## Purpose

H1 r2.1 replaces the superseded r1.14 assumption that each provider mode maps to a different homelab node. It performs a zero-launch, read-only discovery of the actual service topology and promotes a governed topology only when OpenWatchlist-specific identity evidence is complete.

## Accepted starting point

The command requires the accepted H1 r2.0.1 baseline:

- 35 archetypes;
- 105 scenarios;
- 315 executions;
- 315 ready;
- 0 blocked;
- `launch_ready=false`;
- `qualification_attempts=0`;
- accepted binding, planner, governed state, and candidate-pack hashes unchanged;
- superseded r1.14 harness sentinels absent.

## Identity policy

HTTP 200 from `/healthz` and `/readyz` is not sufficient. An authentic OpenWatchlist runtime must provide:

1. JSON `status=ok` from both endpoints;
2. a valid 64-character `config_sha256` from both endpoints;
3. the same configuration hash in health and readiness;
4. the complete governed readiness-check set, all with `status=ok`;
5. a configured container image under `ghcr.io/openwatchlist-labs/watchlist-platform@sha256:`;
6. an exact match between the configured image digest and the running image ID.

The gateway must return the same runtime configuration identity as its backend and its read-only Nginx inspection must prove the expected `proxy_pass` target.

Foreign service markers, including `service=ach-api`, are rejection evidence. A generic service cannot be accepted merely because it responds on a candidate port.

## Governed candidates

- `opt1`: `https://192.168.68.61:8443`, expected TLS gateway;
- `g732`: `http://192.168.68.67:18094`, expected OpenWatchlist platform API runtime;
- `opt2`: `http://192.168.68.62:8081`, expected non-OpenWatchlist service under the current topology.

The live command uses only:

- `GET /healthz`;
- `GET /readyz`;
- read-only SSH commands;
- read-only `docker inspect`, `docker ps`, and `nginx -T` output filtering.

It sends no screening request and performs no service, container, filesystem, database, or remote configuration mutation.

## Promoted topology

A successful discovery writes:

`var/homelab/harness-v2/runtime-topology.v1.json`

The topology records:

- `opt1` as the canonical TLS gateway;
- `g732` as the single confirmed backend runtime instance;
- `opt1 -> g732` gateway lineage;
- identical gateway/backend runtime configuration identity;
- `opt2:8081` as a rejected foreign service;
- provider modes as deliberately unbound pending request-contract proof;
- `launch_ready=false` and `qualification_attempts=0`.

Provider modes are not mapped to nodes in r2.1. The next stage must prove request-time provider selection and activated provider-data lineage before any mode binding or smoke request.

## Commands

Discover and promote the live topology:

```bash
./scripts/homelab/h1-r2-runtime-topology.sh discover \
  --output /tmp/openwatchlist-h1-r2-runtime-topology-r21.json 2>&1 | \
  tee /tmp/openwatchlist-h1-r2-runtime-topology-r21.log
```

Report current topology status:

```bash
./scripts/homelab/h1-r2-runtime-topology.sh status \
  --output /tmp/openwatchlist-h1-r2-runtime-topology-status.json
```

Validate the promoted artifact:

```bash
./scripts/homelab/h1-r2-runtime-topology.sh validate
```

## Expected successful state

- discovery status `PASS`;
- state `authentic_topology_confirmed`;
- canonical entrypoint `https://192.168.68.61:8443`;
- backend runtime `http://192.168.68.67:18094`;
- `opt2` role `foreign_service_rejected`;
- provider-mode state `unbound_pending_request_contract`;
- `launch_ready=false`;
- qualification attempts `0`.

## Required blockers retained

- `provider_mode_selector_contract_unproven`;
- `provider_data_activation_lineage_unproven`;
- `credential_rotation_required_before_runtime_redeployment`.
