# H1 r2.2 provider-mode request contract and active source-lineage discovery

H1 r2.2 extends the accepted r2.1 authentic runtime topology without launching a
screening request. It determines the active `POST /v1/screenings` contract from
repository source and correlates it with read-only runtime, filesystem, binary,
and PostgreSQL lineage evidence from the single authenticated `g732` runtime.

## Safety boundary

The discovery command performs:

- local static source inspection;
- read-only SSH to `g732`;
- `docker inspect` and read-only `docker exec` commands;
- reads of non-secret runtime configuration and catalog metadata;
- PostgreSQL `SELECT` queries with `default_transaction_read_only=on`.

It performs no HTTP probe, no `POST /v1/screenings`, no container or service
mutation, no database write, and no qualification execution. The baseline remains
`launch_ready=false` with `qualification_attempts=0`.

## Determinations

The promoted artifact records:

- whether `POST /v1/screenings` is registered in active source;
- the selected request and nested query structs with JSON field names, types, and
  required/optional status;
- the confirmed request schema-version literal and consumed headers;
- the request-time provider selector, when proven;
- per-mode selector values for `dual_provider`, `native_ofac`, and
  `opensanctions_ofac`;
- active catalog/component/version/source-snapshot lineage per mode;
- runtime files, database rows, and binary markers supporting each lineage;
- whether OpenSanctions `us_ofac_sdn` data is loaded;
- whether the one authenticated `g732` runtime supports all three modes;
- exact fail-closed blockers for every missing selector or inactive lineage.

The superseded r1.14 request envelope is retained only as a comparison candidate.
It is never treated as authoritative unless the active repository source confirms
its route, schema, fields, and selector.

## Command

```bash
./scripts/homelab/h1-r2-provider-contract.sh discover \
  --output /tmp/openwatchlist-h1-r2-provider-contract-r22.json
```

Evidence is written under:

```text
var/homelab/evidence/provider-contract-lineage-r22-<UTC timestamp>
```

A successful read-only discovery promotes:

```text
var/homelab/harness-v2/provider-contract-lineage.v1.json
```

`status=PASS` means discovery completed and the result validated. It does not mean
all provider modes are supported. The state distinguishes:

- `provider_contract_and_lineage_confirmed`: all three modes, exact request shape,
  and complete active lineage are proven on the single runtime;
- `provider_contract_discovered_with_blockers`: the evidence is valid but one or
  more selector, data-loading, component/version, or snapshot requirements remain
  unproven.

Credential rotation remains a mandatory blocker before any runtime redeployment or
qualification launch because prior diagnostic output exposed runtime credentials.
