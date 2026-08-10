# Deployment guide

## Supported reference topology

The checked-in Compose deployment is a local and single-node qualification reference. It contains PostgreSQL, a one-shot migration service, the non-root platform API, a TLS nginx gateway, and an optional Ollama profile.

## Secrets

Generate local qualification secrets with `scripts/release/init-release-env.sh`. For production, replace the environment file with a secret manager or orchestrator secret injection. Required secrets are:

- `OPENWATCHLIST_SIGNING_KEY_HEX`: at least 32 random bytes represented as hexadecimal;
- PostgreSQL credentials and a TLS-validated production DSN;
- TLS private key and certificate chain;
- any model-provider credentials used outside local Ollama.

Never put secrets in runtime JSON, images, SBOMs, scan output, Git history, or backup archives.

## Start

```bash
./scripts/release/init-release-env.sh
./scripts/release/build-images.sh
docker compose --env-file deploy/phase11/.env.release up -d
curl -kfsS https://localhost:8443/readyz
```

The migration service must complete successfully before the API starts. `/readyz` fails closed when PostgreSQL, required configuration, outbox integrity, security audit, or runtime storage checks fail.

## Optional LLM service

```bash
docker compose --env-file deploy/phase11/.env.release --profile llm up -d ollama
```

Install the model IDs referenced in `configs/release/review-console.json` before setting `ollama_required` to true. Model output remains advisory and is subject to citation and unsupported-claim controls.

## Persistence and backup

Persistent volumes contain PostgreSQL and file-backed runtime state. Use the Phase 9G backup command for runtime state and `pg_dump` for PostgreSQL. Store backups outside the deployment host, encrypt them, test restore, and record content hashes.

## Scaling

Before multi-instance deployment:

- use shared durable PostgreSQL and appropriately coordinated file/object storage;
- preserve byte-exact idempotency keys and outbox leases;
- place TLS termination and request IDs at the ingress layer;
- configure tenant quotas consistently across replicas;
- validate row-level security with the actual database role model;
- run target-environment load and failure-injection qualification.

## Production changes required

The local certificate, demo identity registry, generous qualification quotas, localhost ports, and optional model service are examples. A production deployment must use institutional identity federation, managed keys, trusted certificates, restricted ingress, monitored databases, encrypted backups, approved watchlist sources, measured capacity, and organization-specific policy governance.
