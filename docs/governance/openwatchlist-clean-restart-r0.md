# OpenWatchlist Clean Restart R0.3

## R0.3 container-owned runtime-state backup/restore repair

R0.3 extends the split backup model to the g732 `runtime-data` bind mount.
The SSH account cannot read that container-owned directory directly, so the
ordinary deployment tar explicitly excludes it.  R0.3 captures the mounted
state through the allowlisted `openwatchlist-platform-api` container using
`docker cp`, validates the returned tar archive, records its digest and entry
count, and restores it through the recreated container before restarting and
health-checking the service.

The runtime snapshot is marked `live_best_effort_non_authoritative`; the
verified PostgreSQL custom dump remains the authoritative durable data backup.
No historical evidence or provider source files are omitted.

## R0.2 PostgreSQL bind-storage backup contract

On opt1, `/var/lib/postgresql/data` is a host bind mount below the OpenWatchlist
deployment root and is not readable by the SSH account. R0.2 therefore:

1. creates and verifies `openwatchlist-postgresql.dump` with `pg_dump -Fc`;
2. records `logical_pg_dump_custom_format` in backup state;
3. excludes the raw `postgres-data` tree from `deployment-files.tar.gz`;
4. excludes container-owned `runtime-data` from the deployment tar and captures it with `docker cp`;
5. archives Compose, `.env`, migrations, gateway configuration, TLS material,
   and all other readable OpenWatchlist deployment files;
6. restores Compose first, then runs `pg_restore --clean --if-exists`; and
7. verifies that the restored database contains public tables.

The raw database directory is removed only after the verified logical dump and
all other backup checksums are complete.

# OpenWatchlist Clean Restart R0.1

## R0.1 installer repair

R0.1 scopes generated-file hygiene checks to R0-owned paths only. Pre-existing `__pycache__`, `.pyc`, or `.DS_Store` files elsewhere in the legacy repository no longer cause a false installer failure. Installer failures retain a private diagnostic log in the overlay backup before rollback.


## Purpose

R0 retires the current homelab deployment and prepares the existing repository for preservation as `openwatchlist-labs/watchlist-platform-legacy`. It does not rename, archive, delete, or create any GitHub repository. It does not send a screening request and does not launch qualification work.

The workflow is deliberately split into independent gates:

1. `status` — local repository and zero-attempt inventory.
2. `preview --remote` — read-only homelab discovery and ownership classification.
3. `backup` — Git bundle, source/private worktree archives, manifests, deployment files, Docker images, volumes, and PostgreSQL dump.
4. `teardown` — explicit, allowlisted OpenWatchlist-only removal.
5. `verify` — independent post-teardown verification.
6. `restore` — backup-based rollback when required.
7. `local-tag` — optional local annotated tag after the archival commit is reviewed.

## Safety model

R0 removes only resources positively identified by the retained policy and the live preview.

### Exact container allowlist

| Node | Containers eligible for removal |
|---|---|
| `opt1` | `openwatchlist-gateway`, `openwatchlist-postgres` |
| `g732` | `openwatchlist-platform-api` |
| `opt2` | none |

Container IDs are captured during preview. Teardown refuses to remove a same-named container when its ID has changed.

### Explicitly protected services

The policy explicitly protects known Clawbot, ACH/Trust Lab, NATS, Redis, Ollama, Qdrant, and Neo4j names/patterns. Every non-allowlisted container is protected by default, including unknown future services.

### Images

Generic `nginx`, `postgres`, `redis`, `nats`, and `pgvector` images are classified as shared and retained. Only images whose configured reference is owned by `openwatchlist-labs/watchlist-platform` can be removed, and their bytes are saved before teardown.

### Networks, volumes, and directories

Only OpenWatchlist-prefixed networks and volumes attached to allowlisted containers are eligible. Bind mounts must reside below an approved OpenWatchlist directory. Any external bind, volume, network, or image whose ownership is unproven blocks backup and teardown.

### Database objects

Preview lists database, schema, and table names read-only. Backup creates a PostgreSQL custom-format dump without exporting credentials. Teardown removes the OpenWatchlist database deployment only after that dump and the deployment/volume archives pass checksums.

## Install-only behavior

The overlay installer performs no SSH, Docker, database, GitHub, screening, or qualification operation. It only installs and validates the R0 tooling.

## Commands

### 1. Local status

```bash
./scripts/clean-restart/openwatchlist-clean-restart-r0.sh status \
  --output /tmp/openwatchlist-r0-status.json
```

### 2. Read-only remote preview

```bash
./scripts/clean-restart/openwatchlist-clean-restart-r0.sh preview --remote \
  --output /tmp/openwatchlist-r0-preview.json
```

Review `blockers`, `resource_classification`, `owned_containers`, `protected_containers`, `owned_images`, `shared_images_preserved`, `owned_networks`, `owned_named_volumes`, and `owned_bind_sources`.

Do not continue unless:

```text
backup_ready: true
blockers: []
qualification safe: true
```

### 3. Backup

```bash
./scripts/clean-restart/openwatchlist-clean-restart-r0.sh backup \
  --preview /tmp/openwatchlist-r0-preview.json \
  --archive-root "$HOME/openwatchlist-legacy-archives" \
  --confirm BACKUP-OPENWATCHLIST-R0 \
  --output /tmp/openwatchlist-r0-backup.json
```

The backup directory is mode `0700`. It contains a Git bundle, `git archive`, private working-tree archive, diffs, untracked inventory, preserved-artifact manifest, migration manifest, node inventories, deployment archives, Docker image archives, named-volume archives, and PostgreSQL dump. `SHA256SUMS` covers the full backup.

The private working-tree archive may contain historical secrets and must remain private/offline.

### 4. Optional archival commit and local tag

R0 does not create the commit automatically. Review the generated `legacy-archive-plan.v1.json`, create the archival commit manually, then run:

```bash
./scripts/clean-restart/openwatchlist-clean-restart-r0.sh local-tag \
  --confirm TAG-LEGACY-OPENWATCHLIST-R0 \
  --tag clean-restart-r0-legacy-freeze
```

The command refuses a dirty tracked worktree. It creates only a local tag; it does not push anything.

### 5. Targeted teardown

```bash
./scripts/clean-restart/openwatchlist-clean-restart-r0.sh teardown \
  --backup "$HOME/openwatchlist-legacy-archives/<timestamp>-openwatchlist-clean-restart-r0" \
  --confirm TEARDOWN-OPENWATCHLIST-R0 \
  --output /tmp/openwatchlist-r0-teardown.json
```

Teardown revalidates checksums, zero qualification state, protected container identities, and allowlisted container identities before removal.

### 6. Verification

```bash
./scripts/clean-restart/openwatchlist-clean-restart-r0.sh verify \
  --backup "$HOME/openwatchlist-legacy-archives/<timestamp>-openwatchlist-clean-restart-r0" \
  --output /tmp/openwatchlist-r0-verification.json
```

Successful verification requires:

- no allowlisted OpenWatchlist container remains;
- the OpenWatchlist staging root is absent on all three nodes;
- every protected container present during preview remains present;
- backup checksums remain valid.

### 7. Restore

```bash
./scripts/clean-restart/openwatchlist-clean-restart-r0.sh restore \
  --backup "$HOME/openwatchlist-legacy-archives/<timestamp>-openwatchlist-clean-restart-r0" \
  --confirm RESTORE-OPENWATCHLIST-R0 \
  --output /tmp/openwatchlist-r0-restore.json
```

Restore loads saved images, restores deployment directories and named volumes, and runs each node's saved Compose deployment. The logical PostgreSQL dump remains available as an additional recovery artifact.

## Secret retirement

The exposed PostgreSQL password and signing key must never be reused. R0 removes the active homelab copies with the OpenWatchlist deployment. After teardown, complete these manual actions:

1. Delete or replace corresponding GitHub repository/environment secrets in the legacy repository.
2. Do not copy old secret values into the new repository.
3. Delete, encrypt, or move terminal and diagnostic exports containing those values to offline forensic storage.
4. Generate entirely new database and signing credentials during the clean deployment phase.
5. Record only secret fingerprints, never raw values, in migration evidence.

## Clean repository migration manifest

`clean-repository-import-manifest.v1.json` provides a review queue rather than an automatic copy. The new repository must not import:

- `var/`;
- `.homelab-h1-backups/`;
- H1 r1.14/r2 activation and qualification overlays;
- generated selectors or fixtures;
- runtime diagnostics and run state;
- `.env`, signing keys, password files, or other secret-bearing files.

Mutable evidence must live outside the Go module in the replacement repository.

## GitHub boundary

R0 performs zero GitHub mutations. After backup and teardown are verified, rename/archive the legacy repository and create the new canonical repository manually or through a separately reviewed GitHub migration procedure.
