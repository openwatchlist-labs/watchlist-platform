# Homelab H1: fixed-host deployment and functional-test harness

## Objective

Deploy the exact published `v0.1.0-rc.2` image to the Linux homelab, prove
release identity and basic service readiness, and establish a test runner for
the 35 tracked transaction-screening false-positive archetypes.

H1 does not claim OFAC/OpenSanctions functional qualification. It establishes
the infrastructure and emits a deterministic 315-execution plan. Functional
executions remain blocked until real records from reviewed frozen snapshots are
bound to every archetype.

## Immutable application identity

- Tag: `v0.1.0-rc.2`
- VCS ref: `fb88a11846b8940f69d2c5b4325e22812686a0b8`
- Image digest: `sha256:02c1538f3525b16499062f72ae230f62279d021fe922ac9c5828dc9076562bf3`
- Image reference: `ghcr.io/openwatchlist-labs/watchlist-platform@sha256:02c1538f3525b16499062f72ae230f62279d021fe922ac9c5828dc9076562bf3`

The deployment scripts reject a different application image reference.

## Host placement

| Host | H1 role | Persistent state |
|---|---|---|
| OptiPlex-1 | PostgreSQL, migrations, TLS gateway | PostgreSQL data and gateway TLS material |
| ai-g732 | Platform API and mmap/runtime state | API runtime and active catalog packages |
| OptiPlex-2 | Source acquisition and catalog/test preparation | Frozen OFAC/OpenSanctions source files |
| P50 | Excluded from deterministic H1 | Existing Qdrant/Neo4j services unchanged |
| Mac mini | Controller, test runner, evidence collection | Untracked `var/homelab` state |

Traffic between services uses stable wired-LAN addresses. SSH may use hostnames
or Tailscale names, but the remote identity is explicit: `mindseye73` on each
Linux node. The scripts never inherit the Mac controller username. No Docker
daemon TCP socket is exposed.

## Local state and secrets

`h1-init.sh` creates untracked files under `var/homelab`:

- `inventory.env`
- `source-urls.env`
- `secrets/credentials.env`
- TLS CA and gateway certificate
- staging directories
- evidence bundles

No generated secret or full source catalog belongs in Git.

## Deployment sequence

1. `h1-init.sh` creates templates and secrets without overwriting existing data.
2. The operator confirms `mindseye73` as each role SSH user and fills stable LAN IPs in `inventory.env`.
3. `h1-preflight.sh` checks SSH, Docker Compose, host capacity, release identity,
   repository migrations/configuration, and the 35-archetype corpus.
4. `h1-stage.sh` copies only the fixed-host deployment bundles and required
   configuration to each node.
5. `h1-deploy.sh` pulls the immutable application digest, starts PostgreSQL,
   applies all SQL migrations, starts the G732 API, starts the TLS gateway, and
   verifies liveness/readiness.
6. `h1-smoke.sh` records HTTPS responses, container identity, PostgreSQL query
   success, release metadata, configuration checksums, and evidence hashes.
7. `h1-plan-tests.sh` expands 35 archetypes × 3 controls × 3 provider modes.

## Source acquisition

`h1-freeze-sources.sh` runs on OptiPlex-2 and downloads:

- official OFAC `SDN_ADVANCED.XML`;
- the current versioned OpenSanctions `us_ofac_sdn/entities.ftm.json` artifact.

The script requires an explicit OpenSanctions non-commercial-use acknowledgement
or a license identifier. It returns a candidate metadata lock and keeps the
large data files outside Git.

The candidate source lock is not sufficient by itself. Before tracking it:

- run the production parser/catalog builder;
- record actual record/entity counts;
- record parser and FollowTheMoney model versions;
- review source URLs, file sizes, and checksums;
- build immutable provider packages and record their hashes.

## Test harness states

Each provider-mode execution is one of:

- `blocked_unbound`: frozen source data or a reviewed real-record binding is
  missing;
- `ready_for_fixture_generation`: source lock and both provider identities are
  bound, but concrete synthetic transaction fixtures still need generation;
- later execution states will be added with request/response evidence.

`--allow-unbound` allows generation of a planning artifact only. It never makes
an unbound execution qualification-eligible.

## Evidence

Each script creates a timestamped directory under `var/homelab/evidence` with a
`SHA256SUMS` file. Evidence must record the release image reference, source lock,
provider/catalog/activation lineage, configuration hashes, and exact request
bytes once functional execution begins.

## Non-goals

H1 does not:

- modify P50 RAG/graph/vector services;
- enable LLM influence over deterministic screening tests;
- publish homelab data publicly;
- provide regulatory clearance, release, or a confirmed false-positive decision;
- automatically activate a newly downloaded source snapshot.

## H1 r1.1 parser compatibility

The OpenSanctions artifact resolver is a standalone Python helper. This avoids
embedding Python regular expressions inside a shell heredoc, which is not
accepted reliably by the macOS Bash 3.2 parser during static validation.

## H1 r1.2 explicit SSH identity

The inventory includes `HOMELAB_OPT1_SSH_USER`, `HOMELAB_G732_SSH_USER`,
`HOMELAB_OPT2_SSH_USER`, and `HOMELAB_P50_SSH_USER`. Existing r1.1 inventories
without these fields remain compatible and default to `mindseye73`. Before any
remote operation, `common.sh` converts each plain host or SSH alias to an
explicit target such as `mindseye73@ai-g732`. This applies consistently to SSH,
rsync, registry login, source freezing, deployment, smoke, status, and teardown.

## H1 r1.3 GHCR read authentication

The deployer first attempts an anonymous pull so public release packages require
no credentials. A private package requires a dedicated personal access token
(classic) with `read:packages`; the generic token returned by `gh auth token` is
not treated as a package credential.

Run `h1-configure-ghcr-auth.sh` to store `GHCR_USERNAME` and
`GHCR_READ_TOKEN` in the ignored, mode-0600 local credentials file. During the
pull, the token is sent to G732 over SSH standard input and used with a temporary
`DOCKER_CONFIG`. The temporary registry configuration is deleted immediately
after the immutable digest is available locally. The G732 Compose service uses
`pull_policy: never` so it cannot trigger a second unauthenticated registry
request.


## H1 r1.4 gateway TLS ownership

H1 deployment is resumable after a post-migration failure. Before invoking the
migration container, the deployer counts one expected relation from each
migration family. A count of zero is treated as a fresh database, the complete
count skips migration replay, and an intermediate count fails closed as a
partial schema rather than replaying non-idempotent SQL.

The staged gateway private key remains mode `0600` and owned by the remote
`mindseye73` account. It is not bind-mounted directly into the restricted
Nginx container because the gateway drops all Linux capabilities, including
`CAP_DAC_OVERRIDE`; container root therefore cannot read a mode-0600 bind mount
owned by the host UID.

Before gateway startup, `h1-deploy.sh` copies the certificate and key through a
short-lived root helper into the external named Docker volume
`openwatchlist-homelab-gateway-tls`. Inside that volume, the certificate is
`root:root` mode `0644` and the private key is `root:nginx` mode `0640`. The
host copy remains mode `0600` and is never made world-readable.

## H1 r1.6 rootless gateway runtime

The stock Nginx entrypoint assumes container root can change ownership of
`/var/cache/nginx`. That conflicts with `cap_drop: ["ALL"]`. H1 therefore does
not add `CAP_CHOWN` or restore root privileges. The gateway runs as UID/GID
`101:101`, uses a repository-owned `nginx.conf` without a `user` directive,
places its PID and temporary paths under an ephemeral `/tmp` tmpfs, and starts
Nginx directly instead of running the stock entrypoint mutation scripts.

`h1-stage.sh` renders the API address into `gateway/default.conf` before transfer,
so the rootless container needs no writable configuration directory. Both the
custom main configuration and rendered server configuration are mounted
read-only. The TLS volume is declared external because `h1-deploy.sh` creates
and verifies it before Compose starts the gateway. The gateway retains a
read-only root filesystem, all capabilities dropped, and
`no-new-privileges:true`. Normal teardown preserves the TLS volume;
`h1-teardown.sh --purge-data` removes it.


## Persistent runtime staging boundary

`h1-stage.sh` stages only immutable configuration, secrets, migration files, and source-freeze tooling. It deliberately excludes the G732 `runtime-data` directory. That directory is persistent screening-runtime state, is prepared by `h1-deploy.sh`, and is owned by application UID `65532` after deployment. Re-running staging therefore leaves active catalog packages, runtime bindings, ownership, permissions, and directory timestamps unchanged. Normal staging must never remove, copy through, chmod, chown, or preserve timestamps on `runtime-data`.

## H1 r1.7 rootless Nginx temporary-directory initialization

The rootless Nginx master runs as UID/GID `101:101` on an ephemeral `/tmp`
tmpfs. Nginx creates hash-level children inside its configured temporary paths,
but it does not create the missing `/tmp/nginx` parent hierarchy. Starting the
binary directly therefore fails with `mkdir() "/tmp/nginx/client_temp" failed`
even though `/tmp` itself is writable.

The gateway now mounts a repository-owned `rootless-entrypoint.sh` read-only and
invokes it with `/bin/sh` as UID 101. The wrapper creates and mode-restricts the
client, proxy, FastCGI, uWSGI, and SCGI temporary directories, verifies each is
writable by the runtime identity, and then replaces itself with the Nginx master.
It performs no ownership changes, requires no Linux capabilities, writes only to
the ephemeral tmpfs, and leaves the root filesystem, configuration, and TLS
volume read-only.


## H1 r1.8 stable G732 configuration mounts

The G732 staging path preserves the `configs/release` and `secrets` directory
inodes. Restaging synchronizes files into the existing directories and never
replaces the persistent `runtime-data` directory. Deployment verifies the six
required release configuration files on the host, force-recreates the API
container after each restage, and verifies the same files are readable inside
`/etc/openwatchlist`. Host and container configuration checksums are retained in
the deployment evidence. This prevents a running container from remaining bound
to a deleted pre-restage directory inode.
