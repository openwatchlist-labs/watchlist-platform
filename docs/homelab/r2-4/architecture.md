# R2.4 role architecture

## Roles

| Role | Activation mode | Qualified responsibility |
|---|---|---|
| Opt1 | Runtime | Platform API and an OpenWatchlist-owned PostgreSQL instance |
| Opt2 | Runtime | Published `catalog-mmap` binary and deterministic catalog package |
| G732 | Capability-only | Existing Ollama API and required model availability |
| P50 | Capability-only | Existing Qdrant and Neo4j service availability |

The public names identify roles, not private host addresses.

## Opt1 isolation

Opt1 owns only its bounded R2.4 resources:

- API bind: `127.0.0.1:8080`
- OpenWatchlist PostgreSQL bind: `127.0.0.1:15432`
- Existing protected PostgreSQL bind: port `5432`, outside the activation scope
- Owned container and volume labels identify the R2.4 resources
- Runtime secrets are required only on Opt1 and remain outside the repository

The deployment neither pulls nor builds images, installs packages, nor mutates
systemd. It uses a locally available `pgvector/pgvector:pg16` image and the
published Linux AMD64 executable.

## Opt2 catalog boundary

Opt2 uses the published `catalog-mmap` executable to materialize and verify a
memory-mapped catalog package from the repository's synthetic conformance
input. The accepted package has:

- 3 records
- 8 names
- 3 identifiers
- package SHA-256:
  `8c5e581ad36807c15a2ae00c5cb4e8b7f9154e208b369ff3227617294a473367`

The qualification performs exact name, identifier, and record-ID lookups. No
resident catalog daemon is started.

## Capability-only roles

G732 and P50 are inspected before and after the activation cycle. The harness
must not create runtime roots, active links, systemd units, containers, or new
processes on either role.

## Controlled sequence

1. Validate accepted no-start staging evidence.
2. Verify exact source-locked activation inputs.
3. Revalidate all four roles and protected workloads.
4. Transfer the Opt1 input archive only.
5. Run temporary Opt1 configuration qualification.
6. Transfer the Opt2 archive only after qualification passes.
7. Activate Opt2, then Opt1.
8. Run first smoke qualification.
9. Roll back both runtime roles.
10. Verify stage and protected-workload preservation.
11. Reactivate Opt2, then Opt1.
12. Run final smoke and capability qualification.
13. Remove temporary archives and seal evidence.
