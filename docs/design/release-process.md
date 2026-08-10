# Release process

## Two-stage qualification model

Phase 11 separates GitHub artifact publication from post-release homelab qualification.

### Stage 1: GitHub release candidate

The GitHub workflow is release-blocking for:

1. complete Go regression;
2. Phase 11 static contracts;
3. `govulncheck`;
4. container image build;
5. SPDX image SBOM generation;
6. blocking high/critical Trivy scan;
7. deterministic source archives, manifest, and checksums;
8. multi-architecture GHCR push on a matching version tag;
9. keyless Cosign signing and signature verification;
10. GitHub prerelease publication.

The workflow deliberately does not run Compose deployment, target-hardware benchmark, provider-functional tests, database upgrade, or rollback qualification. Those tests require the intended homelab topology and execute after publication against the immutable image digest.

Run a non-publishing workflow dry run from `main` before creating a tag:

```bash
gh workflow run release.yml --ref main
```

The dry run builds and scans a local Linux AMD64 image, generates an SBOM, validates Cosign installation, and uploads reviewable release assets. It does not push an image, sign a registry digest, or create a GitHub release.

To publish, the tag must exactly match `v$(cat VERSION)`. For Phase 11 r8:

```bash
git tag -a v0.1.0-rc.2 -m "OpenWatchlist 0.1.0-rc.2"
git push origin v0.1.0-rc.2
```

The resulting manifest records `release_qualified: true` and `homelab_qualified: false`.

### Stage 2: post-release homelab qualification

Deploy the exact published GHCR digest across the homelab and produce separate evidence for:

1. distributed health/readiness and configuration lineage;
2. native OFAC functional fixtures;
3. OpenSanctions functional fixtures;
4. cross-provider differential fixtures;
5. authenticated target-environment benchmark;
6. Phase 10/Phase 11 database upgrade and backup rollback.

Only this stage can qualify promotion from the release candidate to stable `v0.1.0`.

## Legacy single-host qualification command

The existing orchestrated command remains available for local integration evidence:

```bash
./scripts/release/qualify-release.sh
```

Its Docker Desktop benchmark is not a prerequisite for GitHub release publication. It must not be represented as homelab qualification.

## Release evidence

The GitHub prerelease contains exact source archives, an SPDX image SBOM, the immutable image digest, a qualification manifest, and `SHA256SUMS`.

`artifacts/phase11/` and `release-dist/` remain local evidence directories for the legacy single-host qualification path. Generated evidence, runtime catalogs, local secrets, and build output are not committed.

## Scanner policy

High or critical dependency/image findings or blocking misconfigurations fail the relevant qualification stage. Exceptions require a documented risk acceptance outside this repository; suppressions must be narrow, time-bounded, and reviewable.

## Benchmark policy

The default authenticated workload is `GET /v1/alerts` through the TLS gateway. The runner sends 64 unmeasured warm-up requests, then measures 2,000 requests at concurrency 16. The default homelab gates remain zero failed measured requests, p95 no more than 250 ms, and throughput at least 100 requests/second.

Benchmark evidence is collected only after release on the intended homelab deployment. Hosted GitHub runners and Docker Desktop are not substitutes for deployment-hardware qualification.

## GitHub release safety

The manual workflow path is non-publishing. Only a pushed tag matching the repository `VERSION` may log in to GHCR, push the multi-architecture image, sign its digest, and create a prerelease. SBOM release attachment is handled explicitly with the other release assets rather than implicitly by the SBOM action.

The release and homelab processes remain deterministic and advisory. They do not provide regulatory clearance or disposition.

## Optional GitHub code-scanning upload

Trivy remains a mandatory release scan and its SARIF output is always retained as a workflow artifact. Uploading that SARIF file into GitHub code scanning is optional because private or internal repositories require GitHub Code Security. The upload step runs only when the repository variable `OPENWATCHLIST_ENABLE_CODE_SCANNING` is set to `true`; leaving the variable unset does not weaken the Trivy release gate. Enable GitHub Code Security first, then set the variable when Security-tab ingestion is desired.
