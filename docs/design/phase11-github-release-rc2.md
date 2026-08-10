# Phase 11 GitHub release and post-release homelab qualification

## Purpose

Phase 11 separates artifact publication from deployment qualification.

A GitHub release candidate proves that the exact source commit can pass the Go regression and static contracts, build a container image, generate an SBOM, pass blocking high/critical image scanning, produce deterministic source assets, and—on a tag-triggered run—push and sign a multi-architecture image and publish a GitHub prerelease.

A GitHub release candidate does **not** claim that the image has passed homelab performance, provider-functional, upgrade, rollback, or deployment-hardware qualification. The release manifest therefore records `release_qualified: true` and `homelab_qualified: false` only after the tag-triggered publication path succeeds.

## Dry run

Run the workflow from `main` before creating the release tag:

```bash
gh workflow run release.yml --ref main

run_id="$(
  gh run list \
    --workflow release.yml \
    --branch main \
    --limit 1 \
    --json databaseId \
    --jq '.[0].databaseId'
)"

gh run watch "$run_id" --exit-status
```

The manual run does not log in to GHCR, push an image, sign a registry digest, or create a GitHub release. It builds a Linux AMD64 image locally on the hosted runner, runs the same source validation, generates an SBOM, scans the image, verifies Cosign installation, packages source assets, and uploads a seven-day workflow artifact for review.

## Publish `v0.1.0-rc.2`

The tag must exactly match `v$(cat VERSION)`:

```bash
git status --short
git fetch origin
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"

git tag -a v0.1.0-rc.2 -m "OpenWatchlist 0.1.0-rc.2"
git push origin v0.1.0-rc.2
```

The tag path pushes `linux/amd64` and `linux/arm64`, generates an SPDX JSON SBOM, performs blocking Trivy scanning, signs and verifies the immutable GHCR digest with GitHub OIDC, packages the exact tagged source, and creates a prerelease with checksums and a qualification manifest.

## Published assets

- `openwatchlist-0.1.0-rc.2.zip`
- `openwatchlist-0.1.0-rc.2-source.tar.gz`
- `openwatchlist-0.1.0-rc.2.manifest.json`
- `openwatchlist-platform.spdx.json`
- `IMAGE_DIGEST`
- `SHA256SUMS`

The homelab deployment must use the immutable image reference from `IMAGE_DIGEST`, not a mutable version tag.

## Post-release qualification

After publication, deploy the exact digest to the homelab and produce separate evidence for:

1. distributed deployment health and readiness;
2. native OFAC ingestion, activation, screening, lineage, and rollback;
3. OpenSanctions ingestion, FollowTheMoney mapping, activation, screening, lineage, and rollback;
4. cross-provider differential fixtures;
5. target-environment performance;
6. database upgrade and backup-based rollback.

Only that later qualification can change `homelab_qualified` to true or justify promotion from release candidate to stable `v0.1.0`.

The platform remains deterministic and advisory. Neither release publication nor homelab qualification provides regulatory clearance or disposition.

## Optional GitHub code-scanning upload

Trivy remains a mandatory release scan and its SARIF output is always retained as a workflow artifact. Uploading that SARIF file into GitHub code scanning is optional because private or internal repositories require GitHub Code Security. The upload step runs only when the repository variable `OPENWATCHLIST_ENABLE_CODE_SCANNING` is set to `true`; leaving the variable unset does not weaken the Trivy release gate. Enable GitHub Code Security first, then set the variable when Security-tab ingestion is desired.
