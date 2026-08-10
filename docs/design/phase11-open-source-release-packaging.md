# Phase 11 — open-source release packaging and deployment

Phase 11 converts the accepted Phase 10 product into a reproducible release candidate. It adds OCI build targets, a TLS Compose stack, immutable release-evidence persistence, actual SBOM and scanner commands, an authenticated benchmark runner, deterministic release manifests and bundles, GitHub project documentation, CI/release workflows, and Phase 10-to-Phase 11 upgrade/rollback qualification.

The installer performs static and Go regression validation only. It does not fabricate scanner or performance results. `scripts/release/qualify-release.sh` must run on the target environment to produce actual evidence and blocks when required tools are absent or thresholds fail.
