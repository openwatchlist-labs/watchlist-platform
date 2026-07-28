# Public prerelease engineering reconstruction

This change reconstructs the smallest non-publishing release qualification
surface after the clean-repository restart and R2.2.1 security repair.

It prepares `v0.1.0-rc.3` by running complete native CI, producing deterministic
source and native assets twice, comparing every output byte, and qualifying
Linux amd64, Linux arm64, Darwin arm64, and the host-native Rust
`catalog-mmap` binary.

The workflow writes only to runner-local temporary storage. It does not upload
artifacts, create tags or releases, push images, deploy, or publish packages.
