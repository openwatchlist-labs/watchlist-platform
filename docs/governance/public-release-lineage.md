# Public-release lineage

The public repository begins from a new root commit created during OpenWatchlist
Clean Restart R2.1.2.2. The previous private clean-restart history is preserved
in a checksummed local Git bundle outside the public repository.

The private canonical commit and tree identifiers are intentionally recorded
only in off-repository, access-controlled evidence. They are not published in
this repository because rewritten GitHub objects can remain retrievable through
cached or retained references.

The new root removes workstation-specific absolute paths from reachable public
history while retaining reviewed source-lineage and imported-blob evidence
under `.clean-restart/`. The preservation bundle is not committed, uploaded, or
named by object ID in the public repository.

## Reconstructed public release line

R2.1 reconstructed public governance and required checks. R2.2 rebuilt
non-publishing release qualification. R2.3 published and verified the clean
prerelease line. R2.4 advanced that line to `v0.1.0-rc.4` and completed a
controlled homelab deployment and rollback qualification.

Current public release boundary:

- release: `v0.1.0-rc.4`;
- release ID: `361927608`;
- main commit: `210dc3c00d43f4f4e9ceae6905c24c9c9ea99584`;
- main tree: `51b93dd4a4e27b5607c2a460580829490e9742d1`;
- Linux AMD64 runtime SHA-256:
  `1cf61dce31fad81d8511bac76c5a29aef3c0375a3a26d0c92f58a70a3494a29f`.

## Controlled homelab qualification

The R2.4 qualification used two runtime roles and two capability-only roles.
Public documentation records role boundaries, loopback binds, synthetic fixture
hashes, smoke outcomes, rollback qualification, and reactivation status.

Private addresses, SSH usernames, host-specific absolute paths, secret material,
container IDs, and generated evidence remain outside the public repository.

The result is a controlled homelab engineering qualification. It is not a
production, customer, regulatory, or compliance certification.
