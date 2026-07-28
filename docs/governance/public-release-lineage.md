# Public-release lineage

The public repository begins from a new root commit created during OpenWatchlist
Clean Restart R2.1.2.2. The previous private clean-restart history is preserved in
a checksummed local Git bundle outside the public repository.

The private canonical commit and tree identifiers are intentionally recorded
only in off-repository, access-controlled evidence. They are not published in
this repository because rewritten GitHub objects can remain retrievable through
cached or retained references.

The new root removes workstation-specific absolute paths from reachable public
history while retaining reviewed source-lineage and imported-blob evidence under
`.clean-restart/`. The preservation bundle is not committed, uploaded, or named
by object ID in the public repository.
