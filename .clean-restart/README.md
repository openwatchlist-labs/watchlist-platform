# Clean Restart Control Boundary

This directory records provenance and permanent controls for OpenWatchlist Clean
Restart R1.6.

Generated during bootstrap:

- `import-manifest.json` — immutable source commit/tree and every imported blob;
- `imported-files.sha256` — imported source-file hashes;
- `baseline-files.sha256` — historical hashes for the complete staged baseline;
- `import-plan.json` and `import-plan.tsv` — selected and excluded source paths;
- `inherited-whitespace-baseline.txt` — exact source-bound whitespace debt;
- `inherited-rustfmt-baseline.txt` — exact source-bound Rust formatting debt;
- `bootstrap-journal.txt` — fail-closed execution markers.

Bootstrap mode re-hashes every imported file and requires complete staged
baseline identity. Normal CI treats these records as immutable provenance but
does not compare every current source file to its initial hash. This permits
reviewed future development.

An inherited debt exception remains active only while its file still has the
exact imported hash. Once that file changes, the exception retires and the file
must be clean. New debt is never accepted.
