# Phase 7B live-source goldens

Every file in this directory is generated from synthetic, invented test data. No live OFAC or OpenSanctions content is committed.

The FtM fixture deliberately uses the real line-oriented entity shape and separate target, Address, and Sanction records. The goldens lock source-manifest generation, provider projection, source membership lineage, and deterministic replay.

## Licensing behavior fixture

The source-manifest golden includes an OpenSanctions noncommercial license mode
only to verify policy propagation. It contains invented local fixture data, does
not redistribute an OpenSanctions dataset, and does not relicense this Apache-2.0
repository. Live data acquisition remains subject to the provider's current
terms.
