# Third-party notices

OpenWatchlist Platform source code is distributed under the Apache License 2.0.
The repository does not vendor third-party source packages in the current clean
baseline; Go and Rust manifests currently resolve only repository-owned modules.

The project contains synthetic fixtures that model public data formats and API
contracts associated with the U.S. Department of the Treasury OFAC and
OpenSanctions. No live sanctions-list subjects or licensed OpenSanctions dataset
content are committed. Names, identifiers, addresses, and relationships in the
fixtures are invented.

References to OpenSanctions URLs, dataset identifiers, and licensing modes are
metadata used to test acquisition and policy behavior. They do not redistribute
OpenSanctions data and do not relicense this repository. Anyone acquiring live
third-party data must comply with the provider's current terms independently.

GitHub Actions workflows reference actions maintained by GitHub. Those actions
remain governed by their own repositories and licenses and are pinned here to
immutable commit SHAs for build reproducibility.
