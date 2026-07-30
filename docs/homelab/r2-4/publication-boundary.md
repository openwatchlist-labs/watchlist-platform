# R2.4 public publication boundary

## Included

The public repository may contain:

- release tags, commit IDs, tree IDs, release IDs, and public asset hashes;
- sanitized role names and loopback service binds;
- synthetic fixture bytes already governed by the repository;
- deterministic package and corpus checksums;
- reusable deployment, readiness, smoke, and rollback logic;
- non-operational example policies using `.example.invalid` hosts;
- sanitized qualification status, counts, and endpoint outcomes;
- engineering lessons and failure-mode controls.

## Excluded

Do not commit:

- private IP addresses or Tailscale addresses;
- SSH usernames or workstation usernames;
- host-specific home directories or evidence roots;
- secret values, signing keys, database passwords, tokens, or environment files;
- live container IDs, process IDs, runtime state, logs, packet captures, or
  generated evidence directories;
- customer data, real watchlist data beyond approved public source fixtures, or
  regulatory decisions;
- an operational policy file.

## Policy handling

The committed harness policy is marked `public_template: true` and is
non-operational. Operators must copy it outside the repository, replace every
placeholder, set `public_template` to `false`, restrict file permissions, and
set `R183_POLICY_OVERRIDE`.

The runtime entrypoints fail closed while the public template is active.

## Evidence handling

Private evidence may be summarized into the committed sanitized result only
after confirming that the summary contains no private infrastructure identity
or secret-bearing material.
