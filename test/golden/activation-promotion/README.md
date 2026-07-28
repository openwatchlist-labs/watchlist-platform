# Phase 8F promotion goldens

The validator creates temporary immutable promotion state and compares the
checked-in current/candidate screening fixtures. The checked-in prepared state
is only a portable configuration/check fixture; it is never promoted in place.

Required deterministic properties:

- exact activation-document SHA-256 binding;
- monotonic state revisions with compare-and-swap transitions;
- hash-chained append-only audit events;
- deterministic shadow metrics and canary routing;
- current/candidate backend activation fencing;
- byte-exact public idempotent replay.
