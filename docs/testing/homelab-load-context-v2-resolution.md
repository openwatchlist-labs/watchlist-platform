# H1 r1.13.5 load-context governed-v2 resolution repair

## Purpose

Repair the r1.13.4 planner candidate resolver without modifying the accepted
35-binding set, its review/acceptance evidence, or the promoted binding file.

r1.13.4 selected the wrong AST target because the legacy-v1 rejection text is
inside `validate_pack(pack)`. It replaced that validator with path logic even
though `pack` is already a parsed JSON dictionary, causing:

```
TypeError: argument should be a str or an os.PathLike object ... not 'dict'
```

## Repair boundary

The installer restores only `scripts/homelab/h1-binding-review.py` from the
latest r1.13.4 backup and patches the parsed candidate-pack assignment inside
`load_context`. `validate_pack(pack)` remains unchanged.

Resolution order:

1. Explicit candidate-pack argument, when provided; v1 remains rejected.
2. Exact v2 pack pinned by governed state and `candidate_pack_sha256`.
3. Latest v2 evidence pack.
4. Strict legacy-v1 rejection when no v2 pack exists.

Historical v1 evidence is neither deleted nor modified.

## Safety gates

- Requires a bound state with 35 selections, set review, acceptance, and a
  promoted binding.
- Verifies acceptance `SHA256SUMS` and snapshots all governed artifacts.
- Refuses to patch if the r1.13.4 backup cannot be found or already contains
  the broken marker.
- Runs a direct `h1-binding-review.sh show fp-001` context-load smoke test.
- Proves byte-for-byte immutability of governed state, acceptance evidence,
  promoted binding, and pinned v2 candidate pack.
