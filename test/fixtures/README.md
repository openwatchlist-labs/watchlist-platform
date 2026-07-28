# Test fixture safety

All fixture records in this repository are synthetic or deterministic test
material. They must never be used as production credentials or screening data.

The following key-like files are fixed test vectors only:

- `review-console/signing-key.hex` — deterministic review-console signing key;
- `screening-ledger/snapshot-key.hex` — deterministic ledger snapshot key.

They are intentionally public, provide no access to any deployed environment,
and production use is prohibited. Production keys must be generated, stored,
rotated, and audited outside the repository.
