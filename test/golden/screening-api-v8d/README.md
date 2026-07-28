# Phase 8D API goldens

These responses are generated from the Phase 8D fixture retrieval backend,
checksum-addressed Phase 8C policy, and bounded candidate projection registry.

Validation compares real-time and batch responses exactly, except that the
readiness upstream URL is dynamically allocated during the test and is checked
separately. Any scoring, ordering, evidence, policy checksum, lineage, or schema
change requires an intentional golden update.
