# Phase 10 — Evaluation and Release Qualification

Phase 10 turns the accepted Phase 9 product into a release candidate through a checksum-bound evaluation suite and release-blocking gates. The report is content-addressed, replayable, immutable in PostgreSQL, and fails closed.

The qualified path covers ISO 20022 and external alert sources, canonical evidence, candidate result vectors, deterministic scoring, false-positive classification, policy routing, alert and case creation, governed RAG/LLM assistance, independent analyst review, and durable audit verification.

## Evaluation categories

Exact and fuzzy matches, transliteration/script variants, common false positives, sparse data, entity-type and geography contradictions, duplicate delivery, catalog and policy changes, external-engine alerts, historical replay, RAG relevance/citations, unsupported claims, tenant isolation, durability, multi-instance idempotency, rollback, scanning, and documentation.

## Release blockers

A release is blocked by any false negative, deterministic replay mismatch, authorization leak, unsupported LLM claim, invalid citation, durability or restore failure, multi-instance inconsistency, failed dependency/container/secret/license scan, rollback failure, missing documentation, or threshold regression in precision, recall, false-positive reduction, latency, throughput, or batch capacity.

The fixture benchmark is a deterministic qualification contract. Production release evidence must replace fixture benchmark values with measured results from the target deployment while preserving the same schema and thresholds.
