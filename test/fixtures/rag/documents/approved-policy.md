# Transaction Screening Policy

## Decision ownership

The deterministic policy engine owns the clear, investigate, and escalate disposition. Retrieved material and generated analyst notes provide context only and must not change the authoritative decision or review route.

## Entity-type conflicts

When a candidate entity type is incompatible with the screened ISO 20022 field, the case remains investigate unless an independently qualifying primary identifier resolves the conflict. The blocker entity_type_conflict prevents escalation while the conflict remains unresolved.

## Supporting evidence

A supporting-evidence field cannot independently escalate a case. Exact dates, addresses, countries, and configured account identifiers may corroborate a candidate but remain secondary evidence unless linked to a qualifying candidate-alert match.

## Primary identifiers

An exact LEI or exact BIC on a candidate-alert field may support escalation when the score threshold is met and no escalation blocker remains.
