# Validated Regression Cases

## Entity type mismatch fixture

A creditor name of EXAMPLE VESSEL matched an OFAC-shaped vessel record with a perfect textual score. The candidate was suppressed because creditor.name permits individual and organization candidates but not vessels. The validated outcome was investigate with entity_type_conflict.

## Substring fixture

SCUBA EQUIPMENT PURCHASE must not match CUBA because CUBA is not a whole token. The validated pattern is substring_containment and the route is clear eligible under the baseline policy.
