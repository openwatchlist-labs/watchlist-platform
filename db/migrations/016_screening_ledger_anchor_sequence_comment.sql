-- SEC-7 Stage 3 (3/3): document screening_ledger_anchor's column
-- semantics as live schema comments (ADR-0007 §5.3), not just ADR prose.
--
-- This exists because the column name alone proved ambiguous: "sequence"
-- could plausibly mean the event chain's sequence, the audit chain's
-- sequence, or an anchor-generation counter independent of both, since
-- the two chains this table anchors are sequenced independently (the
-- audit chain has four AppendAudit call sites against the event chain's
-- one Append -- internal/screeningledger's own §1.2 -- so their sequence
-- counters drift apart over time). Resolved during Stage 3's design pass:
-- sequence is the EVENT chain's sequence number at anchor time. audit_
-- sha256 is supplementary evidence of the audit chain's head digest at
-- that same moment -- it rides alongside the primary anchor, is not
-- keyed to any particular audit sequence number, and Verify does not
-- attempt to re-validate it against the live audit chain once further
-- audit entries have accrued past that moment (only event_sha256 is a
-- continuously-checkable invariant). See internal/screeningledger/
-- anchor.go's Anchor type doc comment for the same statement next to the
-- Go code that acts on it.
BEGIN;

DO $$
BEGIN
  IF to_regclass('screening_ledger_anchor') IS NULL THEN
    RAISE EXCEPTION 'SEC-7 anchor sequence-comment migration: screening_ledger_anchor does not exist; 015_screening_ledger_anchor.sql must run first';
  END IF;
END $$;

COMMENT ON COLUMN screening_ledger_anchor.sequence IS
  'The EVENT chain''s sequence number at anchor time -- not the audit chain''s, and not an independent anchor-generation counter. The event and audit chains are sequenced independently (AppendAudit has four call sites against Append''s one), so a single column cannot carry both; the event chain is the one ADR-0007 treats as authoritative (§3.2).';

COMMENT ON COLUMN screening_ledger_anchor.audit_sha256 IS
  'Supplementary evidence of the audit chain''s head digest at the same moment "sequence" (the event chain''s sequence) was anchored. NOT keyed to a specific audit sequence number -- it is not a second thing being anchored, only corroborating context alongside the primary event_sha256 commitment. Not continuously re-validated by Verify once later audit entries have accrued past that moment.';

COMMENT ON COLUMN screening_ledger_anchor.event_sha256 IS
  'The event chain''s digest at "sequence" (that same column, the event chain''s sequence number). This is the primary, continuously-checkable commitment Verify cross-checks the live chain against.';

COMMIT;
