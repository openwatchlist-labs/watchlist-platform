package revieworchestrator

import (
	"fmt"
	"reflect"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/analystnote"
	"github.com/openwatchlist-labs/watchlist-platform/internal/falsepositive"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
	"github.com/openwatchlist-labs/watchlist-platform/internal/policyengine"
	"github.com/openwatchlist-labs/watchlist-platform/internal/rag"
)

func ValidateRunBundle(bundle RunBundle) error {
	if bundle.SchemaVersion != RunBundleSchema || bundle.RunID == "" || bundle.OrchestratorVersion != OrchestratorVersion {
		return fmt.Errorf("invalid review run metadata")
	}
	if bundle.TenantID == "" || bundle.SourceReference == "" {
		return fmt.Errorf("tenant_id and source_reference are required")
	}
	if _, err := time.Parse(time.RFC3339, bundle.EffectiveAt); err != nil {
		return fmt.Errorf("invalid effective_at")
	}
	if err := matcherprovider.ValidateResultBatch(bundle.InputResultBatch); err != nil {
		return err
	}
	if err := falsepositive.ValidateObservationBatch(bundle.Observations); err != nil {
		return err
	}
	if err := falsepositive.ValidateClassificationBatch(bundle.Classifications); err != nil {
		return err
	}
	if err := policyengine.ValidateDecisionBatch(bundle.Decisions); err != nil {
		return err
	}
	if bundle.Observations.SourceReference != bundle.SourceReference || bundle.Classifications.InputObservationBatchID != bundle.Observations.BatchID || bundle.Decisions.InputClassificationBatchID != bundle.Classifications.ClassificationBatchID {
		return fmt.Errorf("review stage lineage mismatch")
	}
	if len(bundle.Cases) != len(bundle.Decisions.Decisions) {
		return fmt.Errorf("case count differs from decisions")
	}
	for i := range bundle.Cases {
		c := bundle.Cases[i]
		d := bundle.Decisions.Decisions[i]
		o := d.Classification.Observation
		if c.SchemaVersion != CaseBundleSchema || c.CaseID != o.CaseID || c.ObservationID != o.ObservationID || c.ClassificationID != d.Classification.ClassificationID || c.DecisionID != d.DecisionID || c.Disposition != d.Disposition || c.ReviewRoute != d.ReviewRoute {
			return fmt.Errorf("cases[%d] lineage mismatch", i)
		}
		if c.CorrelationID != correlationID(bundle.InputResultBatch.ResultBatchID, c.CaseID) {
			return fmt.Errorf("cases[%d] correlation mismatch", i)
		}
		if c.RetrievalStatus == RetrievalCompleted {
			if c.CitationPackage == nil {
				return fmt.Errorf("cases[%d] completed retrieval lacks citation package", i)
			}
			if err := rag.ValidateCitationPackage(*c.CitationPackage); err != nil {
				return err
			}
			if c.CitationPackage.Query.DecisionID != d.DecisionID {
				return fmt.Errorf("cases[%d] citation decision mismatch", i)
			}
		} else if c.RetrievalStatus == RetrievalFailed {
			if c.CitationPackage != nil || len(c.Warnings) == 0 || c.NoteStatus != NoteRetrievalFailed {
				return fmt.Errorf("cases[%d] invalid failed retrieval state", i)
			}
		} else {
			return fmt.Errorf("cases[%d] unsupported retrieval status %q", i, c.RetrievalStatus)
		}
		switch c.NoteStatus {
		case NoteGenerated:
			if c.AnalystInvocation == nil || c.CitationPackage == nil {
				return fmt.Errorf("cases[%d] generated note is incomplete", i)
			}
			if err := analystnote.ValidateInvocation(*c.AnalystInvocation); err != nil {
				return err
			}
			if c.AnalystInvocation.Decision.DecisionID != d.DecisionID || c.AnalystInvocation.Note.DeterministicDisposition != string(d.Disposition) || c.AnalystInvocation.Note.ReviewRoute != string(d.ReviewRoute) {
				return fmt.Errorf("cases[%d] analyst note route mismatch", i)
			}
		case NoteDisabled, NoteSkippedAutoClear:
			if c.AnalystInvocation != nil || c.RetrievalStatus != RetrievalCompleted {
				return fmt.Errorf("cases[%d] invalid skipped note state", i)
			}
			if c.NoteStatus == NoteSkippedAutoClear && d.ReviewRoute != policyengine.ReviewRouteAutoRelease {
				return fmt.Errorf("cases[%d] auto-clear skip on non-auto-release route", i)
			}
		case NoteRetrievalFailed:
			if c.AnalystInvocation != nil || c.RetrievalStatus != RetrievalFailed {
				return fmt.Errorf("cases[%d] invalid retrieval-failed note state", i)
			}
		case NoteGenerationFailed:
			if c.AnalystInvocation != nil || c.RetrievalStatus != RetrievalCompleted || len(c.Warnings) == 0 {
				return fmt.Errorf("cases[%d] invalid generation-failed state", i)
			}
		default:
			return fmt.Errorf("cases[%d] unsupported note status %q", i, c.NoteStatus)
		}
		if c.CaseBundleID != stableCaseBundleID(c) {
			return fmt.Errorf("cases[%d] case_bundle_id mismatch", i)
		}
	}
	if expected := summarizeCases(bundle.Cases); !reflect.DeepEqual(bundle.Summary, expected) {
		return fmt.Errorf("review summary mismatch")
	}
	if bundle.RunID != stableRunID(bundle) {
		return fmt.Errorf("run_id mismatch")
	}
	expectedEvents := buildAudit(bundle)
	if !reflect.DeepEqual(bundle.AuditEvents, expectedEvents) {
		return fmt.Errorf("audit events do not match bundle content")
	}
	if err := validateAudit(bundle.AuditEvents, bundle.AuditHead); err != nil {
		return err
	}
	return nil
}

func buildAudit(bundle RunBundle) []AuditEvent {
	b := &auditBuilder{}
	b.add("run_started", "", struct{ ResultBatchID, TenantID, EffectiveAt, SourceReference string }{bundle.InputResultBatch.ResultBatchID, bundle.TenantID, bundle.EffectiveAt, bundle.SourceReference})
	b.add("observations_projected", "", bundle.Observations)
	b.add("classifications_completed", "", bundle.Classifications)
	b.add("policy_decisions_completed", "", bundle.Decisions)
	for _, c := range bundle.Cases {
		if c.CitationPackage != nil {
			b.add("retrieval_completed", c.CaseID, *c.CitationPackage)
		} else {
			b.add("retrieval_failed", c.CaseID, struct {
				Status   string
				Warnings []string
			}{c.RetrievalStatus, c.Warnings})
		}
		if c.AnalystInvocation != nil {
			b.add("analyst_note_generated", c.CaseID, *c.AnalystInvocation)
		} else {
			b.add("analyst_note_not_generated", c.CaseID, struct {
				Status   string
				Warnings []string
			}{c.NoteStatus, c.Warnings})
		}
		b.add("case_completed", c.CaseID, c)
	}
	b.add("run_completed", "", bundle.Summary)
	return b.events
}
