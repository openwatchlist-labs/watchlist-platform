package revieworchestrator

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/analystnote"
	"github.com/openwatchlist-labs/watchlist-platform/internal/falsepositive"
	"github.com/openwatchlist-labs/watchlist-platform/internal/matcherprovider"
	"github.com/openwatchlist-labs/watchlist-platform/internal/policyengine"
	"github.com/openwatchlist-labs/watchlist-platform/internal/rag"
)

type Orchestrator struct {
	classifier  *falsepositive.Classifier
	policy      *policyengine.Engine
	retriever   *rag.Retriever
	profile     analystnote.Profile
	noteFactory NoteProviderFactory
}

func New(classifier *falsepositive.Classifier, policy *policyengine.Engine, retriever *rag.Retriever, profile analystnote.Profile, noteFactory NoteProviderFactory) (*Orchestrator, error) {
	if classifier == nil || policy == nil || retriever == nil {
		return nil, fmt.Errorf("classifier, policy engine, and retriever are required")
	}
	if err := analystnote.ValidateProfile(profile); err != nil {
		return nil, err
	}
	return &Orchestrator{classifier: classifier, policy: policy, retriever: retriever, profile: profile, noteFactory: noteFactory}, nil
}

func (o *Orchestrator) Run(input matcherprovider.ResultBatch, options RunOptions) (RunBundle, error) {
	if err := matcherprovider.ValidateResultBatch(input); err != nil {
		return RunBundle{}, fmt.Errorf("matcher results: %w", err)
	}
	if strings.TrimSpace(options.TenantID) == "" || strings.TrimSpace(options.SourceReference) == "" {
		return RunBundle{}, fmt.Errorf("tenant_id and source_reference are required")
	}
	if _, err := time.Parse(time.RFC3339, options.EffectiveAt); err != nil {
		return RunBundle{}, fmt.Errorf("effective_at must be RFC3339: %w", err)
	}

	observations, err := falsepositive.ObservationsFromMatcherResults(input, options.SourceReference)
	if err != nil {
		return RunBundle{}, err
	}
	if options.CaseID != "" {
		filtered := observations.Observations[:0]
		for _, observation := range observations.Observations {
			if observation.CaseID == options.CaseID {
				filtered = append(filtered, observation)
			}
		}
		if len(filtered) == 0 {
			return RunBundle{}, fmt.Errorf("case_id %q was not found in matcher results", options.CaseID)
		}
		observations.Observations = append([]falsepositive.Observation(nil), filtered...)
		observations = falsepositive.CanonicalizeObservationBatch(observations)
		if err := falsepositive.ValidateObservationBatch(observations); err != nil {
			return RunBundle{}, err
		}
	}
	classifications, err := o.classifier.ClassifyBatch(observations)
	if err != nil {
		return RunBundle{}, err
	}
	decisions, err := o.policy.EvaluateBatch(classifications)
	if err != nil {
		return RunBundle{}, err
	}

	cases := make([]CaseBundle, 0, len(decisions.Decisions))
	for _, decision := range decisions.Decisions {
		observation := decision.Classification.Observation
		bundle := CaseBundle{
			SchemaVersion:    CaseBundleSchema,
			CaseID:           observation.CaseID,
			CorrelationID:    correlationID(input.ResultBatchID, observation.CaseID),
			ObservationID:    observation.ObservationID,
			ClassificationID: decision.Classification.ClassificationID,
			DecisionID:       decision.DecisionID,
			Disposition:      decision.Disposition,
			ReviewRoute:      decision.ReviewRoute,
		}
		query, err := rag.QueryFromDecision(decision, options.TenantID, options.EffectiveAt)
		if err != nil {
			bundle.RetrievalStatus = RetrievalFailed
			bundle.NoteStatus = NoteRetrievalFailed
			bundle.Warnings = append(bundle.Warnings, "retrieval_query_failed: "+err.Error())
		} else {
			citations, retrieveErr := o.retriever.Retrieve(query)
			if retrieveErr != nil {
				bundle.RetrievalStatus = RetrievalFailed
				bundle.NoteStatus = NoteRetrievalFailed
				bundle.Warnings = append(bundle.Warnings, "retrieval_failed: "+retrieveErr.Error())
			} else {
				bundle.RetrievalStatus = RetrievalCompleted
				bundle.CitationPackage = &citations
				switch {
				case decision.ReviewRoute == policyengine.ReviewRouteAutoRelease:
					bundle.NoteStatus = NoteSkippedAutoClear
				case o.noteFactory == nil:
					bundle.NoteStatus = NoteDisabled
				default:
					input := analystnote.DraftInput{Decision: decision, CitationPackage: citations, Profile: o.profile}
					provider := o.noteFactory(input)
					if provider == nil {
						bundle.NoteStatus = NoteDisabled
					} else if invocation, noteErr := analystnote.Generate(input, provider); noteErr != nil {
						bundle.NoteStatus = NoteGenerationFailed
						bundle.Warnings = append(bundle.Warnings, "analyst_note_failed: "+noteErr.Error())
					} else {
						bundle.NoteStatus = NoteGenerated
						bundle.AnalystInvocation = &invocation
					}
				}
			}
		}
		bundle.Warnings = sortedUnique(bundle.Warnings)
		bundle.CaseBundleID = stableCaseBundleID(bundle)
		cases = append(cases, bundle)
	}

	output := RunBundle{
		SchemaVersion: RunBundleSchema, OrchestratorVersion: OrchestratorVersion,
		TenantID: options.TenantID, EffectiveAt: options.EffectiveAt, SourceReference: options.SourceReference,
		InputResultBatch: input, Observations: observations, Classifications: classifications, Decisions: decisions, Cases: cases,
	}
	output.Summary = summarizeCases(cases)
	output.RunID = stableRunID(output)
	output.AuditEvents = buildAudit(output)
	output.AuditHead = output.AuditEvents[len(output.AuditEvents)-1].EventHash
	if err := ValidateRunBundle(output); err != nil {
		return RunBundle{}, err
	}
	return output, nil
}

func summarizeCases(cases []CaseBundle) RunSummary {
	s := RunSummary{TotalCases: len(cases)}
	for _, c := range cases {
		switch c.Disposition {
		case policyengine.DispositionClear:
			s.ClearCases++
		case policyengine.DispositionInvestigate:
			s.InvestigateCases++
		case policyengine.DispositionEscalate:
			s.EscalateCases++
		}
		if c.RetrievalStatus == RetrievalCompleted {
			s.RetrievalCompleted++
		} else {
			s.RetrievalFailed++
		}
		switch c.NoteStatus {
		case NoteGenerated:
			s.NotesGenerated++
		case NoteGenerationFailed, NoteRetrievalFailed:
			s.NotesFailed++
		default:
			s.NotesDisabledOrSkipped++
		}
	}
	return s
}

func sortedUnique(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
