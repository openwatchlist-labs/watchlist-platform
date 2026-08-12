package screeningapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertlistmapping"
	"github.com/openwatchlist-labs/watchlist-platform/internal/candidatescoring"
	"github.com/openwatchlist-labs/watchlist-platform/internal/runtimemmapclient"
)

var ErrRuntimeUnavailable = errors.New("rust candidate runtime is unavailable")

type Service struct {
	Loader        StateLoader
	Runtime       RuntimeProvider
	MaxCandidates int
	Clock         func() time.Time
	// Scoring is not optional at runtime (ADR-0004 §6): a Service used to
	// process requests must be constructed with a verified binding. cmd/
	// screening-api/main.go's serve() refuses to start otherwise.
	Scoring *ScoringBinding
}

func (service *Service) Ready() error {
	if service.Loader == nil || service.Runtime == nil {
		return fmt.Errorf("state loader and runtime provider are required")
	}
	state, err := service.Loader.Load()
	if err != nil {
		return err
	}
	return service.Runtime.Ready(state.Catalog)
}

func (service *Service) Screen(ctx context.Context, request ScreeningRequest, correlationID, idempotencyKey string) (ScreeningResponse, error) {
	return service.screenAt(ctx, request, correlationID, idempotencyKey, service.now())
}

func (service *Service) screenAt(ctx context.Context, request ScreeningRequest, correlationID, idempotencyKey string, processedAt time.Time) (ScreeningResponse, error) {
	if err := ValidateRequest(request, service.MaxCandidates); err != nil {
		return ScreeningResponse{}, err
	}
	if service.Scoring == nil {
		return ScreeningResponse{}, fmt.Errorf("scoring binding is not configured")
	}
	state, err := service.Loader.Load()
	if err != nil {
		return ScreeningResponse{}, err
	}
	resolution, err := alertlistmapping.Resolve(state.Mapping, state.Catalog, alertlistmapping.ResolveRequest{SourceSystemID: request.SourceSystemID, RawListName: request.RawListName, At: request.EffectiveAt})
	if err != nil {
		return ScreeningResponse{}, err
	}
	response := ScreeningResponse{
		SchemaVersion:  ResponseSchemaVersion,
		APIVersion:     APIVersion,
		CorrelationID:  correlationID,
		IdempotencyKey: idempotencyKey,
		ProcessedAt:    processedAt.UTC(),
		Status:         StatusBlocked,
		Request:        request,
		ListResolution: resolution,
		Candidates:     []Candidate{},
		Policy:         service.Scoring.policy,
	}
	if !resolution.Available {
		if resolution.ReviewBlocker != "" {
			response.ReviewBlockers = []string{resolution.ReviewBlocker}
		}
		response.ScreeningID = screeningID(response)
		return response, nil
	}
	pointer, ok := findActivePointer(state.Catalog, resolution.ComponentID)
	if !ok || pointer.VersionID != resolution.ActiveCatalogVersionID {
		return ScreeningResponse{}, fmt.Errorf("%w: active catalog pointer changed during resolution", ErrRuntimeUnavailable)
	}
	version, ok := findCatalogVersion(state.Catalog, pointer.VersionID)
	if !ok {
		return ScreeningResponse{}, fmt.Errorf("%w: active catalog version %s is missing", ErrRuntimeUnavailable, pointer.VersionID)
	}
	runtimeQuery := runtimemmapclient.Query{
		RequestID:      "api-" + digest(request)[:24],
		Kind:           runtimeQueryKind(request.Query.Kind),
		Value:          request.Query.Value,
		IdentifierType: request.Query.IdentifierType,
		Prefix:         request.Query.Prefix,
		Limit:          effectiveLimit(request.Query.Limit, service.MaxCandidates),
	}
	result, err := service.Runtime.Lookup(ctx, resolution.ComponentID, pointer.VersionID, runtimeQuery)
	if err != nil {
		return ScreeningResponse{}, fmt.Errorf("%w: %v", ErrRuntimeUnavailable, err)
	}
	response.Runtime = &RuntimeLineage{
		SchemaVersion:       RuntimeLineageSchema,
		ClientVersion:       runtimemmapclient.ClientVersion,
		WorkerProtocol:      result.Info.ProtocolVersion,
		ComponentID:         pointer.ComponentID,
		CatalogVersionID:    pointer.VersionID,
		CatalogActivationID: pointer.ActivationID,
		CatalogEpoch:        pointer.Epoch,
		CatalogID:           version.CatalogID,
		CatalogVersion:      version.CatalogVersion,
		CatalogChecksum:     version.CatalogChecksum,
		CatalogMode:         string(versionMode(version)),
		PackageSHA256:       result.Info.PackageSHA256,
		RuntimeRecordCount:  result.Info.RecordCount,
	}
	allowed := entityTypeSet(request.Query.TargetEntityTypes)
	for _, candidate := range result.Candidates {
		if len(allowed) > 0 {
			if _, ok := allowed[candidate.EntityType]; !ok {
				continue
			}
		}
		value := Candidate{
			RecordID:        candidate.RecordID,
			EntityType:      candidate.EntityType,
			PrimaryName:     candidate.PrimaryName,
			MatchKind:       candidate.MatchKind,
			MatchedValue:    candidate.MatchedValue,
			NormalizedQuery: candidate.NormalizedQuery,
		}
		value.CandidateID = stableID("screening_candidate_", struct {
			RequestID string    `json:"request_id"`
			Component string    `json:"component_id"`
			Version   string    `json:"version_id"`
			Candidate Candidate `json:"candidate"`
		}{RequestID: request.RequestID, Component: pointer.ComponentID, Version: pointer.VersionID, Candidate: value})
		response.Candidates = append(response.Candidates, value)
	}

	if request.Query.Kind == QueryRecordID {
		// §4: a record-ID lookup has no subject to compare against.
		// Returning it with an unpopulated score would be the silent
		// degradation §6 rejects, so the whole item is blocked instead.
		response.CandidateCount = len(response.Candidates)
		response.Status = StatusBlocked
		response.ReviewBlockers = append(response.ReviewBlockers, BlockerScoringSubjectUnavailable)
		response.ScreeningID = screeningID(response)
		return response, nil
	}

	envelopes := make([]candidatescoring.CandidateEnvelope, 0, len(response.Candidates))
	var missingRecordIDs []string
	for _, candidate := range response.Candidates {
		projected, ok := service.Scoring.index[candidate.RecordID]
		if !ok {
			missingRecordIDs = append(missingRecordIDs, candidate.RecordID)
			continue
		}
		envelopes = append(envelopes, candidatescoring.CandidateEnvelope{
			Candidate: projected,
			Retrieval: candidatescoring.RetrievalEvidence{Routes: []string{candidate.MatchKind}},
		})
	}
	if len(missingRecordIDs) > 0 {
		// §6: a data gap in an artifact, not a service fault. The
		// retrieval evidence is real and must not be discarded -- the
		// whole item is blocked, loudly, rather than partially scored.
		response.CandidateCount = len(response.Candidates)
		response.Status = StatusBlocked
		response.ReviewBlockers = append(response.ReviewBlockers, BlockerCandidateProjectionUnavailable)
		for _, recordID := range missingRecordIDs {
			response.ReviewBlockers = append(response.ReviewBlockers, BlockerCandidateProjectionUnavailable+":"+recordID)
		}
		response.ScreeningID = screeningID(response)
		return response, nil
	}

	if len(envelopes) > 0 {
		scoreRequest := candidatescoring.Request{
			SchemaVersion: candidatescoring.RequestSchemaV1,
			RequestID:     request.RequestID,
			FieldPath:     "query.value",
			OriginalValue: request.Query.Value,
			Subject:       scoringSubject(request.Query),
			Lineage:       service.Scoring.lineage,
			Candidates:    envelopes,
		}
		scored, err := service.Scoring.engine.Score(scoreRequest)
		if err != nil {
			return ScreeningResponse{}, fmt.Errorf("score candidates: %w", err)
		}
		byRecordID := make(map[string]Candidate, len(response.Candidates))
		for _, candidate := range response.Candidates {
			byRecordID[candidate.RecordID] = candidate
		}
		reordered := make([]Candidate, 0, len(scored.Candidates))
		for _, result := range scored.Candidates {
			candidate := byRecordID[result.CandidateID]
			candidate.Score = result.Score
			candidate.StrengthBand = result.StrengthBand
			candidate.ExactIdentifierMatched = result.ExactIdentifierMatched
			candidate.ExactNameMatched = result.ExactNameMatched
			candidate.ReasonCodes = result.ReasonCodes
			candidate.Components = result.Components
			candidate.Evidence = result.Evidence
			reordered = append(reordered, candidate)
		}
		response.Candidates = reordered
	}

	response.CandidateCount = len(response.Candidates)
	if response.CandidateCount > 0 {
		response.Status = StatusMatched
	} else {
		response.Status = StatusNoCandidates
	}
	response.ScreeningID = screeningID(response)
	return response, nil
}

func (service *Service) ScreenBatch(ctx context.Context, request BatchRequest, correlationID, idempotencyKey string) (BatchResponse, error) {
	if err := ValidateBatchRequest(request, service.MaxCandidates); err != nil {
		return BatchResponse{}, err
	}
	processedAt := service.now()
	output := BatchResponse{
		SchemaVersion:  BatchResponseSchemaVersion,
		APIVersion:     APIVersion,
		CorrelationID:  correlationID,
		IdempotencyKey: idempotencyKey,
		ProcessedAt:    processedAt,
		FailurePolicy:  "atomic_no_partial_results",
		Results:        make([]ScreeningResponse, 0, len(request.Requests)),
	}
	for _, item := range request.Requests {
		response, err := service.screenAt(ctx, item, correlationID, idempotencyKey, processedAt)
		if err != nil {
			return BatchResponse{}, err
		}
		output.Results = append(output.Results, response)
		switch response.Status {
		case StatusMatched:
			output.Summary.Matched++
		case StatusNoCandidates:
			output.Summary.NoCandidates++
		case StatusBlocked:
			output.Summary.Blocked++
		}
		output.Summary.Candidates += response.CandidateCount
	}
	output.Summary.Total = len(output.Results)
	output.BatchID = batchID(output)
	return output, nil
}

func ValidateRequest(request ScreeningRequest, maxCandidates int) error {
	if request.SchemaVersion != RequestSchemaVersion {
		return fmt.Errorf("schema_version must be %q", RequestSchemaVersion)
	}
	if err := validateToken("request_id", request.RequestID, 96); err != nil {
		return err
	}
	if err := validateToken("source_system_id", request.SourceSystemID, 128); err != nil {
		return err
	}
	if request.RawListName == "" || len(request.RawListName) > 512 {
		return fmt.Errorf("raw_list_name must contain 1..512 bytes")
	}
	if request.EffectiveAt.IsZero() {
		return fmt.Errorf("effective_at is required")
	}
	if strings.TrimSpace(request.Query.Value) == "" || len(request.Query.Value) > 4096 {
		return fmt.Errorf("query.value must contain 1..4096 bytes")
	}
	if request.Query.Limit < 0 || request.Query.Limit > maxCandidates {
		return fmt.Errorf("query.limit must be between 0 and %d", maxCandidates)
	}
	switch request.Query.Kind {
	case QueryName:
		if request.Query.IdentifierType != "" {
			return fmt.Errorf("query.identifier_type is only valid for identifier queries")
		}
	case QueryIdentifier:
		if strings.TrimSpace(request.Query.IdentifierType) == "" || len(request.Query.IdentifierType) > 256 {
			return fmt.Errorf("query.identifier_type is required for identifier queries")
		}
		if request.Query.Prefix {
			return fmt.Errorf("query.prefix is only valid for name queries")
		}
	case QueryRecordID:
		if request.Query.IdentifierType != "" || request.Query.Prefix {
			return fmt.Errorf("record_id queries do not accept identifier_type or prefix")
		}
	default:
		return fmt.Errorf("unsupported query.kind %q", request.Query.Kind)
	}
	seen := map[string]struct{}{}
	for _, entityType := range request.Query.TargetEntityTypes {
		if !validEntityType(entityType) {
			return fmt.Errorf("unsupported target_entity_type %q", entityType)
		}
		if _, exists := seen[entityType]; exists {
			return fmt.Errorf("duplicate target_entity_type %q", entityType)
		}
		seen[entityType] = struct{}{}
	}
	return nil
}

func ValidateBatchRequest(request BatchRequest, maxCandidates int) error {
	if request.SchemaVersion != BatchRequestSchemaVersion {
		return fmt.Errorf("schema_version must be %q", BatchRequestSchemaVersion)
	}
	if len(request.Requests) == 0 {
		return fmt.Errorf("requests must not be empty")
	}
	seen := map[string]struct{}{}
	for index, item := range request.Requests {
		if err := ValidateRequest(item, maxCandidates); err != nil {
			return fmt.Errorf("requests[%d]: %w", index, err)
		}
		if _, exists := seen[item.RequestID]; exists {
			return fmt.Errorf("duplicate request_id %q", item.RequestID)
		}
		seen[item.RequestID] = struct{}{}
	}
	return nil
}

// scoringSubject maps a screening Query onto a scoring Subject per ADR-0004
// §4's table. record_id queries never reach here (screenAt short-circuits
// them before scoring). EntityType is set only when TargetEntityTypes names
// exactly one type -- the field is singular and any other count has no
// honest single answer.
func scoringSubject(query Query) candidatescoring.Subject {
	subject := candidatescoring.Subject{}
	switch query.Kind {
	case QueryName:
		subject.Names = []string{query.Value}
	case QueryIdentifier:
		subject.Identifiers = []candidatescoring.Identifier{{Type: query.IdentifierType, Value: query.Value}}
	}
	if len(query.TargetEntityTypes) == 1 {
		subject.EntityType = query.TargetEntityTypes[0]
	}
	return subject
}

func runtimeQueryKind(kind QueryKind) runtimemmapclient.QueryKind {
	switch kind {
	case QueryName:
		return runtimemmapclient.QueryName
	case QueryIdentifier:
		return runtimemmapclient.QueryIdentifier
	default:
		return runtimemmapclient.QueryRecordID
	}
}

func effectiveLimit(limit, maximum int) int {
	if limit == 0 {
		if maximum < 20 {
			return maximum
		}
		return 20
	}
	return limit
}

func entityTypeSet(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func validEntityType(value string) bool {
	switch value {
	case "individual", "organization", "government_entity", "financial_institution", "vessel", "aircraft", "jurisdiction":
		return true
	default:
		return false
	}
}

func validateToken(name, value string, maximum int) error {
	if value == "" || len(value) > maximum {
		return fmt.Errorf("%s must contain 1..%d characters", name, maximum)
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("_-.:", char) {
			continue
		}
		return fmt.Errorf("%s contains an unsupported character", name)
	}
	return nil
}

func (service *Service) now() time.Time {
	if service.Clock != nil {
		return service.Clock().UTC()
	}
	return time.Now().UTC()
}
