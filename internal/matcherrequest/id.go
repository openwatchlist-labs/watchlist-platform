package matcherrequest

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

func stableRequestID(request CandidateSearchRequest) string {
	tx := ""
	if request.TransactionIndex != nil {
		tx = strconv.Itoa(*request.TransactionIndex)
	}
	attributeKeys := make([]string, 0, len(request.Query.Attributes))
	for key := range request.Query.Attributes {
		attributeKeys = append(attributeKeys, key)
	}
	sort.Strings(attributeKeys)
	attributeParts := make([]string, 0, len(attributeKeys))
	for _, key := range attributeKeys {
		attributeParts = append(attributeParts, key+"="+request.Query.Attributes[key])
	}
	parts := []string{
		RequestSchemaVersion,
		ProjectorVersion,
		string(request.RequestKind),
		request.MessageID,
		request.TransactionID,
		tx,
		request.NativePath,
		strconv.Itoa(request.Occurrence),
		string(request.SemanticRole),
		string(request.PartyRole),
		string(request.ValueType),
		string(request.TriggerPolicy),
		request.Query.OriginalValue,
		request.Query.NormalizedValue,
		strings.Join(attributeParts, "\x1e"),
		joinRoutes(request),
		joinTargets(request),
		request.NormalizationProfile,
		request.ThresholdProfile,
		joinSupporting(request),
		request.SourceLineage.SourcePayloadReference,
		request.SourceLineage.ParserVersion,
		request.SourceLineage.ExecutorVersion,
		request.SourceLineage.EvidenceBundleID,
		request.SourceLineage.EvidenceID,
		request.SourceLineage.ElementID,
		string(request.SourceLineage.MessageDefinition),
		request.SourceLineage.MessageNamespace,
		request.SourceLineage.ScreeningPlan.PlanID,
		request.SourceLineage.ScreeningPlan.PlanVersion,
		request.SourceLineage.ScreeningPlan.PlanChecksum,
	}
	return digestID("request_", parts)
}

func stableBatchID(batch RequestBatch) string {
	parts := []string{
		BatchSchemaVersion,
		batch.InputEvidenceBundleID,
		batch.MessageID,
		string(batch.MessageDefinition),
		batch.MessageNamespace,
		batch.SourcePayloadReference,
		batch.ParserVersion,
		batch.ExecutorVersion,
		batch.ProjectorVersion,
		batch.ScreeningPlan.PlanID,
		batch.ScreeningPlan.PlanVersion,
		batch.ScreeningPlan.PlanChecksum,
	}
	for _, request := range batch.Requests {
		parts = append(parts, request.RequestID)
	}
	return digestID("request_batch_", parts)
}

func stableReplayID(envelope ReplayEnvelope) string {
	parts := []string{
		ReplaySchemaVersion,
		envelope.ProjectorVersion,
		envelope.ProjectionContract.SelectionPolicy,
		envelope.ProjectionContract.OrderingPolicy,
		envelope.ProjectionContract.IdentityPolicy,
		envelope.ProjectionContract.LineagePolicy,
		envelope.Input.EvidenceSchemaVersion,
		envelope.Input.EvidenceBundleID,
		envelope.Input.SourcePayloadReference,
		envelope.Input.ParserVersion,
		envelope.Input.ExecutorVersion,
		envelope.Input.ScreeningPlan.PlanID,
		envelope.Input.ScreeningPlan.PlanVersion,
		envelope.Input.ScreeningPlan.PlanChecksum,
		envelope.RequestBatch.BatchID,
	}
	return digestID("replay_", parts)
}

func digestID(prefix string, parts []string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return prefix + hex.EncodeToString(sum[:12])
}

func joinRoutes(request CandidateSearchRequest) string {
	values := make([]string, 0, len(request.MatchRoutes))
	for _, value := range request.MatchRoutes {
		values = append(values, string(value))
	}
	return strings.Join(values, "\x1e")
}

func joinTargets(request CandidateSearchRequest) string {
	values := make([]string, 0, len(request.TargetEntityTypes))
	for _, value := range request.TargetEntityTypes {
		values = append(values, string(value))
	}
	return strings.Join(values, "\x1e")
}

func joinSupporting(request CandidateSearchRequest) string {
	values := make([]string, 0, len(request.SupportingFields))
	for _, value := range request.SupportingFields {
		values = append(values, string(value))
	}
	return strings.Join(values, "\x1e")
}
