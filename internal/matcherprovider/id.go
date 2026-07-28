package matcherprovider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogruntime"
)

func stableCandidateID(requestID string, provider ProviderDescriptor, candidate CandidateMatch) string {
	parts := []string{
		CandidateResultSchemaVersion,
		requestID,
		provider.ProviderID,
		provider.ProviderVersion,
		provider.Catalog.CatalogID,
		provider.Catalog.CatalogVersion,
		provider.Catalog.CatalogChecksum,
		string(provider.Catalog.CatalogMode),
		candidate.ProviderRecordID,
		candidate.ProviderEntityID,
		string(candidate.EntityType),
		candidate.PrimaryName,
		candidate.MatchedValue,
		candidate.NormalizedMatchedValue,
		string(candidate.MatchRoute),
		strconv.Itoa(candidate.ScoreBasisPoints),
		strconv.FormatBool(candidate.Exact),
		joinAttributes(candidate.Attributes),
		joinAssertions(candidate.SourceAssertions),
	}
	parts = append(parts, matchEvidenceIdentity(candidate.Evidence)...)
	return digestID("candidate_", parts)
}

func stableResultID(result CandidateSearchResult) string {
	parts := []string{
		CandidateResultSchemaVersion,
		result.Request.RequestID,
		result.Provider.ProviderID,
		result.Provider.ProviderVersion,
		result.Provider.Catalog.CatalogID,
		result.Provider.Catalog.CatalogVersion,
		result.Provider.Catalog.CatalogChecksum,
		string(result.Provider.Catalog.CatalogMode),
		string(result.Status),
	}
	parts = append(parts, generationIdentity(result.RuntimeGeneration)...)
	for _, candidate := range result.Candidates {
		parts = append(parts, candidate.CandidateID)
	}
	for _, diagnostic := range result.Diagnostics {
		parts = append(parts, diagnosticIdentity(diagnostic))
	}
	return digestID("candidate_result_", parts)
}

func stableResultBatchID(batch ResultBatch) string {
	parts := []string{
		ResultBatchSchemaVersion,
		batch.InputRequestBatchID,
		batch.MessageID,
		batch.RunnerVersion,
		batch.Provider.ProviderID,
		batch.Provider.ProviderVersion,
		batch.Provider.Catalog.CatalogID,
		batch.Provider.Catalog.CatalogVersion,
		batch.Provider.Catalog.CatalogChecksum,
		string(batch.Provider.Catalog.CatalogMode),
	}
	parts = append(parts, generationIdentity(batch.RuntimeGeneration)...)
	for _, result := range batch.Results {
		parts = append(parts, result.ResultID)
	}
	return digestID("candidate_result_batch_", parts)
}

func stableProviderReplayID(envelope ProviderReplayEnvelope) string {
	parts := []string{
		ProviderReplaySchemaVersion,
		envelope.RunnerVersion,
		envelope.ExecutionContract.RequestOrdering,
		envelope.ExecutionContract.CandidateOrdering,
		envelope.ExecutionContract.IdentityPolicy,
		envelope.ExecutionContract.FailurePolicy,
		envelope.ExecutionContract.LineagePolicy,
		envelope.InputReplay.ReplayID,
		envelope.ResultBatch.ResultBatchID,
	}
	return digestID("provider_replay_", parts)
}

func digestID(prefix string, parts []string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return prefix + hex.EncodeToString(sum[:12])
}

func joinAttributes(attributes map[string]string) string {
	keys := make([]string, 0, len(attributes))
	for key := range attributes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+attributes[key])
	}
	return strings.Join(parts, "\x1e")
}

func joinAssertions(assertions []SourceAssertion) string {
	parts := make([]string, 0, len(assertions))
	for _, assertion := range assertions {
		parts = append(parts, strings.Join([]string{
			assertion.SourceID,
			assertion.Authority,
			assertion.ListID,
			assertion.SourceRecordID,
			strings.Join(assertion.Programs, "\x1d"),
		}, "\x1c"))
	}
	return strings.Join(parts, "\x1e")
}

func generationIdentity(stamp *catalogruntime.GenerationStamp) []string {
	if stamp == nil {
		return nil
	}
	return []string{
		stamp.SchemaVersion,
		stamp.GenerationID,
		strconv.FormatUint(stamp.ActivationEpoch, 10),
		stamp.PackageID,
		stamp.PackageChecksum,
		stamp.CatalogID,
		stamp.CatalogVersion,
		stamp.CatalogChecksum,
		stamp.SourceManifestID,
		stamp.CompiledAt.Format(time.RFC3339Nano),
		stamp.ActivatedAt.Format(time.RFC3339Nano),
	}
}

func matchEvidenceIdentity(evidence *MatchEvidence) []string {
	if evidence == nil {
		return nil
	}
	data, _ := json.Marshal(evidence)
	return []string{string(data)}
}

func diagnosticIdentity(diagnostic CandidateDiagnostic) string {
	data, _ := json.Marshal(diagnostic)
	return string(data)
}
