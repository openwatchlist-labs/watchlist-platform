package rag

import (
	"fmt"
	"sort"
	"time"
)

func ValidateManifest(manifest CorpusManifest) error {
	if manifest.SchemaVersion != CorpusManifestSchema {
		return fmt.Errorf("manifest schema must be %q", CorpusManifestSchema)
	}
	if manifest.CorpusID == "" || manifest.CorpusVersion == "" || manifest.SnapshotAt == "" || manifest.CorpusChecksum == "" {
		return fmt.Errorf("manifest identifiers, snapshot_at, and checksum are required")
	}
	if _, err := time.Parse(time.RFC3339, manifest.SnapshotAt); err != nil {
		return fmt.Errorf("snapshot_at: %w", err)
	}
	if len(manifest.Documents) == 0 {
		return fmt.Errorf("documents are required")
	}
	seen := map[string]struct{}{}
	for i, doc := range manifest.Documents {
		if doc.SourceID == "" || doc.Path == "" || doc.Title == "" || doc.Publisher == "" || doc.DocumentType == "" || doc.ApprovalStatus == "" || len(doc.AccessScope) == 0 {
			return fmt.Errorf("documents[%d] missing required metadata", i)
		}
		if _, ok := seen[doc.SourceID]; ok {
			return fmt.Errorf("duplicate source_id %q", doc.SourceID)
		}
		seen[doc.SourceID] = struct{}{}
		if !validTier(doc.SourceTier) {
			return fmt.Errorf("documents[%d] invalid source tier", i)
		}
	}
	if expected := ManifestChecksum(manifest); manifest.CorpusChecksum != expected {
		return fmt.Errorf("corpus_checksum=%q expected %q", manifest.CorpusChecksum, expected)
	}
	return nil
}

func ValidateSnapshot(snapshot CorpusSnapshot) error {
	if snapshot.SchemaVersion != CorpusSnapshotSchema || snapshot.SnapshotID == "" || snapshot.CorpusID == "" || snapshot.CorpusVersion == "" || snapshot.CorpusChecksum == "" {
		return fmt.Errorf("invalid corpus snapshot metadata")
	}
	if len(snapshot.Documents) == 0 {
		return fmt.Errorf("snapshot documents are required")
	}
	for i, doc := range snapshot.Documents {
		if doc.ContentChecksum == "" || len(doc.Chunks) == 0 {
			return fmt.Errorf("documents[%d] missing checksum or chunks", i)
		}
		for j, chunk := range doc.Chunks {
			if chunk.ChunkID == "" || chunk.SourceID != doc.Spec.SourceID || chunk.Locator == "" || chunk.Text == "" || chunk.ContentChecksum == "" || len(chunk.Tokens) == 0 {
				return fmt.Errorf("documents[%d].chunks[%d] invalid", i, j)
			}
		}
	}
	if expected := stableSnapshotID(snapshot); snapshot.SnapshotID != expected {
		return fmt.Errorf("snapshot_id=%q expected %q", snapshot.SnapshotID, expected)
	}
	return nil
}

func ValidatePolicy(policy RetrievalPolicy) error {
	if policy.SchemaVersion != RetrievalPolicySchema || policy.PolicyID == "" || policy.PolicyVersion == "" || policy.PolicyChecksum == "" {
		return fmt.Errorf("invalid retrieval policy metadata")
	}
	if len(policy.AllowedSourceTiers) == 0 || len(policy.AllowedApprovalStatuses) == 0 {
		return fmt.Errorf("allowed tiers and approval statuses are required")
	}
	if policy.MaxResults < 1 || policy.MaxResults > 50 || policy.MinimumScoreBasisPoints < 0 || policy.MinimumScoreBasisPoints > 10000 {
		return fmt.Errorf("invalid retrieval result limits")
	}
	weights := policy.MetadataWeightBasisPoints + policy.LexicalWeightBasisPoints + policy.VectorWeightBasisPoints
	if weights != 10000 {
		return fmt.Errorf("retrieval weights must sum to 10000")
	}
	if expected := PolicyChecksum(policy); policy.PolicyChecksum != expected {
		return fmt.Errorf("policy_checksum=%q expected %q", policy.PolicyChecksum, expected)
	}
	return nil
}

func ValidateQuery(query RetrievalQuery) error {
	if query.SchemaVersion != RetrievalQuerySchema || query.QueryID == "" || query.Task == "" || query.TenantID == "" || query.Scope == "" || query.DecisionID == "" || query.Disposition == "" || query.ReviewRoute == "" || query.MessageType == "" || query.SemanticRole == "" || query.PolicyID == "" || query.EffectiveAt == "" {
		return fmt.Errorf("invalid retrieval query metadata")
	}
	if len(query.ReasonCodes) == 0 {
		return fmt.Errorf("reason_codes are required")
	}
	if _, err := time.Parse(time.RFC3339, query.EffectiveAt); err != nil {
		return fmt.Errorf("effective_at: %w", err)
	}
	if expected := stableQueryID(query); query.QueryID != expected {
		return fmt.Errorf("query_id=%q expected %q", query.QueryID, expected)
	}
	return nil
}

func ValidateCitationPackage(pkg CitationPackage) error {
	if pkg.SchemaVersion != CitationPackageSchema || pkg.CitationPackageID == "" || pkg.RetrieverVersion != RetrieverVersion || pkg.CorpusSnapshotID == "" {
		return fmt.Errorf("invalid citation package metadata")
	}
	if err := ValidateQuery(pkg.Query); err != nil {
		return err
	}
	if len(pkg.Citations) == 0 {
		return fmt.Errorf("citations are required")
	}
	seen := map[string]struct{}{}
	for i, citation := range pkg.Citations {
		if citation.CitationID == "" || citation.SourceID == "" || citation.Title == "" || citation.Publisher == "" || citation.Locator == "" || citation.Excerpt == "" || citation.ContentChecksum == "" || citation.CorpusSnapshotID != pkg.CorpusSnapshotID || len(citation.RetrievalMethods) == 0 {
			return fmt.Errorf("citations[%d] invalid", i)
		}
		if _, ok := seen[citation.CitationID]; ok {
			return fmt.Errorf("duplicate citation_id %q", citation.CitationID)
		}
		seen[citation.CitationID] = struct{}{}
		if expected := stableCitationID(citation); citation.CitationID != expected {
			return fmt.Errorf("citations[%d] citation ID mismatch", i)
		}
	}
	if pkg.Summary.CitationsReturned != len(pkg.Citations) {
		return fmt.Errorf("citation summary mismatch")
	}
	if expected := stableCitationPackageID(pkg); pkg.CitationPackageID != expected {
		return fmt.Errorf("citation_package_id=%q expected %q", pkg.CitationPackageID, expected)
	}
	return nil
}

func validTier(tier SourceTier) bool {
	return tier == TierA || tier == TierB || tier == TierC || tier == TierD
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsTier(values []SourceTier, target SourceTier) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
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
