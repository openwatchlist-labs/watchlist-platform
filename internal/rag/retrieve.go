package rag

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"time"
)

type Retriever struct {
	snapshot CorpusSnapshot
	policy   RetrievalPolicy
}

func NewRetriever(snapshot CorpusSnapshot, policy RetrievalPolicy) (*Retriever, error) {
	if err := ValidateSnapshot(snapshot); err != nil {
		return nil, err
	}
	if err := ValidatePolicy(policy); err != nil {
		return nil, err
	}
	return &Retriever{snapshot: snapshot, policy: policy}, nil
}

func (r *Retriever) Retrieve(query RetrievalQuery) (CitationPackage, error) {
	if query.QueryID == "" {
		query.QueryID = stableQueryID(query)
	}
	if err := ValidateQuery(query); err != nil {
		return CitationPackage{}, err
	}
	queryTokens := tokenize(strings.Join(append(append(append([]string{}, query.ReasonCodes...), query.Blockers...), query.RequiredEvidence...), " ") + " " + query.Task + " " + query.Disposition + " " + query.ReviewRoute + " " + query.MessageType + " " + query.SemanticRole + " " + query.PolicyID + " " + query.QueryText)
	if len(queryTokens) == 0 {
		return CitationPackage{}, fmt.Errorf("retrieval query produced no tokens")
	}
	effectiveAt, _ := time.Parse(time.RFC3339, query.EffectiveAt)
	candidates := []Citation{}
	summary := RetrievalSummary{}
	for _, document := range r.snapshot.Documents {
		summary.DocumentsConsidered++
		if !r.documentAllowed(document.Spec, query, effectiveAt, &summary) {
			continue
		}
		for _, chunk := range document.Chunks {
			summary.ChunksConsidered++
			if chunk.InstructionLike && r.policy.ExcludeInstructionLikeText {
				summary.ExcludedInstructionLikeChunks++
				continue
			}
			score := r.score(query, queryTokens, document.Spec, chunk)
			if score.TotalBasisPoints < r.policy.MinimumScoreBasisPoints {
				summary.ExcludedBelowMinimumScore++
				continue
			}
			methods := []string{}
			if score.MetadataBasisPoints > 0 {
				methods = append(methods, "metadata")
			}
			if score.LexicalBasisPoints > 0 {
				methods = append(methods, "lexical")
			}
			if score.VectorBasisPoints > 0 {
				methods = append(methods, "vector")
			}
			citation := Citation{
				SourceID:         document.Spec.SourceID,
				SourceTier:       document.Spec.SourceTier,
				Title:            document.Spec.Title,
				Publisher:        document.Spec.Publisher,
				DocumentType:     document.Spec.DocumentType,
				Jurisdiction:     document.Spec.Jurisdiction,
				EffectiveFrom:    document.Spec.EffectiveFrom,
				EffectiveTo:      document.Spec.EffectiveTo,
				ApprovalStatus:   document.Spec.ApprovalStatus,
				TenantID:         document.Spec.TenantID,
				Locator:          chunk.Locator,
				Excerpt:          chunk.Text,
				ContentChecksum:  chunk.ContentChecksum,
				CorpusSnapshotID: r.snapshot.SnapshotID,
				RetrievalMethods: methods,
				Score:            score,
			}
			citation.CitationID = stableCitationID(citation)
			candidates = append(candidates, citation)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Score.TotalBasisPoints != candidates[j].Score.TotalBasisPoints {
			return candidates[i].Score.TotalBasisPoints > candidates[j].Score.TotalBasisPoints
		}
		return candidates[i].CitationID < candidates[j].CitationID
	})
	if len(candidates) > r.policy.MaxResults {
		candidates = candidates[:r.policy.MaxResults]
	}
	if len(candidates) == 0 {
		return CitationPackage{}, fmt.Errorf("no citations satisfied retrieval policy")
	}
	summary.CitationsReturned = len(candidates)
	pkg := CitationPackage{
		SchemaVersion:    CitationPackageSchema,
		Query:            query,
		RetrieverVersion: RetrieverVersion,
		RetrievalPolicy:  RetrievalPolicyReference{PolicyID: r.policy.PolicyID, PolicyVersion: r.policy.PolicyVersion, PolicyChecksum: r.policy.PolicyChecksum},
		CorpusSnapshotID: r.snapshot.SnapshotID,
		Summary:          summary,
		Citations:        candidates,
	}
	pkg.CitationPackageID = stableCitationPackageID(pkg)
	if err := ValidateCitationPackage(pkg); err != nil {
		return CitationPackage{}, err
	}
	return pkg, nil
}

func (r *Retriever) documentAllowed(spec DocumentSpec, query RetrievalQuery, effectiveAt time.Time, summary *RetrievalSummary) bool {
	if !containsTier(r.policy.AllowedSourceTiers, spec.SourceTier) || !containsString(r.policy.AllowedApprovalStatuses, spec.ApprovalStatus) {
		summary.ExcludedUnapprovedOrIneffective++
		return false
	}
	if spec.TenantID != "" && spec.TenantID != query.TenantID {
		summary.ExcludedTenantOrScope++
		return false
	}
	if !containsString(spec.AccessScope, query.Scope) {
		summary.ExcludedTenantOrScope++
		return false
	}
	if spec.EffectiveFrom != "" {
		value, err := time.Parse("2006-01-02", spec.EffectiveFrom)
		if err != nil || effectiveAt.Before(value) {
			summary.ExcludedUnapprovedOrIneffective++
			return false
		}
	}
	if spec.EffectiveTo != "" {
		value, err := time.Parse("2006-01-02", spec.EffectiveTo)
		if err != nil || effectiveAt.After(value.Add(24*time.Hour-time.Nanosecond)) {
			summary.ExcludedUnapprovedOrIneffective++
			return false
		}
	}
	return true
}

func (r *Retriever) score(query RetrievalQuery, queryTokens []string, spec DocumentSpec, chunk Chunk) RetrievalScore {
	metadata := 0
	metadataText := normalizeText(spec.DocumentType + " " + spec.Jurisdiction + " " + strings.Join(chunk.HeadingPath, " "))
	for _, value := range append(append(append([]string{}, query.ReasonCodes...), query.Blockers...), query.RequiredEvidence...) {
		if strings.Contains(metadataText+" "+normalizeText(chunk.Text), normalizeText(value)) {
			metadata += 1500
		}
	}
	if strings.Contains(metadataText+" "+normalizeText(chunk.Text), normalizeText(query.PolicyID)) {
		metadata += 2000
	}
	if strings.Contains(metadataText, normalizeText(query.SemanticRole)) || strings.Contains(normalizeText(chunk.Text), normalizeText(query.SemanticRole)) {
		metadata += 1500
	}
	if metadata > 10000 {
		metadata = 10000
	}
	lexical := overlapBasisPoints(queryTokens, chunk.Tokens)
	vector := hashedVectorSimilarity(queryTokens, chunk.Tokens)
	total := metadata*r.policy.MetadataWeightBasisPoints/10000 + lexical*r.policy.LexicalWeightBasisPoints/10000 + vector*r.policy.VectorWeightBasisPoints/10000
	return RetrievalScore{MetadataBasisPoints: metadata, LexicalBasisPoints: lexical, VectorBasisPoints: vector, TotalBasisPoints: total}
}

func overlapBasisPoints(query, document []string) int {
	if len(query) == 0 || len(document) == 0 {
		return 0
	}
	set := map[string]struct{}{}
	for _, token := range document {
		set[token] = struct{}{}
	}
	matches := 0
	for _, token := range query {
		if _, ok := set[token]; ok {
			matches++
		}
	}
	return matches * 10000 / len(query)
}

func hashedVectorSimilarity(a, b []string) int {
	const buckets = 64
	av := [buckets]int{}
	bv := [buckets]int{}
	for _, token := range a {
		av[hashBucket(token, buckets)]++
	}
	for _, token := range b {
		bv[hashBucket(token, buckets)]++
	}
	dot, asq, bsq := 0, 0, 0
	for i := 0; i < buckets; i++ {
		dot += av[i] * bv[i]
		asq += av[i] * av[i]
		bsq += bv[i] * bv[i]
	}
	if asq == 0 || bsq == 0 {
		return 0
	}
	// Integer Dice-like normalization avoids floating-point replay drift.
	return 2 * dot * 10000 / (asq + bsq)
}

func hashBucket(value string, buckets uint32) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(value))
	return h.Sum32() % buckets
}
