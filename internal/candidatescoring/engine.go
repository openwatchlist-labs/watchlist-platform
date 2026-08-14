package candidatescoring

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Engine evaluates candidate projections under one immutable policy.
type Engine struct {
	loaded LoadedPolicy
}

func NewEngine(policy LoadedPolicy) (*Engine, error) {
	if err := validatePolicy(policy.Policy); err != nil {
		return nil, err
	}
	if len(policy.SHA256) != 64 {
		return nil, errors.New("policy SHA256 must be a lowercase hexadecimal digest")
	}
	canonical, err := json.Marshal(policy.Policy)
	if err != nil {
		return nil, fmt.Errorf("marshal policy for checksum verification: %w", err)
	}
	digest := sha256.Sum256(canonical)
	if got := hex.EncodeToString(digest[:]); got != policy.SHA256 {
		return nil, errors.New("policy content does not match policy SHA256")
	}
	return &Engine{loaded: policy}, nil
}

func (e *Engine) PolicyReference() PolicyReference {
	return PolicyReference{
		PolicyID:             e.loaded.Policy.PolicyID,
		PolicyVersion:        e.loaded.Policy.PolicyVersion,
		PolicySHA256:         e.loaded.SHA256,
		NormalizationProfile: e.loaded.Policy.NormalizationProfile,
	}
}

func (e *Engine) Score(request Request) (Response, error) {
	if err := validateRequest(request, e.loaded.Policy); err != nil {
		return Response{}, err
	}
	digest, err := canonicalDigest(request)
	if err != nil {
		return Response{}, err
	}
	results := make([]CandidateResult, 0, len(request.Candidates))
	seen := map[string]struct{}{}
	for _, envelope := range request.Candidates {
		id := strings.TrimSpace(envelope.Candidate.CandidateID)
		if _, exists := seen[id]; exists {
			return Response{}, fmt.Errorf("duplicate candidate_id %q", id)
		}
		seen[id] = struct{}{}
		results = append(results, e.scoreCandidate(request.Subject, request.Lineage, envelope))
	}
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		if results[i].ExactIdentifierMatched != results[j].ExactIdentifierMatched {
			return results[i].ExactIdentifierMatched
		}
		if results[i].ExactNameMatched != results[j].ExactNameMatched {
			return results[i].ExactNameMatched
		}
		return results[i].CandidateID < results[j].CandidateID
	})
	return Response{
		SchemaVersion: ResponseSchemaV1,
		RequestID:     request.RequestID,
		RequestSHA256: digest,
		Field: ScreenedField{
			Path:            request.FieldPath,
			OriginalValue:   request.OriginalValue,
			NormalizedValue: request.NormalizedValue,
		},
		Policy:     e.PolicyReference(),
		Candidates: results,
	}, nil
}

func (e *Engine) ScoreBatch(batch BatchRequest) (BatchResponse, error) {
	if batch.SchemaVersion != BatchRequestSchemaV1 {
		return BatchResponse{}, fmt.Errorf("batch schema_version %q is not %q", batch.SchemaVersion, BatchRequestSchemaV1)
	}
	if strings.TrimSpace(batch.BatchID) == "" {
		return BatchResponse{}, errors.New("batch_id is required")
	}
	if len(batch.Items) == 0 {
		return BatchResponse{}, errors.New("batch items must not be empty")
	}
	digest, err := canonicalDigest(batch)
	if err != nil {
		return BatchResponse{}, err
	}
	items := make([]Response, 0, len(batch.Items))
	seen := map[string]struct{}{}
	for index, request := range batch.Items {
		if _, exists := seen[request.RequestID]; exists {
			return BatchResponse{}, fmt.Errorf("duplicate request_id %q at batch index %d", request.RequestID, index)
		}
		seen[request.RequestID] = struct{}{}
		response, err := e.Score(request)
		if err != nil {
			return BatchResponse{}, fmt.Errorf("score batch item %d: %w", index, err)
		}
		items = append(items, response)
	}
	return BatchResponse{
		SchemaVersion: BatchResponseSchemaV1,
		BatchID:       batch.BatchID,
		RequestSHA256: digest,
		Policy:        e.PolicyReference(),
		Items:         items,
	}, nil
}

func (e *Engine) scoreCandidate(subject Subject, lineage Lineage, envelope CandidateEnvelope) CandidateResult {
	candidate := envelope.Candidate
	components := make([]ScoreComponent, 0, 8)
	evidence := make([]EvidenceItem, 0, e.loaded.Policy.MaxEvidenceItems)
	reasons := make([]string, 0, 12)
	add := func(component string, points int, reason, kind, outcome, subjectValue, candidateValue string) {
		if points != 0 {
			components = append(components, ScoreComponent{Component: component, Points: points, ReasonCode: reason})
		}
		reasons = append(reasons, reason)
		if len(evidence) < e.loaded.Policy.MaxEvidenceItems {
			evidence = append(evidence, EvidenceItem{
				Kind: kind, Outcome: outcome, SubjectValue: subjectValue,
				CandidateValue: candidateValue, Points: points, ReasonCode: reason,
			})
		}
	}

	exactIdentifier, subjectIdentifier, candidateIdentifier := identifierMatch(subject.Identifiers, candidate.Identifiers)
	if exactIdentifier {
		add("typed_identifier", e.loaded.Policy.Weights.TypedIdentifierExact,
			"typed_identifier_exact", "identifier", "support",
			subjectIdentifier, candidateIdentifier)
	}

	nameShape, subjectName, candidateName := bestNameMatch(subject.Names, candidate.Names)
	exactName := nameShape == "exact"
	switch nameShape {
	case "exact":
		add("name", e.loaded.Policy.Weights.NameExact, "name_exact", "name", "support", subjectName, candidateName)
	case "concatenation_normalized":
		add("name", e.loaded.Policy.Weights.NameConcatenationNormalized, "name_concatenation_normalized", "name", "support", subjectName, candidateName)
	case "token_set":
		add("name", e.loaded.Policy.Weights.NameTokenSet, "name_token_set_exact", "name", "support", subjectName, candidateName)
	case "particle_stripped":
		add("name", e.loaded.Policy.Weights.NameParticleStripped, "name_particle_stripped", "name", "support", subjectName, candidateName)
	case "prefix":
		add("name", e.loaded.Policy.Weights.NamePrefix, "name_prefix", "name", "support", subjectName, candidateName)
	case "containment":
		add("name", e.loaded.Policy.Weights.NameContainment, "name_containment", "name", "support", subjectName, candidateName)
	}

	dobOutcome, subjectDOB, candidateDOB := dateMatch(subject.DatesOfBirth, candidate.DatesOfBirth)
	switch dobOutcome {
	case "exact":
		add("date_of_birth", e.loaded.Policy.Weights.DateOfBirthExact, "date_of_birth_exact", "date_of_birth", "support", subjectDOB, candidateDOB)
	case "year":
		add("date_of_birth", e.loaded.Policy.Weights.DateOfBirthYear, "date_of_birth_year_exact", "date_of_birth", "support", subjectDOB, candidateDOB)
	case "conflict":
		add("date_of_birth", e.loaded.Policy.Weights.DateOfBirthConflict, "date_of_birth_conflict", "date_of_birth", "contradiction", subjectDOB, candidateDOB)
	}

	countryOutcome, subjectCountry, candidateCountry := setMatch(subject.Countries, candidate.Countries, normalizeCountry)
	switch countryOutcome {
	case "exact":
		add("country", e.loaded.Policy.Weights.CountryExact, "country_exact", "country", "support", subjectCountry, candidateCountry)
	case "conflict":
		add("country", e.loaded.Policy.Weights.CountryConflict, "country_conflict", "country", "contradiction", subjectCountry, candidateCountry)
	}

	subjectEntityType := normalizeEntityType(subject.EntityType)
	candidateEntityType := normalizeEntityType(candidate.EntityType)
	if subjectEntityType != "" && candidateEntityType != "" {
		if subjectEntityType == candidateEntityType {
			add("entity_type", e.loaded.Policy.Weights.EntityTypeExact, "entity_type_exact", "entity_type", "support", subjectEntityType, candidateEntityType)
		} else {
			add("entity_type", e.loaded.Policy.Weights.EntityTypeConflict, "entity_type_conflict", "entity_type", "contradiction", subjectEntityType, candidateEntityType)
		}
	}

	for _, reason := range uniqueSorted(envelope.Retrieval.ReasonCodes, normalizeReasonCode) {
		reasons = append(reasons, "retrieval_"+reason)
	}

	score := 0
	for _, component := range components {
		score += component.Points
	}
	if score < e.loaded.Policy.ScoreFloor {
		score = e.loaded.Policy.ScoreFloor
	}
	if score > e.loaded.Policy.ScoreCeiling {
		score = e.loaded.Policy.ScoreCeiling
	}

	return CandidateResult{
		CandidateID:            candidate.CandidateID,
		Score:                  score,
		StrengthBand:           strengthBand(score, e.loaded.Policy),
		ExactIdentifierMatched: exactIdentifier,
		ExactNameMatched:       exactName,
		ReasonCodes:            uniqueSorted(reasons, normalizeReasonCode),
		Components:             components,
		Evidence:               evidence,
		Retrieval: RetrievalEvidence{
			Routes:      uniqueSorted(envelope.Retrieval.Routes, normalizeReasonCode),
			ReasonCodes: uniqueSorted(envelope.Retrieval.ReasonCodes, normalizeReasonCode),
		},
		Lineage: lineage,
	}
}

func validateRequest(request Request, policy Policy) error {
	if request.SchemaVersion != RequestSchemaV1 {
		return fmt.Errorf("request schema_version %q is not %q", request.SchemaVersion, RequestSchemaV1)
	}
	if strings.TrimSpace(request.RequestID) == "" {
		return errors.New("request_id is required")
	}
	if len(request.Candidates) == 0 {
		return errors.New("candidates must not be empty")
	}
	if len(request.Candidates) > 1000 {
		return errors.New("candidates exceeds the Phase 8C bound of 1000")
	}
	for index, envelope := range request.Candidates {
		if strings.TrimSpace(envelope.Candidate.CandidateID) == "" {
			return fmt.Errorf("candidate_id is required at index %d", index)
		}
	}
	if request.Lineage.Provider == "" || request.Lineage.CatalogID == "" ||
		request.Lineage.ComponentID == "" || request.Lineage.ComponentVersion == "" ||
		request.Lineage.ActivationID == "" || request.Lineage.NormalizationProfile == "" {
		return errors.New("complete catalog component/version activation lineage is required")
	}
	if request.Lineage.NormalizationProfile != policy.NormalizationProfile {
		return fmt.Errorf("lineage normalization_profile %q does not match policy %q", request.Lineage.NormalizationProfile, policy.NormalizationProfile)
	}
	return nil
}

func canonicalDigest(value any) (string, error) {
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal canonical request: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func DecodeRequest(raw []byte) (Request, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var request Request
	if err := dec.Decode(&request); err != nil {
		return Request{}, fmt.Errorf("decode request: %w", err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return Request{}, fmt.Errorf("decode request: %w", err)
	}
	return request, nil
}

func DecodeBatchRequest(raw []byte) (BatchRequest, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var request BatchRequest
	if err := dec.Decode(&request); err != nil {
		return BatchRequest{}, fmt.Errorf("decode batch request: %w", err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return BatchRequest{}, fmt.Errorf("decode batch request: %w", err)
	}
	return request, nil
}

func requireJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func identifierMatch(subject, candidate []Identifier) (bool, string, string) {
	type pair struct{ typ, value string }
	candidateSet := map[pair]struct{}{}
	candidateDisplay := map[pair]string{}
	for _, identifier := range candidate {
		key := pair{normalizeIdentifierType(identifier.Type), normalizeIdentifierValue(identifier.Value)}
		if key.typ != "" && key.value != "" {
			candidateSet[key] = struct{}{}
			candidateDisplay[key] = key.typ + ":" + key.value
		}
	}
	matches := make([]pair, 0)
	for _, identifier := range subject {
		key := pair{normalizeIdentifierType(identifier.Type), normalizeIdentifierValue(identifier.Value)}
		if _, ok := candidateSet[key]; ok {
			matches = append(matches, key)
		}
	}
	if len(matches) == 0 {
		return false, "", ""
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].typ != matches[j].typ {
			return matches[i].typ < matches[j].typ
		}
		return matches[i].value < matches[j].value
	})
	selected := matches[0]
	display := selected.typ + ":" + selected.value
	return true, display, candidateDisplay[selected]
}

func bestNameMatch(subject, candidate []string) (string, string, string) {
	type match struct {
		rank                      int
		shape, subject, candidate string
	}
	matches := make([]match, 0)
	for _, rawSubject := range subject {
		ns := normalizeText(rawSubject)
		if ns == "" {
			continue
		}
		for _, rawCandidate := range candidate {
			nc := normalizeText(rawCandidate)
			if nc == "" {
				continue
			}
			switch {
			case ns == nc:
				matches = append(matches, match{6, "exact", ns, nc})
			case equalSpacesStripped(ns, nc):
				matches = append(matches, match{5, "concatenation_normalized", ns, nc})
			case equalTokenSet(ns, nc):
				matches = append(matches, match{4, "token_set", ns, nc})
			case equalParticleStrippedTokenSet(ns, nc):
				matches = append(matches, match{3, "particle_stripped", ns, nc})
			case strings.HasPrefix(ns, nc) || strings.HasPrefix(nc, ns):
				matches = append(matches, match{2, "prefix", ns, nc})
			case strings.Contains(ns, nc) || strings.Contains(nc, ns):
				matches = append(matches, match{1, "containment", ns, nc})
			}
		}
	}
	if len(matches) == 0 {
		return "", "", ""
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].rank != matches[j].rank {
			return matches[i].rank > matches[j].rank
		}
		if matches[i].subject != matches[j].subject {
			return matches[i].subject < matches[j].subject
		}
		return matches[i].candidate < matches[j].candidate
	})
	return matches[0].shape, matches[0].subject, matches[0].candidate
}

func dateMatch(subject, candidate []string) (string, string, string) {
	s := uniqueSorted(subject, normalizeDate)
	c := uniqueSorted(candidate, normalizeDate)
	if len(s) == 0 || len(c) == 0 {
		return "", "", ""
	}
	for _, sv := range s {
		for _, cv := range c {
			if sv == cv {
				return "exact", sv, cv
			}
		}
	}
	for _, sv := range s {
		for _, cv := range c {
			if len(sv) >= 4 && len(cv) >= 4 && sv[:4] == cv[:4] {
				return "year", sv, cv
			}
		}
	}
	return "conflict", s[0], c[0]
}

func normalizeDate(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 4 {
		return value
	}
	return ""
}

func setMatch(subject, candidate []string, normalizer func(string) string) (string, string, string) {
	s := uniqueSorted(subject, normalizer)
	c := uniqueSorted(candidate, normalizer)
	if len(s) == 0 || len(c) == 0 {
		return "", "", ""
	}
	candidateSet := map[string]struct{}{}
	for _, value := range c {
		candidateSet[value] = struct{}{}
	}
	for _, value := range s {
		if _, ok := candidateSet[value]; ok {
			return "exact", value, value
		}
	}
	return "conflict", s[0], c[0]
}

func normalizeReasonCode(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastUnderscore := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastUnderscore = false
		} else if !lastUnderscore && b.Len() > 0 {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.Trim(b.String(), "_")
}

func strengthBand(score int, policy Policy) string {
	switch {
	case score >= policy.Thresholds.StrongCandidate:
		return "strong_candidate"
	case score >= policy.Thresholds.ReviewCandidate:
		return "review_candidate"
	case score >= policy.Thresholds.WeakCandidate:
		return "weak_candidate"
	default:
		return "no_candidate_support"
	}
}
