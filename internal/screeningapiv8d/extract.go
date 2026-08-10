package screeningapiv8d

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/candidatescoring"
)

type extractedRequest struct {
	RequestID       string
	FieldPath       string
	OriginalValue   string
	NormalizedValue string
	Subject         candidatescoring.Subject
}

type retrievedCandidate struct {
	CandidateID string
	Retrieval   candidatescoring.RetrievalEvidence
}

type extractedUpstream struct {
	Status     string
	Blockers   []Blocker
	Lineage    Lineage
	Candidates []retrievedCandidate
}

func extractSingleRequest(raw []byte) (extractedRequest, error) {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return extractedRequest{}, fmt.Errorf("decode screening request: %w", err)
	}
	return extractRequestMap(root), nil
}

func extractRequestMap(root map[string]any) extractedRequest {
	subjectMap := objectValue(root, "subject", "screening_subject", "party")
	if subjectMap == nil {
		subjectMap = root
	}
	field := objectValue(root, "field", "screened_field")
	request := extractedRequest{
		RequestID:       stringValue(root, "request_id", "screening_id", "id"),
		FieldPath:       firstNonEmpty(stringValue(root, "field_path"), stringValue(field, "path")),
		OriginalValue:   firstNonEmpty(stringValue(root, "original_value"), stringValue(field, "original_value"), stringValue(subjectMap, "name")),
		NormalizedValue: firstNonEmpty(stringValue(root, "normalized_value"), stringValue(field, "normalized_value")),
		Subject: candidatescoring.Subject{
			Names:        stringSlice(subjectMap, "names", "aliases"),
			Countries:    stringSlice(subjectMap, "countries", "country_codes", "nationalities"),
			DatesOfBirth: stringSlice(subjectMap, "dates_of_birth", "date_of_birth", "birth_dates"),
			EntityType:   stringValue(subjectMap, "entity_type", "type"),
			Identifiers:  identifierSlice(subjectMap),
		},
	}
	if len(request.Subject.Names) == 0 {
		if name := stringValue(subjectMap, "name", "full_name", "legal_name"); name != "" {
			request.Subject.Names = []string{name}
		}
	}
	return request
}

func extractUpstreamSingle(raw []byte, fallback Lineage) (extractedUpstream, error) {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return extractedUpstream{}, fmt.Errorf("decode Phase 8B response: %w", err)
	}
	return extractUpstreamMap(root, fallback), nil
}

func extractUpstreamBatch(raw []byte, fallback Lineage) ([]extractedUpstream, error) {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("decode Phase 8B batch response: %w", err)
	}
	items := arrayValue(root, "items", "results", "screenings")
	out := make([]extractedUpstream, 0, len(items))
	for index, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("phase 8B batch item %d is not an object", index)
		}
		if nested := objectValue(object, "response", "result"); nested != nil {
			object = nested
		}
		out = append(out, extractUpstreamMap(object, fallback))
	}
	return out, nil
}

func extractUpstreamMap(root map[string]any, fallback Lineage) extractedUpstream {
	lineageMap := objectValue(root, "lineage", "catalog_lineage", "runtime_binding")
	lineage := fallback
	assignIfPresent(&lineage.Provider, stringValue(lineageMap, "provider", "provider_id"))
	assignIfPresent(&lineage.CatalogID, stringValue(lineageMap, "catalog_id"))
	assignIfPresent(&lineage.ComponentID, stringValue(lineageMap, "component_id"))
	assignIfPresent(&lineage.ComponentVersion, stringValue(lineageMap, "component_version", "version"))
	assignIfPresent(&lineage.ActivationID, stringValue(lineageMap, "activation_id"))
	assignIfPresent(&lineage.NormalizationProfile, stringValue(lineageMap, "normalization_profile"))

	blockers := make([]Blocker, 0)
	for _, item := range arrayValue(root, "blockers", "errors") {
		switch value := item.(type) {
		case string:
			blockers = append(blockers, Blocker{Code: value})
		case map[string]any:
			blockers = append(blockers, Blocker{Code: stringValue(value, "code", "reason_code", "type"), Detail: stringValue(value, "detail", "message")})
		}
	}

	candidates := make([]retrievedCandidate, 0)
	for _, item := range arrayValue(root, "candidates", "matches", "results") {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		candidateMap := objectValue(object, "candidate", "record")
		if candidateMap == nil {
			candidateMap = object
		}
		id := stringValue(candidateMap, "candidate_id", "record_id", "id")
		if id == "" {
			id = stringValue(object, "candidate_id", "record_id", "id")
		}
		retrievalMap := objectValue(object, "retrieval", "retrieval_evidence")
		candidates = append(candidates, retrievedCandidate{
			CandidateID: id,
			Retrieval: candidatescoring.RetrievalEvidence{
				Routes:      stringSlice(retrievalMap, "routes", "route"),
				ReasonCodes: stringSlice(retrievalMap, "reason_codes", "reasons"),
			},
		})
	}
	return extractedUpstream{
		Status:     firstNonEmpty(stringValue(root, "status"), "ok"),
		Blockers:   blockers,
		Lineage:    lineage,
		Candidates: candidates,
	}
}

func objectValue(root map[string]any, keys ...string) map[string]any {
	if root == nil {
		return nil
	}
	for _, key := range keys {
		if value, ok := root[key].(map[string]any); ok {
			return value
		}
	}
	return nil
}

func arrayValue(root map[string]any, keys ...string) []any {
	if root == nil {
		return nil
	}
	for _, key := range keys {
		if value, ok := root[key].([]any); ok {
			return value
		}
	}
	return nil
}

func stringValue(root map[string]any, keys ...string) string {
	if root == nil {
		return ""
	}
	for _, key := range keys {
		value, ok := root[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return strings.TrimSpace(typed)
			}
		case json.Number:
			return typed.String()
		case float64:
			return strconv.FormatFloat(typed, 'f', -1, 64)
		}
	}
	return ""
}

func stringSlice(root map[string]any, keys ...string) []string {
	if root == nil {
		return nil
	}
	for _, key := range keys {
		value, ok := root[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return []string{strings.TrimSpace(typed)}
			}
		case []any:
			out := make([]string, 0, len(typed))
			for _, item := range typed {
				if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
					out = append(out, strings.TrimSpace(text))
				}
			}
			return out
		}
	}
	return nil
}

func identifierSlice(root map[string]any) []candidatescoring.Identifier {
	items := arrayValue(root, "identifiers", "typed_identifiers")
	out := make([]candidatescoring.Identifier, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		identifier := candidatescoring.Identifier{Type: stringValue(object, "type", "identifier_type"), Value: stringValue(object, "value", "identifier_value")}
		if identifier.Type != "" && identifier.Value != "" {
			out = append(out, identifier)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func assignIfPresent(target *string, value string) {
	if value != "" {
		*target = value
	}
}
