package activationpromotion

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

type candidateScore struct {
	ID    string
	Score int
}

type screeningResult struct {
	Candidates []candidateScore
	Blockers   int
}

func CompareResponses(intentID, correlationID string, currentRaw, candidateRaw []byte, observedAt string) (ShadowObservation, error) {
	current, err := extractScreeningResults(currentRaw)
	if err != nil {
		return ShadowObservation{}, fmt.Errorf("decode current response: %w", err)
	}
	candidate, err := extractScreeningResults(candidateRaw)
	if err != nil {
		return ShadowObservation{}, fmt.Errorf("decode candidate response: %w", err)
	}
	if len(current) != len(candidate) {
		return ShadowObservation{}, errors.New("current and candidate responses contain different screening item counts")
	}
	observation := ShadowObservation{
		SchemaVersion:           ShadowSchemaV1,
		IntentID:                intentID,
		CorrelationID:           correlationID,
		ObservedAt:              observedAt,
		CurrentResponseSHA256:   shaHex(currentRaw),
		CandidateResponseSHA256: shaHex(candidateRaw),
		ScreeningItems:          len(current),
	}
	for index := range current {
		left, right := current[index], candidate[index]
		if !sameCandidateSet(left.Candidates, right.Candidates) {
			observation.CandidateSetChanges++
		}
		if topID(left.Candidates) != topID(right.Candidates) {
			observation.TopCandidateChanges++
		}
		leftScores := scoreMap(left.Candidates)
		rightScores := scoreMap(right.Candidates)
		for id, score := range leftScores {
			other, ok := rightScores[id]
			if !ok {
				observation.CoverageLossCount++
				continue
			}
			delta := score - other
			if delta < 0 {
				delta = -delta
			}
			if delta > observation.MaxAbsoluteScoreDelta {
				observation.MaxAbsoluteScoreDelta = delta
			}
		}
		if right.Blockers > left.Blockers {
			observation.AdditionalBlockerCount += right.Blockers - left.Blockers
		}
	}
	raw, _ := canonical(observation)
	observation.ObservationSHA256 = shaHex(raw)
	return observation, nil
}

func (m *Manager) RecordObservation(observation ShadowObservation) error {
	unlock, err := m.lock()
	if err != nil {
		return err
	}
	defer unlock()
	intent, state, err := m.intentAndState()
	if err != nil {
		return err
	}
	if observation.IntentID != intent.IntentID || (state.Phase != PhasePrepared && state.Phase != PhaseValidated && state.Phase != PhaseCanary) {
		return errors.New("shadow observation does not match an active pre-promotion phase")
	}
	if err := verifyObservation(observation); err != nil {
		return err
	}
	return m.writeImmutable(m.observationPath(intent.IntentID, observation.ObservationSHA256), observation)
}

func (m *Manager) SummarizeObservations(intentID string) (ShadowSummary, error) {
	unlock, err := m.lock()
	if err != nil {
		return ShadowSummary{}, err
	}
	defer unlock()
	intent, _, err := m.intentAndState()
	if err != nil {
		return ShadowSummary{}, err
	}
	if intentID != intent.IntentID {
		return ShadowSummary{}, errors.New("intent_id does not match active promotion")
	}
	paths, err := filepath.Glob(filepath.Join(m.directory, "observations", intentID, "*.json"))
	if err != nil {
		return ShadowSummary{}, err
	}
	sort.Strings(paths)
	summary := ShadowSummary{SchemaVersion: ShadowSummaryV1, IntentID: intentID, GeneratedAt: m.timestamp()}
	for _, path := range paths {
		var observation ShadowObservation
		if err := decodeStrictFile(path, &observation); err != nil {
			return ShadowSummary{}, err
		}
		if err := verifyObservation(observation); err != nil {
			return ShadowSummary{}, err
		}
		summary.ObservationCount++
		summary.ScreeningItems += observation.ScreeningItems
		summary.CandidateSetChanges += observation.CandidateSetChanges
		summary.TopCandidateChanges += observation.TopCandidateChanges
		summary.CoverageLossCount += observation.CoverageLossCount
		summary.AdditionalBlockerCount += observation.AdditionalBlockerCount
		if observation.MaxAbsoluteScoreDelta > summary.MaxAbsoluteScoreDelta {
			summary.MaxAbsoluteScoreDelta = observation.MaxAbsoluteScoreDelta
		}
	}
	if summary.ScreeningItems > 0 {
		summary.CandidateSetChangeBPS = summary.CandidateSetChanges * 10000 / summary.ScreeningItems
		summary.TopCandidateChangeBPS = summary.TopCandidateChanges * 10000 / summary.ScreeningItems
	}
	raw, _ := canonical(summary)
	summary.SummarySHA256 = shaHex(raw)
	return summary, nil
}

func (m *Manager) Route(correlationID string) (string, Status, error) {
	status, err := m.Status()
	if err != nil {
		return "", Status{}, err
	}
	switch status.State.Phase {
	case PhasePromoted:
		return "candidate", status, nil
	case PhaseCanary:
		for _, allowed := range status.Intent.CanaryCorrelationAllowlist {
			if correlationID == allowed {
				return "candidate", status, nil
			}
		}
		digest := sha256.Sum256([]byte(correlationID))
		bucket := int(binary.BigEndian.Uint64(digest[:8]) % 10000)
		if bucket < status.Intent.CanaryBasisPoints {
			return "candidate", status, nil
		}
		return "current", status, nil
	case PhasePrepared, PhaseValidated, PhaseBlocked, PhaseRolledBack:
		return "current", status, nil
	default:
		return "", Status{}, fmt.Errorf("unsupported promotion phase %q", status.State.Phase)
	}
}

func verifyObservation(observation ShadowObservation) error {
	if observation.SchemaVersion != ShadowSchemaV1 || observation.IntentID == "" || observation.ObservationSHA256 == "" || observation.ScreeningItems < 0 {
		return errors.New("invalid shadow observation")
	}
	expected := observation.ObservationSHA256
	observation.ObservationSHA256 = ""
	raw, _ := canonical(observation)
	if shaHex(raw) != expected {
		return errors.New("shadow observation checksum mismatch")
	}
	return nil
}

func verifySummary(summary ShadowSummary) error {
	if summary.SchemaVersion != ShadowSummaryV1 || summary.IntentID == "" || summary.SummarySHA256 == "" || summary.ScreeningItems < 1 {
		return errors.New("invalid shadow summary")
	}
	expected := summary.SummarySHA256
	summary.SummarySHA256 = ""
	raw, _ := canonical(summary)
	if shaHex(raw) != expected {
		return errors.New("shadow summary checksum mismatch")
	}
	return nil
}

func extractScreeningResults(raw []byte) ([]screeningResult, error) {
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	if items, ok := document["items"].([]any); ok {
		results := make([]screeningResult, 0, len(items))
		for _, item := range items {
			object, ok := item.(map[string]any)
			if !ok {
				return nil, errors.New("batch item is not an object")
			}
			response, ok := object["response"].(map[string]any)
			if !ok {
				return nil, errors.New("batch item response is missing")
			}
			results = append(results, extractOne(response))
		}
		return results, nil
	}
	return []screeningResult{extractOne(document)}, nil
}

func extractOne(document map[string]any) screeningResult {
	result := screeningResult{}
	if blockers, ok := document["blockers"].([]any); ok {
		result.Blockers = len(blockers)
	}
	candidates, _ := document["candidates"].([]any)
	for _, value := range candidates {
		candidate, ok := value.(map[string]any)
		if !ok {
			continue
		}
		id, _ := candidate["candidate_id"].(string)
		scoreValue, _ := candidate["score"].(float64)
		if strings.TrimSpace(id) != "" {
			result.Candidates = append(result.Candidates, candidateScore{ID: id, Score: int(scoreValue)})
		}
	}
	return result
}

func sameCandidateSet(left, right []candidateScore) bool {
	leftIDs, rightIDs := make([]string, len(left)), make([]string, len(right))
	for i := range left {
		leftIDs[i] = left[i].ID
	}
	for i := range right {
		rightIDs[i] = right[i].ID
	}
	sort.Strings(leftIDs)
	sort.Strings(rightIDs)
	return strings.Join(leftIDs, "\x00") == strings.Join(rightIDs, "\x00")
}

func topID(values []candidateScore) string {
	if len(values) == 0 {
		return ""
	}
	return values[0].ID
}

func scoreMap(values []candidateScore) map[string]int {
	result := make(map[string]int, len(values))
	for _, value := range values {
		result[value.ID] = value.Score
	}
	return result
}

func (m *Manager) observationPath(intentID, sha string) string {
	return filepath.Join(m.directory, "observations", intentID, sha+".json")
}
