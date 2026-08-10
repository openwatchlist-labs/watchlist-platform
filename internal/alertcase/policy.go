package alertcase

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

type screeningLedgerEvent struct {
	SchemaVersion          string          `json:"schema_version"`
	EventID                string          `json:"event_id"`
	LedgerID               string          `json:"ledger_id"`
	Sequence               uint64          `json:"sequence"`
	PreviousEventSHA256    string          `json:"previous_event_sha256"`
	EventSHA256            string          `json:"event_sha256"`
	OccurredAt             string          `json:"occurred_at"`
	Route                  string          `json:"route"`
	HTTPStatus             int             `json:"http_status"`
	CorrelationIDHash      string          `json:"correlation_id_hash"`
	IdempotencyKeyHash     string          `json:"idempotency_key_hash,omitempty"`
	RequestSHA256          string          `json:"request_sha256"`
	ResponseSHA256         string          `json:"response_sha256"`
	RequestSnapshotSHA256  string          `json:"request_snapshot_sha256"`
	ResponseSnapshotSHA256 string          `json:"response_snapshot_sha256"`
	ActivationLineage      json.RawMessage `json:"activation_lineage,omitempty"`
	PromotionLineage       json.RawMessage `json:"promotion_lineage,omitempty"`
	CandidateSummary       json.RawMessage `json:"candidate_summary,omitempty"`
	RetentionClass         string          `json:"retention_class"`
	ExpiresAt              string          `json:"expires_at"`
}

type boundedCandidateSummary struct {
	Blockers   []string `json:"blockers"`
	Candidates []struct {
		CandidateID string   `json:"candidate_id"`
		Score       int      `json:"score"`
		Band        string   `json:"band,omitempty"`
		ReasonCodes []string `json:"reason_codes"`
	} `json:"candidates"`
}

func LoadPolicy(path string) (Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, err
	}
	var p Policy
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Policy{}, err
	}
	if p.SchemaVersion != PolicySchemaV1 {
		return Policy{}, fmt.Errorf("unsupported policy schema %q", p.SchemaVersion)
	}
	if p.PolicyID == "" || p.Version == "" {
		return Policy{}, errors.New("policy_id and version are required")
	}
	if p.HighScoreThreshold <= p.ReviewScoreThreshold || p.ReviewScoreThreshold < 0 || p.HighScoreThreshold > 1000 {
		return Policy{}, errors.New("invalid score thresholds")
	}
	if p.ExternalEscalateThreshold < 0 || p.ExternalEscalateThreshold > 1000 {
		return Policy{}, errors.New("invalid external escalation threshold")
	}
	declared := p.PolicySHA256
	p.PolicySHA256 = ""
	computed, err := HashObject(p)
	if err != nil {
		return Policy{}, err
	}
	if declared != "" && declared != computed {
		return Policy{}, fmt.Errorf("policy checksum mismatch: declared %s computed %s", declared, computed)
	}
	p.PolicySHA256 = computed
	return p, nil
}

func (p Policy) Evaluate(req CreateAlertRequest) (Classification, PolicyDecision, *ScreeningLineage, []CandidateSummary, string, error) {
	if strings.TrimSpace(req.TenantID) == "" {
		return Classification{}, PolicyDecision{}, nil, nil, "", errors.New("tenant_id is required")
	}
	if strings.TrimSpace(req.CorrelationID) == "" || strings.TrimSpace(req.IdempotencyKey) == "" {
		return Classification{}, PolicyDecision{}, nil, nil, "", errors.New("correlation_id and idempotency_key are required")
	}
	var lineage *ScreeningLineage
	var candidates []CandidateSummary
	var blockers, externalReasons []string
	var sourceIdentity string
	var score int
	switch req.SourceType {
	case "screening_ledger":
		if len(req.ScreeningEvent) == 0 {
			return Classification{}, PolicyDecision{}, nil, nil, "", errors.New("screening_event is required")
		}
		var event screeningLedgerEvent
		dec := json.NewDecoder(bytes.NewReader(req.ScreeningEvent))
		if err := dec.Decode(&event); err != nil {
			return Classification{}, PolicyDecision{}, nil, nil, "", fmt.Errorf("screening_event: %w", err)
		}
		if event.SchemaVersion != "openwatchlist.screening-ledger-event.v1" || event.EventID == "" || event.EventSHA256 == "" {
			return Classification{}, PolicyDecision{}, nil, nil, "", errors.New("invalid Phase 8G screening ledger event")
		}
		declaredEventSHA := event.EventSHA256
		event.EventSHA256 = ""
		eventRaw, _ := json.Marshal(event)
		if SHA256Bytes(eventRaw) != declaredEventSHA {
			return Classification{}, PolicyDecision{}, nil, nil, "", errors.New("phase 8G screening event checksum mismatch")
		}
		event.EventSHA256 = declaredEventSHA
		var bounded boundedCandidateSummary
		if len(event.CandidateSummary) > 0 {
			if err := json.Unmarshal(event.CandidateSummary, &bounded); err != nil {
				return Classification{}, PolicyDecision{}, nil, nil, "", fmt.Errorf("candidate_summary: %w", err)
			}
		}
		lineage = &ScreeningLineage{LedgerID: event.LedgerID, EventID: event.EventID, EventSHA256: event.EventSHA256, RequestSHA256: event.RequestSHA256, ResponseSHA256: event.ResponseSHA256, RequestSnapshotSHA256: event.RequestSnapshotSHA256, ResponseSnapshotSHA256: event.ResponseSnapshotSHA256, ActivationLineage: cloneRaw(event.ActivationLineage), PromotionLineage: cloneRaw(event.PromotionLineage)}
		for _, c := range bounded.Candidates {
			candidates = append(candidates, CandidateSummary{CandidateID: c.CandidateID, Score: c.Score, Band: c.Band, ReasonCodes: sortedUnique(c.ReasonCodes)})
			if c.Score > score {
				score = c.Score
			}
		}
		blockers = sortedUnique(bounded.Blockers)
		sourceIdentity = event.EventID + ":" + event.EventSHA256
	case "external_alert":
		if req.ExternalAlert == nil {
			return Classification{}, PolicyDecision{}, nil, nil, "", errors.New("external_alert is required")
		}
		ext := req.ExternalAlert
		if ext.SchemaVersion != ExternalAlertSchemaV1 || ext.SourceSystemID == "" || ext.SourceAlertID == "" || ext.RawListName == "" || len(ext.AlertListResolution) == 0 {
			return Classification{}, PolicyDecision{}, nil, nil, "", errors.New("external alert requires schema, source identity, exact raw_list_name and alert_list_resolution")
		}
		score = ext.ExternalScore
		externalReasons = sortedUnique(ext.ExternalReasons)
		for _, id := range sortedUnique(ext.CandidateReferences) {
			candidates = append(candidates, CandidateSummary{CandidateID: id, Score: score, ReasonCodes: externalReasons})
		}
		sourceIdentity = ext.SourceSystemID + ":" + ext.SourceAlertID + ":" + ext.RawListName
	default:
		return Classification{}, PolicyDecision{}, nil, nil, "", fmt.Errorf("unsupported source_type %q", req.SourceType)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Score != candidates[j].Score {
			return candidates[i].Score > candidates[j].Score
		}
		return candidates[i].CandidateID < candidates[j].CandidateID
	})
	patterns := []string{}
	countervailing := []string{}
	missing := []string{}
	for _, c := range candidates {
		for _, code := range c.ReasonCodes {
			switch code {
			case "entity_type_mismatch", "country_contradiction", "dob_contradiction", "wrong_field", "technical_artifact", "denial_context":
				patterns = append(patterns, code)
			case "identifier_exact", "name_exact", "country_exact", "dob_exact":
				countervailing = append(countervailing, code)
			}
		}
	}
	if len(candidates) == 0 {
		missing = append(missing, "candidate_evidence_unavailable")
	}
	if len(blockers) > 0 {
		patterns = append(patterns, blockers...)
	}
	patterns, countervailing, missing = sortedUnique(patterns), sortedUnique(countervailing), sortedUnique(missing)
	blockers = sortedUnique(append(blockers, missing...))
	routeHint := "clear"
	if len(blockers) > 0 || score >= p.ReviewScoreThreshold {
		routeHint = "investigate"
	}
	if score >= p.HighScoreThreshold || (req.SourceType == "external_alert" && score >= p.ExternalEscalateThreshold) {
		routeHint = "escalate"
	}
	classificationBase := struct {
		Source string   `json:"source"`
		Score  int      `json:"score"`
		P      []string `json:"patterns"`
		C      []string `json:"countervailing"`
		M      []string `json:"missing"`
	}{sourceIdentity, score, patterns, countervailing, missing}
	classificationID, _ := HashObject(classificationBase)
	classification := Classification{SchemaVersion: "openwatchlist.false-positive-classification.phase9ab.v1", ClassificationID: classificationID, PatternCodes: patterns, CountervailingCodes: countervailing, MissingEvidence: missing, RouteHint: routeHint, ScoreBasis: score}

	route := routeHint
	reasons := append([]string{}, countervailing...)
	reasons = append(reasons, patterns...)
	if len(reasons) == 0 {
		reasons = []string{"no_positive_candidate_signal"}
	}
	trace := []string{"load_checksum_addressed_policy", "evaluate_phase4_pattern_evidence", "apply_missing_evidence_blockers", "apply_score_thresholds", "emit_non_analyst_policy_route"}
	threshold := p.ReviewScoreThreshold
	if route == "escalate" {
		threshold = p.HighScoreThreshold
	}
	decisionBase := struct {
		ClassificationID string   `json:"classification_id"`
		PolicySHA        string   `json:"policy_sha256"`
		Route            string   `json:"route"`
		Score            int      `json:"score"`
		Blockers         []string `json:"blockers"`
		Reasons          []string `json:"reasons"`
	}{classificationID, p.PolicySHA256, route, score, blockers, sortedUnique(reasons)}
	decisionID, _ := HashObject(decisionBase)
	decision := PolicyDecision{SchemaVersion: "openwatchlist.policy-decision.phase9ab.v1", DecisionID: decisionID, PolicyID: p.PolicyID, PolicyVersion: p.Version, PolicySHA256: p.PolicySHA256, Route: route, Score: score, Threshold: threshold, Blockers: blockers, ReasonCodes: sortedUnique(reasons), OrderedRuleTrace: trace}
	return classification, decision, lineage, candidates, sourceIdentity, nil
}

func BuildAlert(p Policy, req CreateAlertRequest) (AlertRecord, error) {
	occurredAt, err := normalizeTime(req.OccurredAt)
	if err != nil {
		return AlertRecord{}, err
	}
	classification, decision, lineage, candidates, sourceIdentity, err := p.Evaluate(req)
	if err != nil {
		return AlertRecord{}, err
	}
	alertIdentity := struct {
		TenantID       string `json:"tenant_id"`
		SourceType     string `json:"source_type"`
		SourceIdentity string `json:"source_identity"`
		DecisionID     string `json:"decision_id"`
	}{req.TenantID, req.SourceType, sourceIdentity, decision.DecisionID}
	alertIDHash, _ := HashObject(alertIdentity)
	alert := AlertRecord{SchemaVersion: AlertSchemaV1, AlertID: "alert_" + alertIDHash[:32], TenantID: req.TenantID, SourceType: req.SourceType, SourceIdentity: sourceIdentity, ScreeningLineage: lineage, ExternalAlert: req.ExternalAlert, Subject: cloneRaw(req.Subject), CandidateSummary: candidates, Classification: classification, PolicyDecision: decision, CorrelationIDHash: HashString(req.CorrelationID), CreatedAt: occurredAt}
	recordBase := alert
	recordBase.RecordSHA256 = ""
	alert.RecordSHA256, err = HashObject(recordBase)
	if err != nil {
		return AlertRecord{}, err
	}
	return alert, nil
}
