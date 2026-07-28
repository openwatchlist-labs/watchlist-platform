package assistancerag

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertcase"
)

type Store struct {
	Dir        string
	StreamID   string
	AlertStore *alertcase.Store
	Snapshot   CorpusSnapshot
	Models     ModelProfile
	Client     ModelClient
}

func NewStore(dir, streamID string, alertStore *alertcase.Store, snapshot CorpusSnapshot, profile ModelProfile, client ModelClient) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("assistance state directory is required")
	}
	if streamID == "" {
		streamID = "case-assistance"
	}
	if alertStore == nil {
		return nil, errors.New("alert-case store is required")
	}
	if client == nil {
		return nil, errors.New("model client is required")
	}
	if err := VerifySnapshot(snapshot); err != nil {
		return nil, err
	}
	if profile.PrimaryModelID == "" || profile.ReasoningModelID == "" || profile.GuardianModelID == "" {
		return nil, errors.New("primary, reasoning, and guardian model IDs are required")
	}
	if profile.ContextTokens <= 0 {
		profile.ContextTokens = 16384
	}
	if profile.KeepAlive == "" {
		profile.KeepAlive = "0"
	}
	if profile.MaxOutputBytes <= 0 {
		profile.MaxOutputBytes = 65536
	}
	s := &Store{Dir: dir, StreamID: streamID, AlertStore: alertStore, Snapshot: snapshot, Models: profile, Client: client}
	for _, path := range []string{"assistance", "reviews", "idempotency", "audit/events"} {
		if err := os.MkdirAll(filepath.Join(dir, path), 0o755); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) withLock(fn func() error) error {
	lock := filepath.Join(s.Dir, ".lock")
	deadline := time.Now().Add(15 * time.Second)
	for {
		if err := os.Mkdir(lock, 0o700); err == nil {
			defer os.Remove(lock)
			return fn()
		} else if !os.IsExist(err) {
			return err
		}
		if time.Now().After(deadline) {
			return errors.New("timed out waiting for assistance state lock")
		}
		time.Sleep(15 * time.Millisecond)
	}
}

func (s *Store) Assist(ctx context.Context, req AssistanceRequest) (AssistanceRecord, bool, error) {
	var result AssistanceRecord
	var replayed bool
	err := s.withLock(func() error {
		occurredAt, err := NormalizeTime(req.OccurredAt)
		if err != nil {
			return err
		}
		req.OccurredAt = occurredAt
		if req.CaseID == "" || req.Actor == "" || req.IdempotencyKey == "" {
			return errors.New("case_id, actor, and idempotency_key are required")
		}
		if err := validateCaseID(req.CaseID); err != nil {
			return err
		}
		if req.Task == "" {
			req.Task = "draft_note"
		}
		if req.Task != "draft_note" && req.Task != "evidence_summary" && req.Task != "missing_evidence_questions" {
			return fmt.Errorf("unsupported assistance task %q", req.Task)
		}
		if req.ModelRole == "" {
			req.ModelRole = "primary"
		}
		if req.ModelRole != "primary" && req.ModelRole != "reasoning" {
			return fmt.Errorf("unsupported model_role %q", req.ModelRole)
		}
		caseProjection, err := s.AlertStore.VerifyCase(req.CaseID)
		if err != nil {
			return fmt.Errorf("case verification failed: %w", err)
		}
		if req.TenantID != "" && req.TenantID != caseProjection.TenantID {
			return errors.New("tenant_id does not match case")
		}
		req.TenantID = caseProjection.TenantID
		receipt, err := s.checkReceipt("assist:"+req.CaseID, req.IdempotencyKey, req)
		if err != nil {
			return err
		}
		if receipt != nil {
			result, err = s.Record(receipt.ObjectID)
			replayed = err == nil
			return err
		}
		contextValue, terms, err := s.buildCaseContext(caseProjection)
		if err != nil {
			return err
		}
		retrieval, err := Query(s.Snapshot, RetrievalQuery{TenantID: caseProjection.TenantID, Terms: terms, TopK: 8})
		if err != nil {
			return err
		}
		requestSHA, _ := HashObject(req)
		modelID := s.Models.PrimaryModelID
		if req.ModelRole == "reasoning" {
			modelID = s.Models.ReasoningModelID
		}
		assistanceID := "assistance_" + HashString(req.CaseID + ":" + req.Task + ":" + requestSHA + ":" + retrieval.PackageSHA256 + ":" + modelID)[:24]
		record := AssistanceRecord{SchemaVersion: AssistanceSchemaV1, AssistanceID: assistanceID, CaseID: req.CaseID, TenantID: caseProjection.TenantID, Task: req.Task, Status: "pending", Actor: req.Actor, OccurredAt: occurredAt, CaseContext: contextValue, Retrieval: retrieval}
		if len(retrieval.Passages) == 0 {
			record.Status = "retrieval_empty"
			record.FailureCode = "no_authorized_retrieval_passages"
			if err := s.finalizeRecord(req, &record); err != nil {
				return err
			}
			result = record
			return nil
		}
		generationMessages, err := buildGenerationMessages(contextValue, retrieval, req.Task)
		if err != nil {
			return err
		}
		generationRequest := ModelRequest{Model: modelID, Messages: generationMessages, ContextTokens: s.Models.ContextTokens, KeepAlive: s.Models.KeepAlive}
		generationHash, _ := HashObject(generationMessages)
		record.Generation = ModelInvocation{Role: req.ModelRole, ModelID: modelID, RequestSHA256: generationHash, KeepAlive: s.Models.KeepAlive, ContextTokens: s.Models.ContextTokens}
		generationResponse, generationErr := s.Client.Generate(ctx, generationRequest)
		if generationErr != nil {
			record.Status = "model_unavailable"
			record.FailureCode = "generation_model_unavailable"
			record.FailureDetail = generationErr.Error()
			record.Generation.Error = generationErr.Error()
			if err := s.finalizeRecord(req, &record); err != nil {
				return err
			}
			result = record
			return nil
		}
		record.Generation.ResponseSHA256 = SHA256Bytes([]byte(generationResponse.Content))
		record.Generation.DurationNanos = generationResponse.DurationNanos
		record.Generation.PromptTokens = generationResponse.PromptTokens
		record.Generation.GeneratedTokens = generationResponse.GeneratedTokens
		if len(generationResponse.Content) > s.Models.MaxOutputBytes {
			record.Status = "invalid_model_output"
			record.FailureCode = "generation_output_too_large"
			if err := s.finalizeRecord(req, &record); err != nil {
				return err
			}
			result = record
			return nil
		}
		draft, err := parseDraft(generationResponse.Content, retrieval)
		if err != nil {
			record.Status = "invalid_model_output"
			record.FailureCode = "generation_schema_invalid"
			record.FailureDetail = err.Error()
			if err := s.finalizeRecord(req, &record); err != nil {
				return err
			}
			result = record
			return nil
		}
		record.Draft = &draft
		guardianMessages, err := buildGuardianMessages(contextValue, retrieval, draft)
		if err != nil {
			return err
		}
		guardianHash, _ := HashObject(guardianMessages)
		record.GuardianInvocation = ModelInvocation{Role: "guardian", ModelID: s.Models.GuardianModelID, RequestSHA256: guardianHash, KeepAlive: s.Models.KeepAlive, ContextTokens: s.Models.ContextTokens}
		guardianResponse, guardianErr := s.Client.Generate(ctx, ModelRequest{Model: s.Models.GuardianModelID, Messages: guardianMessages, ContextTokens: s.Models.ContextTokens, KeepAlive: s.Models.KeepAlive})
		if guardianErr != nil {
			record.Status = "guardian_unavailable"
			record.FailureCode = "guardian_model_unavailable"
			record.FailureDetail = guardianErr.Error()
			record.GuardianInvocation.Error = guardianErr.Error()
			if err := s.finalizeRecord(req, &record); err != nil {
				return err
			}
			result = record
			return nil
		}
		record.GuardianInvocation.ResponseSHA256 = SHA256Bytes([]byte(guardianResponse.Content))
		record.GuardianInvocation.DurationNanos = guardianResponse.DurationNanos
		record.GuardianInvocation.PromptTokens = guardianResponse.PromptTokens
		record.GuardianInvocation.GeneratedTokens = guardianResponse.GeneratedTokens
		guardian, err := parseGuardian(guardianResponse.Content)
		if err != nil {
			record.Status = "invalid_guardian_output"
			record.FailureCode = "guardian_schema_invalid"
			record.FailureDetail = err.Error()
			if err := s.finalizeRecord(req, &record); err != nil {
				return err
			}
			result = record
			return nil
		}
		guardian.CitationsValid = validateDraftCitations(draft, retrieval)
		record.Guardian = &guardian
		if guardian.Grounded && guardian.Relevant && guardian.Safe && guardian.CitationsValid && len(guardian.UnsupportedClaims) == 0 {
			record.Status = "completed"
		} else {
			record.Status = "rejected_guardrail"
			record.FailureCode = "guardian_rejected"
		}
		if err := s.finalizeRecord(req, &record); err != nil {
			return err
		}
		result = record
		return nil
	})
	return result, replayed, err
}

func (s *Store) finalizeRecord(req AssistanceRequest, record *AssistanceRecord) error {
	hashCopy := *record
	hashCopy.RecordSHA256 = ""
	hash, err := HashObject(hashCopy)
	if err != nil {
		return err
	}
	record.RecordSHA256 = hash
	path, err := s.assistancePath(record.AssistanceID)
	if err != nil {
		return err
	}
	if err := WriteJSONAtomic(path, record, 0o600); err != nil {
		return err
	}
	if err := s.saveReceipt("assist:"+req.CaseID, req.IdempotencyKey, req, record, "assistance", record.AssistanceID, req.OccurredAt); err != nil {
		return err
	}
	details, _ := json.Marshal(map[string]any{"status": record.Status, "record_sha256": record.RecordSHA256, "snapshot_sha256": record.Retrieval.SnapshotSHA256, "generation_model": record.Generation.ModelID, "guardian_model": record.GuardianInvocation.ModelID})
	if err := s.appendAudit(req.OccurredAt, "assistance_recorded", req.Actor, "assistance", record.AssistanceID, details); err != nil {
		return err
	}
	return nil
}

func (s *Store) Record(id string) (AssistanceRecord, error) {
	var record AssistanceRecord
	path, err := s.assistancePath(id)
	if err != nil {
		return record, err
	}
	if err := ReadStrictJSON(path, &record); err != nil {
		return record, err
	}
	if err := VerifyRecord(record); err != nil {
		return record, err
	}
	return record, nil
}

func VerifyRecord(record AssistanceRecord) error {
	if record.SchemaVersion != AssistanceSchemaV1 {
		return errors.New("unsupported assistance schema")
	}
	hashCopy := record
	expected := hashCopy.RecordSHA256
	hashCopy.RecordSHA256 = ""
	actual, err := HashObject(hashCopy)
	if err != nil {
		return err
	}
	if expected != actual {
		return errors.New("assistance record checksum mismatch")
	}
	if record.Draft != nil && !validateDraftCitations(*record.Draft, record.Retrieval) {
		return errors.New("assistance citations do not resolve")
	}
	return nil
}

func (s *Store) Review(req ReviewRequest) (ReviewEvent, bool, error) {
	var out ReviewEvent
	var replayed bool
	err := s.withLock(func() error {
		occurredAt, err := NormalizeTime(req.OccurredAt)
		if err != nil {
			return err
		}
		req.OccurredAt = occurredAt
		if req.CaseID == "" || req.AssistanceID == "" || req.Actor == "" || req.IdempotencyKey == "" {
			return errors.New("case_id, assistance_id, actor, and idempotency_key are required")
		}
		if err := validateCaseID(req.CaseID); err != nil {
			return err
		}
		if err := validateAssistanceID(req.AssistanceID); err != nil {
			return err
		}
		if req.Action != "accept" && req.Action != "reject" {
			return errors.New("review action must be accept or reject")
		}
		receipt, err := s.checkReceipt("review:"+req.AssistanceID, req.IdempotencyKey, req)
		if err != nil {
			return err
		}
		if receipt != nil {
			out, err = s.reviewBySequence(req.AssistanceID, receipt.ObjectID)
			replayed = err == nil
			return err
		}
		record, err := s.Record(req.AssistanceID)
		if err != nil {
			return err
		}
		if record.CaseID != req.CaseID {
			return errors.New("assistance does not belong to case")
		}
		if record.Status != "completed" && req.Action == "accept" {
			return fmt.Errorf("only completed assistance can be accepted; status is %s", record.Status)
		}
		pattern, err := s.reviewPath(req.AssistanceID, "*.json")
		if err != nil {
			return err
		}
		files, _ := filepath.Glob(pattern)
		sort.Strings(files)
		sequence := uint64(len(files) + 1)
		previous := ""
		if len(files) > 0 {
			var prior ReviewEvent
			if err := ReadStrictJSON(files[len(files)-1], &prior); err != nil {
				return err
			}
			previous = prior.EventSHA256
		}
		out = ReviewEvent{SchemaVersion: ReviewSchemaV1, AssistanceID: req.AssistanceID, CaseID: req.CaseID, Sequence: sequence, PreviousEventSHA256: previous, Action: req.Action, Actor: req.Actor, Reason: req.Reason, OccurredAt: occurredAt}
		hashCopy := out
		hashCopy.EventSHA256 = ""
		out.EventSHA256, _ = HashObject(hashCopy)
		path, err := s.reviewPath(req.AssistanceID, fmt.Sprintf("%020d.json", sequence))
		if err != nil {
			return err
		}
		if err := WriteJSONAtomic(path, out, 0o600); err != nil {
			return err
		}
		if err := s.saveReceipt("review:"+req.AssistanceID, req.IdempotencyKey, req, out, "review_event", strconv.FormatUint(sequence, 10), occurredAt); err != nil {
			return err
		}
		details, _ := json.Marshal(map[string]any{"action": req.Action, "event_sha256": out.EventSHA256})
		return s.appendAudit(occurredAt, "assistance_reviewed", req.Actor, "assistance", req.AssistanceID, details)
	})
	return out, replayed, err
}

func (s *Store) reviewBySequence(id, sequence string) (ReviewEvent, error) {
	var out ReviewEvent
	n, err := strconv.ParseUint(sequence, 10, 64)
	if err != nil {
		return out, err
	}
	path, err := s.reviewPath(id, fmt.Sprintf("%020d.json", n))
	if err != nil {
		return out, err
	}
	return out, ReadStrictJSON(path, &out)
}

func (s *Store) Receipt(scope, key string) (IdempotencyReceipt, error) {
	var out IdempotencyReceipt
	return out, ReadStrictJSON(s.receiptPath(scope, key), &out)
}

func (s *Store) receiptPath(scope, key string) string {
	return filepath.Join(s.Dir, "idempotency", HashString(scope), HashString(key)+".json")
}
func (s *Store) checkReceipt(scope, key string, request any) (*IdempotencyReceipt, error) {
	if key == "" {
		return nil, errors.New("idempotency_key is required")
	}
	requestHash, err := HashObject(request)
	if err != nil {
		return nil, err
	}
	var receipt IdempotencyReceipt
	if err := ReadStrictJSON(s.receiptPath(scope, key), &receipt); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if receipt.RequestSHA256 != requestHash {
		return nil, fmt.Errorf("idempotency conflict for scope %s", scope)
	}
	return &receipt, nil
}
func (s *Store) saveReceipt(scope, key string, request, response any, objectType, objectID, createdAt string) error {
	reqHash, err := HashObject(request)
	if err != nil {
		return err
	}
	responseHash, err := HashObject(response)
	if err != nil {
		return err
	}
	receipt := IdempotencyReceipt{Scope: scope, KeySHA256: HashString(key), RequestSHA256: reqHash, ResponseSHA256: responseHash, ObjectType: objectType, ObjectID: objectID, CreatedAt: createdAt}
	return WriteJSONAtomic(s.receiptPath(scope, key), receipt, 0o600)
}

func (s *Store) appendAudit(occurredAt, action, actor, objectType, objectID string, details json.RawMessage) error {
	files, _ := filepath.Glob(filepath.Join(s.Dir, "audit", "events", "*.json"))
	sort.Strings(files)
	sequence := uint64(len(files) + 1)
	previous := ""
	if len(files) > 0 {
		var prior AuditEvent
		if err := ReadStrictJSON(files[len(files)-1], &prior); err != nil {
			return err
		}
		previous = prior.AuditSHA256
	}
	event := AuditEvent{SchemaVersion: AuditSchemaV1, StreamID: s.StreamID, Sequence: sequence, PreviousAuditSHA256: previous, OccurredAt: occurredAt, Action: action, Actor: actor, ObjectType: objectType, ObjectID: objectID, Details: details}
	hashCopy := event
	hashCopy.AuditSHA256 = ""
	event.AuditSHA256, _ = HashObject(hashCopy)
	return WriteJSONAtomic(filepath.Join(s.Dir, "audit", "events", fmt.Sprintf("%020d.json", sequence)), event, 0o600)
}

func (s *Store) VerifyAudit() (int, error) {
	files, _ := filepath.Glob(filepath.Join(s.Dir, "audit", "events", "*.json"))
	sort.Strings(files)
	previous := ""
	for i, path := range files {
		var e AuditEvent
		if err := ReadStrictJSON(path, &e); err != nil {
			return 0, err
		}
		if e.Sequence != uint64(i+1) || e.PreviousAuditSHA256 != previous {
			return 0, errors.New("audit chain sequence mismatch")
		}
		copy := e
		expected := copy.AuditSHA256
		copy.AuditSHA256 = ""
		actual, _ := HashObject(copy)
		if expected != actual {
			return 0, errors.New("audit checksum mismatch")
		}
		previous = e.AuditSHA256
	}
	return len(files), nil
}

func (s *Store) Status() (Status, error) {
	assistance, _ := filepath.Glob(filepath.Join(s.Dir, "assistance", "*.json"))
	reviews, _ := filepath.Glob(filepath.Join(s.Dir, "reviews", "*", "*.json"))
	auditCount, err := s.VerifyAudit()
	if err != nil {
		return Status{}, err
	}
	return Status{Status: "ok", AssistanceCount: len(assistance), ReviewCount: len(reviews), AuditCount: auditCount}, nil
}

func (s *Store) buildCaseContext(caseProjection alertcase.CaseProjection) (CaseContext, []string, error) {
	facts := make([]map[string]any, 0, len(caseProjection.AlertIDs))
	var terms []string
	terms = append(terms, caseProjection.State, caseProjection.GroupingKey)
	for _, alertID := range caseProjection.AlertIDs {
		alert, err := s.AlertStore.VerifyAlert(alertID)
		if err != nil {
			return CaseContext{}, nil, err
		}
		facts = append(facts, map[string]any{"alert_id": alert.AlertID, "source_type": alert.SourceType, "source_identity": alert.SourceIdentity, "classification": alert.Classification, "policy_decision": alert.PolicyDecision, "candidate_summary": alert.CandidateSummary, "subject": alert.Subject})
		terms = append(terms, alert.PolicyDecision.Route)
		terms = append(terms, alert.PolicyDecision.ReasonCodes...)
		terms = append(terms, alert.PolicyDecision.Blockers...)
		terms = append(terms, alert.Classification.PatternCodes...)
		terms = append(terms, alert.Classification.MissingEvidence...)
		for _, c := range alert.CandidateSummary {
			terms = append(terms, c.CandidateID, c.Band)
			terms = append(terms, c.ReasonCodes...)
		}
	}
	raw, err := CanonicalJSON(facts)
	if err != nil {
		return CaseContext{}, nil, err
	}
	if len(raw) > 65536 {
		return CaseContext{}, nil, errors.New("bounded case context exceeds 65536 bytes")
	}
	contextValue := CaseContext{CaseID: caseProjection.CaseID, TenantID: caseProjection.TenantID, State: caseProjection.State, Revision: caseProjection.Revision, AlertIDs: append([]string(nil), caseProjection.AlertIDs...), AlertFacts: raw}
	hashCopy := contextValue
	hashCopy.ContextSHA256 = ""
	contextValue.ContextSHA256, _ = HashObject(hashCopy)
	return contextValue, SortedUnique(terms), nil
}

func buildGenerationMessages(contextValue CaseContext, retrieval RetrievalPackage, task string) ([]Message, error) {
	contextJSON, _ := CanonicalJSON(contextValue)
	retrievalJSON, _ := CanonicalJSON(retrieval)
	system := "You are a governed sanctions alert-review assistant. Return one JSON object only. Do not make, change, recommend, or imply a regulatory disposition, policy route, case outcome, or customer-impacting action. Every evidence finding must cite one or more passage_id values from the supplied retrieval package. Use schema_version openwatchlist.analyst-assistance-draft.v1 with fields summary, evidence_findings, missing_evidence_questions, and suggested_next_steps."
	user := "Task: " + task + "\nVerified case context:\n" + string(contextJSON) + "\nAuthorized retrieval package:\n" + string(retrievalJSON)
	return []Message{{Role: "system", Content: system}, {Role: "user", Content: user}}, nil
}
func buildGuardianMessages(contextValue CaseContext, retrieval RetrievalPackage, draft AssistanceDraft) ([]Message, error) {
	contextJSON, _ := CanonicalJSON(contextValue)
	retrievalJSON, _ := CanonicalJSON(retrieval)
	draftJSON, _ := CanonicalJSON(draft)
	system := "Evaluate the draft for groundedness, relevance, safety, and citation validity. Return JSON only using schema_version openwatchlist.guardian-assessment.v1 and fields grounded, relevant, safe, citations_valid, unsupported_claims, notes. Reject any final disposition, route override, uncited factual claim, or unsupported assertion."
	user := "Case context:\n" + string(contextJSON) + "\nRetrieval:\n" + string(retrievalJSON) + "\nDraft:\n" + string(draftJSON)
	return []Message{{Role: "system", Content: system}, {Role: "user", Content: user}}, nil
}

func parseDraft(content string, retrieval RetrievalPackage) (AssistanceDraft, error) {
	var draft AssistanceDraft
	dec := json.NewDecoder(strings.NewReader(content))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&draft); err != nil {
		return draft, err
	}
	if draft.SchemaVersion != DraftSchemaV1 {
		return draft, errors.New("draft schema_version is invalid")
	}
	if strings.TrimSpace(draft.Summary) == "" {
		return draft, errors.New("draft summary is required")
	}
	if containsDispositionLanguage(draft) {
		return draft, errors.New("draft contains prohibited disposition language")
	}
	if !validateDraftCitations(draft, retrieval) {
		return draft, errors.New("draft contains unresolved citations")
	}
	return draft, nil
}
func parseGuardian(content string) (GuardianAssessment, error) {
	var g GuardianAssessment
	dec := json.NewDecoder(strings.NewReader(content))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&g); err != nil {
		return g, err
	}
	if g.SchemaVersion != GuardianSchemaV1 {
		return g, errors.New("guardian schema_version is invalid")
	}
	g.UnsupportedClaims = SortedUnique(g.UnsupportedClaims)
	return g, nil
}
func validateDraftCitations(draft AssistanceDraft, retrieval RetrievalPackage) bool {
	allowed := map[string]struct{}{}
	for _, p := range retrieval.Passages {
		allowed[p.PassageID] = struct{}{}
	}
	for _, finding := range draft.EvidenceFindings {
		if strings.TrimSpace(finding.Statement) == "" || len(finding.CitationIDs) == 0 {
			return false
		}
		for _, id := range finding.CitationIDs {
			if _, ok := allowed[id]; !ok {
				return false
			}
		}
	}
	return true
}
func containsDispositionLanguage(d AssistanceDraft) bool {
	raw, _ := json.Marshal(d)
	upper := strings.ToUpper(string(raw))
	prohibited := []string{"CLEAR THE ALERT", "CLOSE THE ALERT", "ESCALATE THE ALERT", "FINAL DISPOSITION", "POLICY ROUTE SHOULD", "CUSTOMER SHOULD BE BLOCKED"}
	for _, p := range prohibited {
		if strings.Contains(upper, p) {
			return true
		}
	}
	return false
}
