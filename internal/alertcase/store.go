package alertcase

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Store struct {
	Dir      string
	Policy   Policy
	StreamID string
}

type IdempotencyReceipt struct {
	Scope          string `json:"scope"`
	KeySHA256      string `json:"key_sha256"`
	RequestSHA256  string `json:"request_sha256"`
	ObjectType     string `json:"object_type"`
	ObjectID       string `json:"object_id"`
	ResponseSHA256 string `json:"response_sha256"`
	CreatedAt      string `json:"created_at"`
}

func NewStore(dir string, policy Policy, streamID string) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("state directory is required")
	}
	if streamID == "" {
		streamID = "alert-case"
	}
	s := &Store{Dir: dir, Policy: policy, StreamID: streamID}
	for _, path := range []string{"alerts", "cases", "idempotency", "audit/events"} {
		if err := os.MkdirAll(filepath.Join(dir, path), 0o755); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) withLock(fn func() error) error {
	lock := filepath.Join(s.Dir, ".lock")
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := os.Mkdir(lock, 0o700)
		if err == nil {
			defer os.Remove(lock)
			return fn()
		}
		if !os.IsExist(err) {
			return err
		}
		if time.Now().After(deadline) {
			return errors.New("timed out waiting for alert-case state lock")
		}
		time.Sleep(15 * time.Millisecond)
	}
}

func (s *Store) receiptPath(scope, key string) string {
	return filepath.Join(s.Dir, "idempotency", HashString(scope), HashString(key)+".json")
}

func (s *Store) checkReceipt(scope, key string, request any) (*IdempotencyReceipt, error) {
	if strings.TrimSpace(key) == "" {
		return nil, errors.New("idempotency_key is required")
	}
	reqHash, err := HashObject(request)
	if err != nil {
		return nil, err
	}
	path := s.receiptPath(scope, key)
	var receipt IdempotencyReceipt
	if err := readStrictJSON(path, &receipt); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if receipt.RequestSHA256 != reqHash {
		return nil, fmt.Errorf("idempotency conflict for scope %s", scope)
	}
	return &receipt, nil
}

func (s *Store) saveReceipt(scope, key string, request, response any, objectType, objectID, createdAt string) error {
	reqHash, err := HashObject(request)
	if err != nil {
		return err
	}
	respHash, err := HashObject(response)
	if err != nil {
		return err
	}
	receipt := IdempotencyReceipt{Scope: scope, KeySHA256: HashString(key), RequestSHA256: reqHash, ObjectType: objectType, ObjectID: objectID, ResponseSHA256: respHash, CreatedAt: createdAt}
	return writeJSONAtomic(s.receiptPath(scope, key), receipt, 0o600)
}

func (s *Store) CreateAlert(req CreateAlertRequest) (AlertRecord, bool, error) {
	var out AlertRecord
	var replayed bool
	err := s.withLock(func() error {
		receipt, err := s.checkReceipt("create-alert", req.IdempotencyKey, req)
		if err != nil {
			return err
		}
		if receipt != nil {
			if err := readStrictJSON(filepath.Join(s.Dir, "alerts", receipt.ObjectID+".json"), &out); err != nil {
				return err
			}
			replayed = true
			return nil
		}
		alert, err := BuildAlert(s.Policy, req)
		if err != nil {
			return err
		}
		path := filepath.Join(s.Dir, "alerts", alert.AlertID+".json")
		if raw, err := os.ReadFile(path); err == nil {
			var existing AlertRecord
			if err := json.Unmarshal(raw, &existing); err != nil {
				return err
			}
			if existing.RecordSHA256 != alert.RecordSHA256 {
				return errors.New("content-addressed alert collision")
			}
			out = existing
			replayed = true
		} else if os.IsNotExist(err) {
			if err := writeJSONAtomic(path, alert, 0o600); err != nil {
				return err
			}
			out = alert
			if err := s.appendAuditUnlocked(alert.CreatedAt, "alert_created", "system", "alert", alert.AlertID, mustRaw(alert)); err != nil {
				return err
			}
		} else {
			return err
		}
		return s.saveReceipt("create-alert", req.IdempotencyKey, req, out, "alert", out.AlertID, out.CreatedAt)
	})
	return out, replayed, err
}

func (s *Store) Alert(id string) (AlertRecord, error) {
	var a AlertRecord
	err := readStrictJSON(filepath.Join(s.Dir, "alerts", id+".json"), &a)
	return a, err
}

func (s *Store) CreateCase(req CreateCaseRequest) (CaseProjection, bool, error) {
	var out CaseProjection
	var replayed bool
	err := s.withLock(func() error {
		receipt, err := s.checkReceipt("create-case", req.IdempotencyKey, req)
		if err != nil {
			return err
		}
		if receipt != nil {
			out, err = s.caseProjectionUnlocked(receipt.ObjectID)
			replayed = true
			return err
		}
		if req.TenantID == "" || req.CreatedBy == "" || req.Reason == "" || len(req.AlertIDs) == 0 {
			return errors.New("tenant_id, created_by, reason and alert_ids are required")
		}
		occurredAt, err := normalizeTime(req.OccurredAt)
		if err != nil {
			return err
		}
		ids := sortedUnique(req.AlertIDs)
		for _, id := range ids {
			alert, err := s.Alert(id)
			if err != nil {
				return fmt.Errorf("alert %s: %w", id, err)
			}
			if alert.TenantID != req.TenantID {
				return fmt.Errorf("alert %s belongs to another tenant", id)
			}
		}
		identity := struct {
			TenantID    string   `json:"tenant_id"`
			AlertIDs    []string `json:"alert_ids"`
			GroupingKey string   `json:"grouping_key"`
		}{req.TenantID, ids, req.GroupingKey}
		h, _ := HashObject(identity)
		caseID := "case_" + h[:32]
		caseDir := filepath.Join(s.Dir, "cases", caseID)
		if _, err := os.Stat(filepath.Join(caseDir, "head.json")); err == nil {
			out, err = s.caseProjectionUnlocked(caseID)
			replayed = true
			if err != nil {
				return err
			}
			return s.saveReceipt("create-case", req.IdempotencyKey, req, out, "case", caseID, occurredAt)
		}
		if err := os.MkdirAll(filepath.Join(caseDir, "events"), 0o755); err != nil {
			return err
		}
		payload, _ := CanonicalJSON(map[string]any{"tenant_id": req.TenantID, "alert_ids": ids, "grouping_key": req.GroupingKey})
		event, err := s.buildCaseEvent(caseID, 1, 1, "", "case_created", req.CreatedBy, req.Reason, occurredAt, payload)
		if err != nil {
			return err
		}
		if err := s.writeCaseEventUnlocked(event); err != nil {
			return err
		}
		projection := CaseProjection{SchemaVersion: CaseProjectionSchemaV1, CaseID: caseID, TenantID: req.TenantID, AlertIDs: ids, GroupingKey: req.GroupingKey, State: "open", Revision: 1, CreatedAt: occurredAt, UpdatedAt: occurredAt, HeadEventSHA256: event.EventSHA256}
		if err := writeJSONAtomic(filepath.Join(caseDir, "projection.json"), projection, 0o600); err != nil {
			return err
		}
		if err := writeJSONAtomic(filepath.Join(caseDir, "head.json"), CaseHead{SchemaVersion: CaseHeadSchemaV1, CaseID: caseID, Sequence: 1, Revision: 1, EventSHA256: event.EventSHA256}, 0o600); err != nil {
			return err
		}
		out = projection
		if err := s.appendAuditUnlocked(occurredAt, "case_created", req.CreatedBy, "case", caseID, mustRaw(event)); err != nil {
			return err
		}
		return s.saveReceipt("create-case", req.IdempotencyKey, req, out, "case", caseID, occurredAt)
	})
	return out, replayed, err
}

func (s *Store) ApplyCaseEvent(req CaseEventRequest) (CaseProjection, CaseEvent, bool, error) {
	var projection CaseProjection
	var event CaseEvent
	var replayed bool
	err := s.withLock(func() error {
		scope := "case-event:" + req.CaseID + ":" + req.Action
		receipt, err := s.checkReceipt(scope, req.IdempotencyKey, req)
		if err != nil {
			return err
		}
		if receipt != nil {
			projection, err = s.caseProjectionUnlocked(req.CaseID)
			if err != nil {
				return err
			}
			var head CaseHead
			if err := readStrictJSON(filepath.Join(s.Dir, "cases", req.CaseID, "head.json"), &head); err != nil {
				return err
			}
			event, err = s.caseEventBySequenceUnlocked(req.CaseID, head.Sequence)
			replayed = true
			return err
		}
		projection, err = s.caseProjectionUnlocked(req.CaseID)
		if err != nil {
			return err
		}
		if req.ExpectedRevision != projection.Revision {
			return fmt.Errorf("case revision conflict: expected %d current %d", req.ExpectedRevision, projection.Revision)
		}
		if req.Actor == "" || req.Action == "" || req.IdempotencyKey == "" {
			return errors.New("actor, action and idempotency_key are required")
		}
		occurredAt, err := normalizeTime(req.OccurredAt)
		if err != nil {
			return err
		}
		var head CaseHead
		if err := readStrictJSON(filepath.Join(s.Dir, "cases", req.CaseID, "head.json"), &head); err != nil {
			return err
		}
		next := projection
		if err := applyTransition(&next, req, occurredAt); err != nil {
			return err
		}
		event, err = s.buildCaseEvent(req.CaseID, head.Sequence+1, head.Revision+1, head.EventSHA256, req.Action, req.Actor, req.Reason, occurredAt, req.Payload)
		if err != nil {
			return err
		}
		if err := s.writeCaseEventUnlocked(event); err != nil {
			return err
		}
		next.Revision = event.Revision
		next.UpdatedAt = occurredAt
		next.HeadEventSHA256 = event.EventSHA256
		if err := writeJSONAtomic(filepath.Join(s.Dir, "cases", req.CaseID, "projection.json"), next, 0o600); err != nil {
			return err
		}
		if err := writeJSONAtomic(filepath.Join(s.Dir, "cases", req.CaseID, "head.json"), CaseHead{SchemaVersion: CaseHeadSchemaV1, CaseID: req.CaseID, Sequence: event.Sequence, Revision: event.Revision, EventSHA256: event.EventSHA256}, 0o600); err != nil {
			return err
		}
		projection = next
		if err := s.appendAuditUnlocked(occurredAt, req.Action, req.Actor, "case", req.CaseID, mustRaw(event)); err != nil {
			return err
		}
		response := struct {
			Projection CaseProjection `json:"case"`
			Event      CaseEvent      `json:"event"`
		}{projection, event}
		return s.saveReceipt(scope, req.IdempotencyKey, req, response, "case", req.CaseID, occurredAt)
	})
	return projection, event, replayed, err
}

func applyTransition(p *CaseProjection, req CaseEventRequest, occurredAt string) error {
	payloadMap := map[string]json.RawMessage{}
	if len(req.Payload) > 0 {
		if err := json.Unmarshal(req.Payload, &payloadMap); err != nil {
			return fmt.Errorf("payload: %w", err)
		}
	}
	getString := func(key string) string {
		var value string
		_ = json.Unmarshal(payloadMap[key], &value)
		return strings.TrimSpace(value)
	}
	switch req.Action {
	case "assign":
		if p.State != "open" && p.State != "assigned" && p.State != "investigating" && p.State != "reopened" {
			return fmt.Errorf("assign is not allowed from %s", p.State)
		}
		assignee := getString("assignee")
		if assignee == "" {
			return errors.New("assign requires payload.assignee")
		}
		p.AssignedTo = assignee
		p.State = "assigned"
	case "start_investigation":
		if p.State != "assigned" && p.State != "reopened" {
			return fmt.Errorf("start_investigation is not allowed from %s", p.State)
		}
		p.State = "investigating"
	case "request_evidence":
		if p.State != "assigned" && p.State != "investigating" && p.State != "pending_evidence" {
			return fmt.Errorf("request_evidence is not allowed from %s", p.State)
		}
		id := getString("evidence_request_id")
		if id == "" {
			id = "evidence_request_" + HashString(req.CaseID + ":" + strconv.FormatUint(req.ExpectedRevision+1, 10))[:24]
		}
		p.EvidenceRequestIDs = sortedUnique(append(p.EvidenceRequestIDs, id))
		p.State = "pending_evidence"
	case "submit_evidence":
		if p.State != "pending_evidence" && p.State != "investigating" {
			return fmt.Errorf("submit_evidence is not allowed from %s", p.State)
		}
		id := getString("evidence_submission_id")
		if id == "" {
			id = "evidence_submission_" + HashString(req.CaseID + ":" + strconv.FormatUint(req.ExpectedRevision+1, 10))[:24]
		}
		p.EvidenceSubmissionIDs = sortedUnique(append(p.EvidenceSubmissionIDs, id))
		p.State = "investigating"
	case "propose_decision":
		if p.State != "assigned" && p.State != "investigating" && p.State != "pending_evidence" && p.State != "reopened" {
			return fmt.Errorf("propose_decision is not allowed from %s", p.State)
		}
		decision := payloadMap["decision"]
		if len(decision) == 0 || bytes.Equal(bytes.TrimSpace(decision), []byte("null")) {
			return errors.New("propose_decision requires payload.decision")
		}
		p.DecisionProposer = req.Actor
		p.ProposedDecision = cloneRaw(decision)
		p.State = "pending_approval"
	case "approve_decision":
		if p.State != "pending_approval" {
			return fmt.Errorf("approve_decision is not allowed from %s", p.State)
		}
		if p.DecisionProposer == "" || p.DecisionProposer == req.Actor {
			return errors.New("four-eyes rule: approver must differ from decision proposer")
		}
		p.ApprovedDecision = cloneRaw(p.ProposedDecision)
		p.State = "resolved"
	case "reject_decision":
		if p.State != "pending_approval" {
			return fmt.Errorf("reject_decision is not allowed from %s", p.State)
		}
		if p.DecisionProposer == "" || p.DecisionProposer == req.Actor {
			return errors.New("four-eyes rule: rejector must differ from decision proposer")
		}
		p.DecisionProposer = ""
		p.ProposedDecision = nil
		p.State = "investigating"
	case "reopen":
		if p.State != "resolved" {
			return fmt.Errorf("reopen is not allowed from %s", p.State)
		}
		p.State = "reopened"
		p.DecisionProposer = ""
		p.ProposedDecision = nil
	case "link_rescreen":
		if p.State == "resolved" {
			return errors.New("link_rescreen requires reopening the case first")
		}
		eventID := getString("screening_event_id")
		if eventID == "" {
			return errors.New("link_rescreen requires payload.screening_event_id")
		}
		p.RescreenEventIDs = sortedUnique(append(p.RescreenEventIDs, eventID))
	default:
		return fmt.Errorf("unsupported case action %q", req.Action)
	}
	_ = occurredAt
	return nil
}

func (s *Store) buildCaseEvent(caseID string, sequence, revision uint64, previous, action, actor, reason, occurredAt string, payload json.RawMessage) (CaseEvent, error) {
	e := CaseEvent{SchemaVersion: CaseEventSchemaV1, CaseID: caseID, Sequence: sequence, Revision: revision, PreviousEventSHA256: previous, Action: action, Actor: actor, Reason: reason, OccurredAt: occurredAt, Payload: cloneRaw(payload)}
	base := e
	base.EventSHA256 = ""
	h, err := HashObject(base)
	if err != nil {
		return CaseEvent{}, err
	}
	e.EventSHA256 = h
	return e, nil
}

func (s *Store) writeCaseEventUnlocked(e CaseEvent) error {
	name := fmt.Sprintf("%020d-%s.json", e.Sequence, e.EventSHA256)
	return writeJSONAtomic(filepath.Join(s.Dir, "cases", e.CaseID, "events", name), e, 0o600)
}

func (s *Store) caseEventBySequenceUnlocked(caseID string, sequence uint64) (CaseEvent, error) {
	matches, err := filepath.Glob(filepath.Join(s.Dir, "cases", caseID, "events", fmt.Sprintf("%020d-*.json", sequence)))
	if err != nil || len(matches) != 1 {
		return CaseEvent{}, fmt.Errorf("case event sequence %d not found", sequence)
	}
	var event CaseEvent
	err = readStrictJSON(matches[0], &event)
	return event, err
}

func (s *Store) Case(id string) (CaseProjection, error) { return s.caseProjectionUnlocked(id) }
func (s *Store) caseProjectionUnlocked(id string) (CaseProjection, error) {
	var p CaseProjection
	err := readStrictJSON(filepath.Join(s.Dir, "cases", id, "projection.json"), &p)
	return p, err
}

func (s *Store) VerifyCase(caseID string) (CaseProjection, error) {
	files, err := filepath.Glob(filepath.Join(s.Dir, "cases", caseID, "events", "*.json"))
	if err != nil || len(files) == 0 {
		return CaseProjection{}, errors.New("case has no events")
	}
	sort.Strings(files)
	var replay CaseProjection
	previous := ""
	for i, path := range files {
		var event CaseEvent
		if err := readStrictJSON(path, &event); err != nil {
			return CaseProjection{}, err
		}
		if event.Sequence != uint64(i+1) || event.Revision != uint64(i+1) || event.PreviousEventSHA256 != previous {
			return CaseProjection{}, fmt.Errorf("case event chain mismatch at sequence %d", event.Sequence)
		}
		base := event
		base.EventSHA256 = ""
		h, _ := HashObject(base)
		if h != event.EventSHA256 {
			return CaseProjection{}, fmt.Errorf("case event checksum mismatch at sequence %d", event.Sequence)
		}
		if event.Action == "case_created" {
			var payload struct {
				TenantID    string   `json:"tenant_id"`
				AlertIDs    []string `json:"alert_ids"`
				GroupingKey string   `json:"grouping_key"`
			}
			if err := json.Unmarshal(event.Payload, &payload); err != nil {
				return CaseProjection{}, err
			}
			replay = CaseProjection{SchemaVersion: CaseProjectionSchemaV1, CaseID: caseID, TenantID: payload.TenantID, AlertIDs: payload.AlertIDs, GroupingKey: payload.GroupingKey, State: "open", Revision: 1, CreatedAt: event.OccurredAt, UpdatedAt: event.OccurredAt, HeadEventSHA256: event.EventSHA256}
		} else {
			req := CaseEventRequest{CaseID: caseID, ExpectedRevision: replay.Revision, Action: event.Action, Actor: event.Actor, Reason: event.Reason, OccurredAt: event.OccurredAt, Payload: event.Payload, IdempotencyKey: "replay"}
			if err := applyTransition(&replay, req, event.OccurredAt); err != nil {
				return CaseProjection{}, fmt.Errorf("replay transition %d: %w", event.Sequence, err)
			}
			replay.Revision = event.Revision
			replay.UpdatedAt = event.OccurredAt
			replay.HeadEventSHA256 = event.EventSHA256
		}
		previous = event.EventSHA256
	}
	stored, err := s.caseProjectionUnlocked(caseID)
	if err != nil {
		return CaseProjection{}, err
	}
	a, _ := CanonicalJSON(replay)
	b, _ := CanonicalJSON(stored)
	if !bytes.Equal(a, b) {
		return CaseProjection{}, errors.New("stored case projection does not match event replay")
	}
	return replay, nil
}

func (s *Store) appendAuditUnlocked(occurredAt, action, actor, objectType, objectID string, details json.RawMessage) error {
	headPath := filepath.Join(s.Dir, "audit", "head.json")
	var head struct {
		Sequence    uint64 `json:"sequence"`
		AuditSHA256 string `json:"audit_sha256"`
	}
	if err := readStrictJSON(headPath, &head); err != nil && !os.IsNotExist(err) {
		return err
	}
	e := AuditEvent{SchemaVersion: AuditSchemaV1, StreamID: s.StreamID, Sequence: head.Sequence + 1, PreviousAuditSHA256: head.AuditSHA256, OccurredAt: occurredAt, Action: action, Actor: actor, ObjectType: objectType, ObjectID: objectID, Details: cloneRaw(details)}
	base := e
	base.AuditSHA256 = ""
	h, err := HashObject(base)
	if err != nil {
		return err
	}
	e.AuditSHA256 = h
	name := fmt.Sprintf("%020d-%s.json", e.Sequence, e.AuditSHA256)
	if err := writeJSONAtomic(filepath.Join(s.Dir, "audit", "events", name), e, 0o600); err != nil {
		return err
	}
	return writeJSONAtomic(headPath, map[string]any{"sequence": e.Sequence, "audit_sha256": e.AuditSHA256}, 0o600)
}

func (s *Store) VerifyAudit() (int, error) {
	files, err := filepath.Glob(filepath.Join(s.Dir, "audit", "events", "*.json"))
	if err != nil {
		return 0, err
	}
	sort.Strings(files)
	previous := ""
	for i, path := range files {
		var event AuditEvent
		if err := readStrictJSON(path, &event); err != nil {
			return 0, err
		}
		if event.Sequence != uint64(i+1) || event.PreviousAuditSHA256 != previous {
			return 0, fmt.Errorf("audit chain mismatch at sequence %d", event.Sequence)
		}
		base := event
		base.AuditSHA256 = ""
		h, _ := HashObject(base)
		if h != event.AuditSHA256 {
			return 0, fmt.Errorf("audit checksum mismatch at sequence %d", event.Sequence)
		}
		previous = event.AuditSHA256
	}
	return len(files), nil
}

func (s *Store) Status() (Status, error) {
	alerts, _ := filepath.Glob(filepath.Join(s.Dir, "alerts", "*.json"))
	cases, _ := filepath.Glob(filepath.Join(s.Dir, "cases", "*", "head.json"))
	audit, err := s.VerifyAudit()
	if err != nil {
		return Status{}, err
	}
	return Status{Status: "ok", AlertCount: len(alerts), CaseCount: len(cases), AuditCount: audit}, nil
}

func mustRaw(v any) json.RawMessage {
	raw, _ := CanonicalJSON(v)
	return raw
}

func (s *Store) Receipt(scope, key string) (IdempotencyReceipt, error) {
	var receipt IdempotencyReceipt
	err := readStrictJSON(s.receiptPath(scope, key), &receipt)
	return receipt, err
}

func (s *Store) LastCaseEvent(caseID string) (CaseEvent, error) {
	var head CaseHead
	if err := readStrictJSON(filepath.Join(s.Dir, "cases", caseID, "head.json"), &head); err != nil {
		return CaseEvent{}, err
	}
	return s.caseEventBySequenceUnlocked(caseID, head.Sequence)
}

func (s *Store) VerifyAlert(alertID string) (AlertRecord, error) {
	alert, err := s.Alert(alertID)
	if err != nil {
		return AlertRecord{}, err
	}
	base := alert
	declared := base.RecordSHA256
	base.RecordSHA256 = ""
	computed, err := HashObject(base)
	if err != nil {
		return AlertRecord{}, err
	}
	if computed != declared {
		return AlertRecord{}, errors.New("alert record checksum mismatch")
	}
	return alert, nil
}

func (s *Store) ReplayAlert(req CreateAlertRequest, expectedAlertID string) (AlertRecord, error) {
	alert, err := BuildAlert(s.Policy, req)
	if err != nil {
		return AlertRecord{}, err
	}
	stored, err := s.VerifyAlert(expectedAlertID)
	if err != nil {
		return AlertRecord{}, err
	}
	if alert.AlertID != stored.AlertID || alert.RecordSHA256 != stored.RecordSHA256 {
		return AlertRecord{}, errors.New("alert replay mismatch")
	}
	return stored, nil
}

func (s *Store) CreateAlertBatch(req CreateAlertBatchRequest) (AlertBatchResult, error) {
	if len(req.Requests) == 0 {
		return AlertBatchResult{}, errors.New("batch requests are required")
	}
	if req.IdempotencyKey == "" || req.CorrelationID == "" {
		return AlertBatchResult{}, errors.New("batch correlation_id and idempotency_key are required")
	}
	if _, err := normalizeTime(req.OccurredAt); err != nil {
		return AlertBatchResult{}, err
	}
	// Validate the complete batch before mutating durable state.
	for _, child := range req.Requests {
		if _, err := BuildAlert(s.Policy, child); err != nil {
			return AlertBatchResult{}, err
		}
	}
	var result AlertBatchResult
	receipt, err := s.checkReceipt("create-alert-batch", req.IdempotencyKey, req)
	if err != nil {
		return AlertBatchResult{}, err
	}
	if receipt != nil {
		path := filepath.Join(s.Dir, "idempotency", "batch-results", receipt.ObjectID+".json")
		if err := readStrictJSON(path, &result); err != nil {
			return AlertBatchResult{}, err
		}
		result.Replayed = true
		return result, nil
	}
	for _, child := range req.Requests {
		alert, _, err := s.CreateAlert(child)
		if err != nil {
			return AlertBatchResult{}, err
		}
		result.Alerts = append(result.Alerts, alert)
	}
	batchHash, _ := HashObject(result.Alerts)
	if err := writeJSONAtomic(filepath.Join(s.Dir, "idempotency", "batch-results", batchHash+".json"), result, 0o600); err != nil {
		return AlertBatchResult{}, err
	}
	if err := s.saveReceipt("create-alert-batch", req.IdempotencyKey, req, result, "alert_batch", batchHash, req.OccurredAt); err != nil {
		return AlertBatchResult{}, err
	}
	return result, nil
}
