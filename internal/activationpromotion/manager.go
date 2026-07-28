package activationpromotion

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/scoringactivation"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type PrepareRequest struct {
	IntentID                   string
	CandidateActivationID      string
	Operator                   string
	Reason                     string
	CanaryBasisPoints          int
	CanaryCorrelationAllowlist []string
	RequiredReadyAcks          int
	Thresholds                 Thresholds
}

type Manager struct {
	directory   string
	activations *scoringactivation.Manager
	now         clock
}

func NewManager(directory string, activations *scoringactivation.Manager) (*Manager, error) {
	return newManager(directory, activations, time.Now)
}

func newManager(directory string, activations *scoringactivation.Manager, now clock) (*Manager, error) {
	if strings.TrimSpace(directory) == "" {
		return nil, errors.New("promotion state directory is required")
	}
	if activations == nil {
		return nil, errors.New("scoring activation manager is required")
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	return &Manager{directory: absolute, activations: activations, now: now}, nil
}

func (m *Manager) Directory() string { return m.directory }

func (m *Manager) Prepare(request PrepareRequest) (Status, error) {
	unlock, err := m.lock()
	if err != nil {
		return Status{}, err
	}
	defer unlock()
	if !identifierPattern.MatchString(request.IntentID) || !identifierPattern.MatchString(request.CandidateActivationID) {
		return Status{}, errors.New("intent_id and candidate_activation_id must be safe identifiers")
	}
	if strings.TrimSpace(request.Operator) == "" || strings.TrimSpace(request.Reason) == "" {
		return Status{}, errors.New("operator and reason are required")
	}
	if request.CanaryBasisPoints < 1 || request.CanaryBasisPoints > 5000 {
		return Status{}, errors.New("canary_basis_points must be between 1 and 5000")
	}
	if request.RequiredReadyAcks < 1 || request.RequiredReadyAcks > 10000 {
		return Status{}, errors.New("required_ready_acks must be between 1 and 10000")
	}
	if err := validateThresholds(request.Thresholds); err != nil {
		return Status{}, err
	}
	if _, err := m.loadState(); err == nil {
		return Status{}, errors.New("a promotion is already active")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Status{}, err
	}
	current, err := m.activations.LoadActive()
	if err != nil {
		return Status{}, err
	}
	candidate, err := m.activations.LoadActivation(request.CandidateActivationID)
	if err != nil {
		return Status{}, err
	}
	if candidate.Activation.ActivationID == current.Activation.ActivationID {
		return Status{}, errors.New("candidate activation must differ from current activation")
	}
	if candidate.Activation.PreviousActivationID != current.Activation.ActivationID {
		return Status{}, fmt.Errorf("candidate activation %q is not linked to current activation %q", candidate.Activation.ActivationID, current.Activation.ActivationID)
	}
	currentDigest, err := m.activations.ActivationDocumentSHA256(current.Activation.ActivationID)
	if err != nil {
		return Status{}, err
	}
	candidateDigest, err := m.activations.ActivationDocumentSHA256(candidate.Activation.ActivationID)
	if err != nil {
		return Status{}, err
	}
	allowlist := normalizedAllowlist(request.CanaryCorrelationAllowlist)
	intent := Intent{
		SchemaVersion:              IntentSchemaV1,
		IntentID:                   request.IntentID,
		CreatedAt:                  m.timestamp(),
		Operator:                   strings.TrimSpace(request.Operator),
		Reason:                     strings.TrimSpace(request.Reason),
		CurrentActivationID:        current.Activation.ActivationID,
		CurrentActivationSHA256:    currentDigest,
		CandidateActivationID:      candidate.Activation.ActivationID,
		CandidateActivationSHA256:  candidateDigest,
		CanaryBasisPoints:          request.CanaryBasisPoints,
		CanaryCorrelationAllowlist: allowlist,
		RequiredReadyAcks:          request.RequiredReadyAcks,
		Thresholds:                 request.Thresholds,
	}
	if err := m.writeImmutable(m.intentPath(intent.IntentID), intent); err != nil {
		return Status{}, err
	}
	state := State{
		SchemaVersion:         StateSchemaV1,
		IntentID:              intent.IntentID,
		Revision:              1,
		Phase:                 PhasePrepared,
		CurrentActivationID:   intent.CurrentActivationID,
		CandidateActivationID: intent.CandidateActivationID,
		UpdatedAt:             m.timestamp(),
	}
	if err := m.commitState(state, "promotion_prepared", intent.Operator, intent.Reason, map[string]any{
		"current_activation_id": intent.CurrentActivationID, "candidate_activation_id": intent.CandidateActivationID,
	}); err != nil {
		return Status{}, err
	}
	return m.statusLocked()
}

func (m *Manager) Evaluate(expectedRevision int64, summary ShadowSummary, actor, reason string) (Status, error) {
	unlock, err := m.lock()
	if err != nil {
		return Status{}, err
	}
	defer unlock()
	intent, state, err := m.intentAndState()
	if err != nil {
		return Status{}, err
	}
	if state.Revision != expectedRevision {
		return Status{}, revisionMismatch(expectedRevision, state.Revision)
	}
	if state.Phase != PhasePrepared && state.Phase != PhaseValidated && state.Phase != PhaseBlocked {
		return Status{}, fmt.Errorf("cannot evaluate promotion in phase %q", state.Phase)
	}
	if summary.IntentID != intent.IntentID || summary.SchemaVersion != ShadowSummaryV1 {
		return Status{}, errors.New("shadow summary does not match active promotion")
	}
	if err := verifySummary(summary); err != nil {
		return Status{}, err
	}
	blockers := evaluateSummary(intent.Thresholds, summary)
	if err := m.writeImmutable(m.reportPath(intent.IntentID, summary.SummarySHA256), summary); err != nil {
		return Status{}, err
	}
	state.Revision++
	state.UpdatedAt = m.timestamp()
	state.LastReportSHA256 = summary.SummarySHA256
	state.Blockers = blockers
	eventType := "promotion_validated"
	state.Phase = PhaseValidated
	if len(blockers) > 0 {
		state.Phase = PhaseBlocked
		eventType = "promotion_blocked"
	}
	if err := m.commitState(state, eventType, actor, reason, map[string]any{
		"summary_sha256": summary.SummarySHA256, "blockers": blockers,
	}); err != nil {
		return Status{}, err
	}
	return m.statusLocked()
}

func (m *Manager) StartCanary(expectedRevision int64, actor, reason string) (Status, error) {
	return m.transition(expectedRevision, PhaseValidated, PhaseCanary, "canary_started", actor, reason)
}

func (m *Manager) Acknowledge(ack Ack) (Status, error) {
	unlock, err := m.lock()
	if err != nil {
		return Status{}, err
	}
	defer unlock()
	intent, state, err := m.intentAndState()
	if err != nil {
		return Status{}, err
	}
	if state.Phase != PhaseCanary && state.Phase != PhaseValidated {
		return Status{}, fmt.Errorf("cannot acknowledge promotion in phase %q", state.Phase)
	}
	if ack.IntentID != intent.IntentID || !identifierPattern.MatchString(ack.InstanceID) {
		return Status{}, errors.New("ack intent_id or instance_id is invalid")
	}
	if ack.ActivationID != intent.CandidateActivationID {
		return Status{}, errors.New("ack activation_id does not match candidate activation")
	}
	if ack.Status != AckReady && ack.Status != AckNotReady {
		return Status{}, errors.New("ack status must be ready or not_ready")
	}
	if strings.TrimSpace(ack.TupleSHA256) == "" {
		return Status{}, errors.New("ack tuple_sha256 is required")
	}
	ack.SchemaVersion = AckSchemaV1
	ack.ObservedAt = m.timestamp()
	if err := m.writeImmutable(m.ackPath(intent.IntentID, ack.InstanceID), ack); err != nil {
		return Status{}, err
	}
	if err := m.appendAudit(m.nextAuditEvent("instance_acknowledged", state, ack.InstanceID, "", map[string]any{
		"status": ack.Status, "activation_id": ack.ActivationID, "tuple_sha256": ack.TupleSHA256,
	})); err != nil {
		return Status{}, err
	}
	return m.statusLocked()
}

func (m *Manager) Promote(expectedRevision int64, actor, reason string) (Status, error) {
	unlock, err := m.lock()
	if err != nil {
		return Status{}, err
	}
	defer unlock()
	intent, state, err := m.intentAndState()
	if err != nil {
		return Status{}, err
	}
	if state.Revision != expectedRevision {
		return Status{}, revisionMismatch(expectedRevision, state.Revision)
	}
	if state.Phase != PhaseCanary {
		return Status{}, fmt.Errorf("cannot promote in phase %q", state.Phase)
	}
	ready, err := m.readyAckCount(intent.IntentID, intent.CandidateActivationID)
	if err != nil {
		return Status{}, err
	}
	if ready < intent.RequiredReadyAcks {
		return Status{}, fmt.Errorf("promotion requires %d ready acknowledgements; found %d", intent.RequiredReadyAcks, ready)
	}
	if _, err := m.activations.PromoteExisting(intent.CandidateActivationID, intent.CurrentActivationID); err != nil {
		return Status{}, err
	}
	state.Revision++
	state.Phase = PhasePromoted
	state.UpdatedAt = m.timestamp()
	state.Blockers = nil
	if err := m.commitState(state, "promotion_completed", actor, reason, map[string]any{"ready_ack_count": ready}); err != nil {
		return Status{}, err
	}
	return m.statusLocked()
}

func (m *Manager) Rollback(expectedRevision int64, actor, reason string) (Status, error) {
	unlock, err := m.lock()
	if err != nil {
		return Status{}, err
	}
	defer unlock()
	intent, state, err := m.intentAndState()
	if err != nil {
		return Status{}, err
	}
	if state.Revision != expectedRevision {
		return Status{}, revisionMismatch(expectedRevision, state.Revision)
	}
	if state.Phase != PhasePromoted {
		return Status{}, fmt.Errorf("cannot rollback in phase %q", state.Phase)
	}
	if _, err := m.activations.PromoteExisting(intent.CurrentActivationID, intent.CandidateActivationID); err != nil {
		return Status{}, err
	}
	state.Revision++
	state.Phase = PhaseRolledBack
	state.UpdatedAt = m.timestamp()
	if err := m.commitState(state, "promotion_rolled_back", actor, reason, nil); err != nil {
		return Status{}, err
	}
	return m.statusLocked()
}

func (m *Manager) Status() (Status, error) {
	unlock, err := m.lock()
	if err != nil {
		return Status{}, err
	}
	defer unlock()
	return m.statusLocked()
}

func (m *Manager) Recover() (string, error) {
	unlock, err := m.lock()
	if err != nil {
		return "", err
	}
	defer unlock()
	var pending pendingDocument
	if err := decodeStrictFile(m.pendingPath(), &pending); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "clean", m.VerifyAudit()
		}
		return "", err
	}
	if pending.SchemaVersion != PendingSchemaV1 || pending.State.SchemaVersion != StateSchemaV1 {
		return "", errors.New("invalid pending promotion transaction")
	}
	if err := m.appendAudit(pending.AuditEvent); err != nil {
		return "", err
	}
	raw, _ := canonical(pending.State)
	if err := atomicWrite(m.statePath(), raw, 0o644); err != nil {
		return "", err
	}
	if err := os.Remove(m.pendingPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return "completed", nil
}

func (m *Manager) VerifyAudit() error {
	head, err := m.loadAuditHead()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	previous := ""
	for sequence := int64(1); sequence <= head.Sequence; sequence++ {
		matches, err := filepath.Glob(filepath.Join(m.auditDirectory(), fmt.Sprintf("%020d-*.json", sequence)))
		if err != nil || len(matches) != 1 {
			return fmt.Errorf("audit sequence %d is missing or ambiguous", sequence)
		}
		var event AuditEvent
		if err := decodeStrictFile(matches[0], &event); err != nil {
			return err
		}
		if event.Sequence != sequence || event.PreviousEventSHA256 != previous {
			return fmt.Errorf("audit chain mismatch at sequence %d", sequence)
		}
		if err := verifyAuditEvent(event); err != nil {
			return err
		}
		previous = event.EventSHA256
	}
	if previous != head.EventSHA256 {
		return errors.New("audit head does not match final event")
	}
	return nil
}

func (m *Manager) transition(expectedRevision int64, from, to, eventType, actor, reason string) (Status, error) {
	unlock, err := m.lock()
	if err != nil {
		return Status{}, err
	}
	defer unlock()
	_, state, err := m.intentAndState()
	if err != nil {
		return Status{}, err
	}
	if state.Revision != expectedRevision {
		return Status{}, revisionMismatch(expectedRevision, state.Revision)
	}
	if state.Phase != from {
		return Status{}, fmt.Errorf("cannot transition from phase %q; expected %q", state.Phase, from)
	}
	state.Revision++
	state.Phase = to
	state.UpdatedAt = m.timestamp()
	if err := m.commitState(state, eventType, actor, reason, nil); err != nil {
		return Status{}, err
	}
	return m.statusLocked()
}

func (m *Manager) statusLocked() (Status, error) {
	intent, state, err := m.intentAndState()
	if err != nil {
		return Status{}, err
	}
	ready, err := m.readyAckCount(intent.IntentID, intent.CandidateActivationID)
	if err != nil {
		return Status{}, err
	}
	head, err := m.loadAuditHead()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Status{}, err
	}
	return Status{Intent: intent, State: state, ReadyAckCount: ready, AuditHead: head}, nil
}

func (m *Manager) intentAndState() (Intent, State, error) {
	state, err := m.loadState()
	if err != nil {
		return Intent{}, State{}, err
	}
	var intent Intent
	if err := decodeStrictFile(m.intentPath(state.IntentID), &intent); err != nil {
		return Intent{}, State{}, err
	}
	if intent.SchemaVersion != IntentSchemaV1 || state.SchemaVersion != StateSchemaV1 || intent.IntentID != state.IntentID {
		return Intent{}, State{}, errors.New("invalid promotion intent/state binding")
	}
	return intent, state, nil
}

func (m *Manager) loadState() (State, error) {
	var state State
	if err := decodeStrictFile(m.statePath(), &state); err != nil {
		return State{}, err
	}
	return state, nil
}

func (m *Manager) commitState(state State, eventType, actor, reason string, payload map[string]any) error {
	if err := os.MkdirAll(m.directory, 0o755); err != nil {
		return err
	}
	if err := m.writeImmutable(m.stateSnapshotPath(state.IntentID, state.Revision), state); err != nil {
		return err
	}
	event := m.nextAuditEvent(eventType, state, actor, reason, payload)
	pending := pendingDocument{SchemaVersion: PendingSchemaV1, State: state, AuditEvent: event}
	pendingRaw, _ := canonical(pending)
	if err := atomicWrite(m.pendingPath(), pendingRaw, 0o644); err != nil {
		return err
	}
	if err := m.appendAudit(event); err != nil {
		return err
	}
	stateRaw, _ := canonical(state)
	if err := atomicWrite(m.statePath(), stateRaw, 0o644); err != nil {
		return err
	}
	return os.Remove(m.pendingPath())
}

func (m *Manager) writeImmutable(path string, value any) error {
	raw, err := canonical(value)
	if err != nil {
		return err
	}
	if existing, err := os.ReadFile(path); err == nil {
		if !bytes.Equal(existing, raw) {
			return fmt.Errorf("immutable file %s already exists with different bytes", path)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return atomicWrite(path, raw, 0o644)
}

func (m *Manager) readyAckCount(intentID, activationID string) (int, error) {
	paths, err := filepath.Glob(filepath.Join(m.directory, "acks", intentID, "*.json"))
	if err != nil {
		return 0, err
	}
	ready := 0
	for _, path := range paths {
		var ack Ack
		if err := decodeStrictFile(path, &ack); err != nil {
			return 0, err
		}
		if ack.SchemaVersion == AckSchemaV1 && ack.IntentID == intentID && ack.ActivationID == activationID && ack.Status == AckReady {
			ready++
		}
	}
	return ready, nil
}

func normalizedAllowlist(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func validateThresholds(thresholds Thresholds) error {
	if thresholds.MaxScoreDelta < 0 || thresholds.MaxScoreDelta > 1000 ||
		thresholds.MaxTopCandidateChangeBPS < 0 || thresholds.MaxTopCandidateChangeBPS > 10000 ||
		thresholds.MaxCandidateSetChangeBPS < 0 || thresholds.MaxCandidateSetChangeBPS > 10000 ||
		thresholds.MaxCoverageLossCount < 0 || thresholds.MaxAdditionalBlockerCount < 0 {
		return errors.New("promotion thresholds are out of range")
	}
	return nil
}

func evaluateSummary(thresholds Thresholds, summary ShadowSummary) []string {
	var blockers []string
	if summary.MaxAbsoluteScoreDelta > thresholds.MaxScoreDelta {
		blockers = append(blockers, "max_score_delta_exceeded")
	}
	if summary.TopCandidateChangeBPS > thresholds.MaxTopCandidateChangeBPS {
		blockers = append(blockers, "top_candidate_change_rate_exceeded")
	}
	if summary.CandidateSetChangeBPS > thresholds.MaxCandidateSetChangeBPS {
		blockers = append(blockers, "candidate_set_change_rate_exceeded")
	}
	if summary.CoverageLossCount > thresholds.MaxCoverageLossCount {
		blockers = append(blockers, "coverage_loss_exceeded")
	}
	if summary.AdditionalBlockerCount > thresholds.MaxAdditionalBlockerCount {
		blockers = append(blockers, "additional_blocker_count_exceeded")
	}
	return blockers
}

func revisionMismatch(expected, actual int64) error {
	return fmt.Errorf("promotion revision CAS mismatch: expected %d, found %d", expected, actual)
}

func (m *Manager) timestamp() string   { return m.now().UTC().Format(time.RFC3339Nano) }
func (m *Manager) statePath() string   { return filepath.Join(m.directory, "promotion.json") }
func (m *Manager) pendingPath() string { return filepath.Join(m.directory, "pending.json") }
func (m *Manager) intentPath(id string) string {
	return filepath.Join(m.directory, "intents", id+".json")
}
func (m *Manager) stateSnapshotPath(id string, revision int64) string {
	return filepath.Join(m.directory, "states", id, fmt.Sprintf("%020d.json", revision))
}
func (m *Manager) reportPath(id, sha string) string {
	return filepath.Join(m.directory, "reports", id, sha+".json")
}
func (m *Manager) ackPath(id, instance string) string {
	return filepath.Join(m.directory, "acks", id, instance+".json")
}
func (m *Manager) auditDirectory() string { return filepath.Join(m.directory, "audit") }
func (m *Manager) auditHeadPath() string  { return filepath.Join(m.directory, "audit-head.json") }
func (m *Manager) lockPath() string       { return filepath.Join(m.directory, ".lock") }

func (m *Manager) lock() (func(), error) {
	if err := os.MkdirAll(m.directory, 0o755); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(m.lockPath(), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, errors.New("promotion state is locked by another operation")
		}
		return nil, err
	}
	_, _ = file.WriteString(fmt.Sprintf("pid=%d\n", os.Getpid()))
	_ = file.Close()
	return func() { _ = os.Remove(m.lockPath()) }, nil
}
