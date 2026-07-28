package productionops

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type OutboxStore struct {
	dir, stream string
	mu          sync.Mutex
}

func NewOutboxStore(dir, stream string) (*OutboxStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("outbox directory is required")
	}
	if stream == "" {
		stream = "platform-outbox-phase9g"
	}
	for _, d := range []string{"messages", "receipts", "events"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0700); err != nil {
			return nil, err
		}
	}
	return &OutboxStore{dir: dir, stream: stream}, nil
}

func (s *OutboxStore) Enqueue(topic, tenant, key string, payload []byte, maxAttempts int, now time.Time) (OutboxMessage, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(topic) == "" || strings.TrimSpace(tenant) == "" || strings.TrimSpace(key) == "" {
		return OutboxMessage{}, false, errors.New("topic, tenant_id, and idempotency_key are required")
	}
	if !json.Valid(payload) {
		return OutboxMessage{}, false, errors.New("payload must be valid JSON")
	}
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	requestHash := sha256Hex(append([]byte(topic+"\x00"+tenant+"\x00"+key+"\x00"), payload...))
	rp := filepath.Join(s.dir, "receipts", safeName(topic+"__"+tenant+"__"+key)+".json")
	if b, err := os.ReadFile(rp); err == nil {
		var r OutboxReceipt
		if json.Unmarshal(b, &r) != nil {
			return OutboxMessage{}, false, errors.New("corrupt outbox receipt")
		}
		if r.RequestSHA256 != requestHash {
			return OutboxMessage{}, false, errors.New("outbox idempotency conflict")
		}
		m, err := s.message(r.MessageID)
		return m, true, err
	} else if !os.IsNotExist(err) {
		return OutboxMessage{}, false, err
	}
	payloadHash := sha256Hex(payload)
	id := "outbox_" + sha256Hex([]byte(topic + "\x00" + tenant + "\x00" + key + "\x00" + payloadHash))[:32]
	m := OutboxMessage{SchemaVersion: OutboxMessageSchemaV1, MessageID: id, Topic: topic, TenantID: tenant, IdempotencyKey: key, PayloadSHA256: payloadHash, Payload: append(json.RawMessage(nil), payload...), MaxAttempts: maxAttempts, CreatedAt: now.UTC().Format(time.RFC3339Nano)}
	h, err := outboxMessageHash(m)
	if err != nil {
		return m, false, err
	}
	m.MessageSHA256 = h
	if err = writeJSONExclusive(filepath.Join(s.dir, "messages", id+".json"), m); err != nil {
		return m, false, err
	}
	r := OutboxReceipt{Scope: "outbox:" + topic, IdempotencyKey: key, RequestSHA256: requestHash, MessageID: id, CreatedAt: m.CreatedAt}
	if err = writeJSONExclusive(rp, r); err != nil {
		return m, false, err
	}
	if _, err = s.appendEventLocked(id, "enqueued", 0, "", "", "", "", now); err != nil {
		return m, false, err
	}
	return m, false, nil
}

func outboxMessageHash(m OutboxMessage) (string, error) {
	x := m
	x.MessageSHA256 = ""
	return objectHash(x)
}
func outboxEventHash(e OutboxEvent) (string, error) { x := e; x.EventSHA256 = ""; return objectHash(x) }
func (s *OutboxStore) message(id string) (OutboxMessage, error) {
	var m OutboxMessage
	b, err := os.ReadFile(filepath.Join(s.dir, "messages", id+".json"))
	if err != nil {
		return m, err
	}
	if err = json.Unmarshal(b, &m); err != nil {
		return m, err
	}
	h, _ := outboxMessageHash(m)
	if h != m.MessageSHA256 {
		return OutboxMessage{}, errors.New("outbox message checksum mismatch")
	}
	return m, nil
}
func (s *OutboxStore) appendEventLocked(id, action string, attempt int, leaseHash, leaseExp, next, detail string, now time.Time) (OutboxEvent, error) {
	files, _ := filepath.Glob(filepath.Join(s.dir, "events", "*.json"))
	sort.Strings(files)
	seq := uint64(1)
	prev := ""
	if len(files) > 0 {
		var last OutboxEvent
		b, err := os.ReadFile(files[len(files)-1])
		if err != nil {
			return OutboxEvent{}, err
		}
		if json.Unmarshal(b, &last) != nil {
			return OutboxEvent{}, errors.New("corrupt outbox event")
		}
		seq = last.Sequence + 1
		prev = last.EventSHA256
	}
	e := OutboxEvent{SchemaVersion: OutboxEventSchemaV1, StreamID: s.stream, Sequence: seq, PreviousEventSHA256: prev, OccurredAt: now.UTC().Format(time.RFC3339Nano), MessageID: id, Action: action, Attempt: attempt, LeaseTokenHash: leaseHash, LeaseExpiresAt: leaseExp, NextAttemptAt: next, Detail: detail}
	h, err := outboxEventHash(e)
	if err != nil {
		return e, err
	}
	e.EventSHA256 = h
	return e, writeJSONExclusive(filepath.Join(s.dir, "events", fmt.Sprintf("%020d.json", seq)), e)
}
func (s *OutboxStore) events() (map[string][]OutboxEvent, []OutboxEvent, error) {
	files, _ := filepath.Glob(filepath.Join(s.dir, "events", "*.json"))
	sort.Strings(files)
	by := map[string][]OutboxEvent{}
	all := make([]OutboxEvent, 0, len(files))
	prev := ""
	for i, f := range files {
		var e OutboxEvent
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, err
		}
		if json.Unmarshal(b, &e) != nil {
			return nil, nil, errors.New("invalid outbox event JSON")
		}
		if e.Sequence != uint64(i+1) || e.PreviousEventSHA256 != prev {
			return nil, nil, errors.New("outbox event chain sequence mismatch")
		}
		h, _ := outboxEventHash(e)
		if h != e.EventSHA256 {
			return nil, nil, errors.New("outbox event checksum mismatch")
		}
		prev = e.EventSHA256
		by[e.MessageID] = append(by[e.MessageID], e)
		all = append(all, e)
	}
	return by, all, nil
}
func project(m OutboxMessage, ev []OutboxEvent) OutboxProjection {
	p := OutboxProjection{Message: m, State: "pending"}
	for _, e := range ev {
		p.Attempt = e.Attempt
		p.LastEventSHA256 = e.EventSHA256
		switch e.Action {
		case "enqueued", "recovered", "retry_scheduled":
			p.State = "pending"
			p.NextAttemptAt = e.NextAttemptAt
			p.LeaseExpiresAt = ""
		case "leased":
			p.State = "leased"
			p.LeaseExpiresAt = e.LeaseExpiresAt
		case "completed":
			p.State = "completed"
			p.LeaseExpiresAt = ""
		case "dead":
			p.State = "dead"
			p.LeaseExpiresAt = ""
		}
	}
	return p
}
func (s *OutboxStore) Claim(now time.Time, lease time.Duration) (OutboxProjection, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if lease <= 0 {
		lease = 30 * time.Second
	}
	if err := s.recoverLocked(now); err != nil {
		return OutboxProjection{}, "", err
	}
	by, _, err := s.events()
	if err != nil {
		return OutboxProjection{}, "", err
	}
	files, _ := filepath.Glob(filepath.Join(s.dir, "messages", "*.json"))
	sort.Strings(files)
	for _, f := range files {
		id := strings.TrimSuffix(filepath.Base(f), ".json")
		m, err := s.message(id)
		if err != nil {
			return OutboxProjection{}, "", err
		}
		p := project(m, by[id])
		if p.State != "pending" {
			continue
		}
		if p.NextAttemptAt != "" {
			t, _ := time.Parse(time.RFC3339Nano, p.NextAttemptAt)
			if now.Before(t) {
				continue
			}
		}
		attempt := p.Attempt + 1
		if attempt > m.MaxAttempts {
			if _, err = s.appendEventLocked(id, "dead", p.Attempt, "", "", "", "max attempts exceeded", now); err != nil {
				return OutboxProjection{}, "", err
			}
			continue
		}
		token := sha256Hex([]byte(id + now.UTC().Format(time.RFC3339Nano) + fmt.Sprint(attempt)))
		exp := now.Add(lease).UTC().Format(time.RFC3339Nano)
		e, err := s.appendEventLocked(id, "leased", attempt, sha256Hex([]byte(token)), exp, "", "", now)
		if err != nil {
			return OutboxProjection{}, "", err
		}
		p = project(m, append(by[id], e))
		return p, token, nil
	}
	return OutboxProjection{}, "", os.ErrNotExist
}
func (s *OutboxStore) Complete(id, token string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.finishLocked(id, token, "completed", "", 0, now)
}
func (s *OutboxStore) Retry(id, token, detail string, delay time.Duration, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.finishLocked(id, token, "retry_scheduled", detail, delay, now)
}
func (s *OutboxStore) finishLocked(id, token, action, detail string, delay time.Duration, now time.Time) error {
	m, err := s.message(id)
	if err != nil {
		return err
	}
	by, _, err := s.events()
	if err != nil {
		return err
	}
	ev := by[id]
	p := project(m, ev)
	if p.State != "leased" || len(ev) == 0 {
		return errors.New("message is not actively leased")
	}
	last := ev[len(ev)-1]
	if last.LeaseTokenHash != sha256Hex([]byte(token)) {
		return errors.New("lease token mismatch")
	}
	exp, _ := time.Parse(time.RFC3339Nano, last.LeaseExpiresAt)
	if now.After(exp) {
		return errors.New("lease expired")
	}
	next := ""
	if action == "retry_scheduled" {
		next = now.Add(delay).UTC().Format(time.RFC3339Nano)
	}
	_, err = s.appendEventLocked(id, action, p.Attempt, "", "", next, detail, now)
	return err
}
func (s *OutboxStore) recoverLocked(now time.Time) error {
	by, _, err := s.events()
	if err != nil {
		return err
	}
	for id, ev := range by {
		p := project(OutboxMessage{MessageID: id}, ev)
		if p.State == "leased" && p.LeaseExpiresAt != "" {
			t, _ := time.Parse(time.RFC3339Nano, p.LeaseExpiresAt)
			if !now.Before(t) {
				if _, err = s.appendEventLocked(id, "recovered", p.Attempt, "", "", "", "expired lease recovered", now); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func (s *OutboxStore) Recover(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recoverLocked(now)
}
func (s *OutboxStore) Status() (OutboxStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	by, all, err := s.events()
	if err != nil {
		return OutboxStatus{}, err
	}
	files, _ := filepath.Glob(filepath.Join(s.dir, "messages", "*.json"))
	st := OutboxStatus{Status: "ok", MessageCount: len(files), EventCount: len(all)}
	for _, f := range files {
		id := strings.TrimSuffix(filepath.Base(f), ".json")
		m, err := s.message(id)
		if err != nil {
			return st, err
		}
		switch project(m, by[id]).State {
		case "pending":
			st.PendingCount++
		case "leased":
			st.LeasedCount++
		case "completed":
			st.CompletedCount++
		case "dead":
			st.DeadCount++
		}
	}
	return st, nil
}
func (s *OutboxStore) Verify() (OutboxStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, _, err := s.events(); err != nil {
		return OutboxStatus{}, err
	}
	files, _ := filepath.Glob(filepath.Join(s.dir, "messages", "*.json"))
	for _, f := range files {
		if _, err := s.message(strings.TrimSuffix(filepath.Base(f), ".json")); err != nil {
			return OutboxStatus{}, err
		}
	}
	s.mu.Unlock()
	st, err := s.Status()
	s.mu.Lock()
	return st, err
}
func writeJSONExclusive(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	return err
}
func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
