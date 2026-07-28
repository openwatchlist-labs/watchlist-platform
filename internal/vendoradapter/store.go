package vendoradapter

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

type Store struct {
	dir, stream string
	clock       Clock
	mu          sync.Mutex
}

func NewStore(dir, stream string, clock Clock) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("state directory is required")
	}
	if stream == "" {
		stream = "vendor-adapter"
	}
	if clock == nil {
		clock = time.Now
	}
	for _, d := range []string{"records", "receipts", "audit"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0700); err != nil {
			return nil, err
		}
	}
	return &Store{dir: dir, stream: stream, clock: clock}, nil
}

func (s *Store) Process(p Profile, sourceRef string, raw []byte) (Envelope, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, err := Convert(p, sourceRef, raw, s.clock())
	if err != nil {
		return Envelope{}, false, err
	}
	key := e.CreateAlertRequest.IdempotencyKey
	scope := "ingest:" + p.AdapterID
	rp := filepath.Join(s.dir, "receipts", safe(scope+"__"+key)+".json")
	if b, err := os.ReadFile(rp); err == nil {
		var r Receipt
		if json.Unmarshal(b, &r) != nil {
			return Envelope{}, false, errors.New("corrupt idempotency receipt")
		}
		if r.SourceSHA256 != e.SourceSHA256 {
			return Envelope{}, false, fmt.Errorf("idempotency conflict for %s", key)
		}
		stored, err := s.record(r.RecordID)
		return stored, true, err
	} else if !os.IsNotExist(err) {
		return Envelope{}, false, err
	}
	ep := filepath.Join(s.dir, "records", e.RecordID+".json")
	if _, err := os.Stat(ep); err == nil {
		return Envelope{}, false, errors.New("record exists without idempotency receipt")
	}
	if err := writeExclusive(ep, e); err != nil {
		return Envelope{}, false, err
	}
	r := Receipt{SchemaVersion: ReceiptSchemaV1, Scope: scope, IdempotencyKey: key, SourceSHA256: e.SourceSHA256, RecordID: e.RecordID, CreatedAt: s.clock().UTC().Format(time.RFC3339)}
	if err := writeExclusive(rp, r); err != nil {
		return Envelope{}, false, err
	}
	details, _ := json.Marshal(map[string]string{"adapter_id": p.AdapterID, "profile_sha256": p.ProfileSHA256, "source_sha256": e.SourceSHA256, "envelope_sha256": e.EnvelopeSHA256})
	if _, err := s.appendAudit("vendor_alert_ingested", "vendor_adapter_record", e.RecordID, details); err != nil {
		return Envelope{}, false, err
	}
	return e, false, nil
}

func (s *Store) record(id string) (Envelope, error) {
	var e Envelope
	b, err := os.ReadFile(filepath.Join(s.dir, "records", id+".json"))
	if err != nil {
		return e, err
	}
	if err := json.Unmarshal(b, &e); err != nil {
		return e, err
	}
	h, err := envelopeHash(e)
	if err != nil || h != e.EnvelopeSHA256 {
		return Envelope{}, errors.New("record checksum mismatch")
	}
	return e, nil
}
func (s *Store) Record(id string) (Envelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.record(id)
}
func (s *Store) Receipt(adapterID, key string) (Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var r Receipt
	b, err := os.ReadFile(filepath.Join(s.dir, "receipts", safe("ingest:"+adapterID+"__"+key)+".json"))
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(b, &r)
	return r, err
}
func (s *Store) appendAudit(action, objType, objID string, details json.RawMessage) (AuditEvent, error) {
	files, _ := filepath.Glob(filepath.Join(s.dir, "audit", "*.json"))
	sort.Strings(files)
	var prev string
	var seq uint64 = 1
	if len(files) > 0 {
		var last AuditEvent
		b, err := os.ReadFile(files[len(files)-1])
		if err != nil {
			return AuditEvent{}, err
		}
		if err := json.Unmarshal(b, &last); err != nil {
			return AuditEvent{}, err
		}
		prev = last.AuditSHA256
		seq = last.Sequence + 1
	}
	a := AuditEvent{SchemaVersion: AuditSchemaV1, StreamID: s.stream, Sequence: seq, PreviousAuditSHA256: prev, OccurredAt: s.clock().UTC().Format(time.RFC3339), Action: action, ObjectType: objType, ObjectID: objID, Details: details}
	h, err := auditHash(a)
	if err != nil {
		return a, err
	}
	a.AuditSHA256 = h
	return a, writeExclusive(filepath.Join(s.dir, "audit", fmt.Sprintf("%020d.json", seq)), a)
}
func (s *Store) Verify() (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	records, _ := filepath.Glob(filepath.Join(s.dir, "records", "*.json"))
	receipts, _ := filepath.Glob(filepath.Join(s.dir, "receipts", "*.json"))
	audits, _ := filepath.Glob(filepath.Join(s.dir, "audit", "*.json"))
	sort.Strings(audits)
	var prev string
	for i, f := range audits {
		var a AuditEvent
		b, err := os.ReadFile(f)
		if err != nil {
			return Status{}, err
		}
		if err := json.Unmarshal(b, &a); err != nil {
			return Status{}, err
		}
		if a.Sequence != uint64(i+1) || a.PreviousAuditSHA256 != prev {
			return Status{}, errors.New("audit chain sequence mismatch")
		}
		h, _ := auditHash(a)
		if h != a.AuditSHA256 {
			return Status{}, errors.New("audit checksum mismatch")
		}
		prev = a.AuditSHA256
	}
	for _, f := range records {
		var e Envelope
		b, err := os.ReadFile(f)
		if err != nil {
			return Status{}, err
		}
		if json.Unmarshal(b, &e) != nil {
			return Status{}, errors.New("invalid record JSON")
		}
		h, _ := envelopeHash(e)
		if h != e.EnvelopeSHA256 {
			return Status{}, errors.New("record checksum mismatch")
		}
	}
	return Status{Status: "ok", RecordCount: len(records), ReceiptCount: len(receipts), AuditCount: len(audits)}, nil
}
func writeExclusive(path string, v any) error {
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
	return err
}
func safe(s string) string {
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
