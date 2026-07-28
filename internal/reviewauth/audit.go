package reviewauth

import (
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

type SecurityAuditStore struct{ Dir, StreamID string }

func NewSecurityAuditStore(dir, stream string) (*SecurityAuditStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("security audit directory is required")
	}
	if stream == "" {
		stream = "review-console-security"
	}
	if e := os.MkdirAll(filepath.Join(dir, "events"), 0700); e != nil {
		return nil, e
	}
	return &SecurityAuditStore{dir, stream}, nil
}
func (s *SecurityAuditStore) withLock(fn func() error) error {
	lock := filepath.Join(s.Dir, ".lock")
	end := time.Now().Add(10 * time.Second)
	for {
		if e := os.Mkdir(lock, 0700); e == nil {
			defer os.Remove(lock)
			return fn()
		} else if !os.IsExist(e) {
			return e
		}
		if time.Now().After(end) {
			return errors.New("timed out waiting for security audit lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func (s *SecurityAuditStore) Append(e SecurityAuditEvent) (SecurityAuditEvent, error) {
	var out SecurityAuditEvent
	err := s.withLock(func() error {
		paths, x := filepath.Glob(filepath.Join(s.Dir, "events", "*.json"))
		if x != nil {
			return x
		}
		sort.Strings(paths)
		e.SchemaVersion = SecurityAuditSchemaV1
		e.StreamID = s.StreamID
		e.Sequence = uint64(len(paths) + 1)
		if len(paths) > 0 {
			var p SecurityAuditEvent
			if x = readJSON(paths[len(paths)-1], &p); x != nil {
				return x
			}
			e.PreviousEventSHA256 = p.EventSHA256
		}
		if e.OccurredAt == "" {
			e.OccurredAt = time.Now().UTC().Format(time.RFC3339Nano)
		} else {
			e.OccurredAt, x = NormalizeTime(e.OccurredAt)
			if x != nil {
				return x
			}
		}
		c := e
		c.EventSHA256 = ""
		e.EventSHA256, x = HashObject(c)
		if x != nil {
			return x
		}
		if x = writeJSONAtomic(filepath.Join(s.Dir, "events", fmt.Sprintf("%020d.json", e.Sequence)), e, 0600); x != nil {
			return x
		}
		out = e
		return nil
	})
	return out, err
}
func (s *SecurityAuditStore) Verify() (AuditStatus, error) {
	paths, e := filepath.Glob(filepath.Join(s.Dir, "events", "*.json"))
	if e != nil {
		return AuditStatus{}, e
	}
	sort.Strings(paths)
	prev := ""
	for i, p := range paths {
		var x SecurityAuditEvent
		if e = readJSON(p, &x); e != nil {
			return AuditStatus{}, e
		}
		if x.SchemaVersion != SecurityAuditSchemaV1 || x.StreamID != s.StreamID || x.Sequence != uint64(i+1) || x.PreviousEventSHA256 != prev {
			return AuditStatus{}, fmt.Errorf("security audit chain mismatch at sequence %d", i+1)
		}
		c := x
		want := c.EventSHA256
		c.EventSHA256 = ""
		got, z := HashObject(c)
		if z != nil {
			return AuditStatus{}, z
		}
		if want != got {
			return AuditStatus{}, fmt.Errorf("security audit checksum mismatch at sequence %d", i+1)
		}
		prev = x.EventSHA256
	}
	return AuditStatus{"ok", len(paths), prev}, nil
}
func (s *SecurityAuditStore) List(limit int) ([]SecurityAuditEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	paths, e := filepath.Glob(filepath.Join(s.Dir, "events", "*.json"))
	if e != nil {
		return nil, e
	}
	sort.Sort(sort.Reverse(sort.StringSlice(paths)))
	if len(paths) > limit {
		paths = paths[:limit]
	}
	o := make([]SecurityAuditEvent, 0, len(paths))
	for _, p := range paths {
		var x SecurityAuditEvent
		if e = readJSON(p, &x); e != nil {
			return nil, e
		}
		o = append(o, x)
	}
	return o, nil
}
func readJSON(p string, d any) error {
	b, e := os.ReadFile(p)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, d)
}
func writeJSONAtomic(p string, v any, m os.FileMode) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	b = append(b, '\n')
	t := p + ".tmp." + strconv.Itoa(os.Getpid())
	if e = os.WriteFile(t, b, m); e != nil {
		return e
	}
	return os.Rename(t, p)
}
