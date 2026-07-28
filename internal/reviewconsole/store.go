package reviewconsole

import (
	"encoding/json"
	"errors"
	"github.com/openwatchlist-labs/watchlist-platform/internal/alertcase"
	"github.com/openwatchlist-labs/watchlist-platform/internal/assistancerag"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type CaseFilter struct {
	State, AssignedTo string
	Limit             int
}

func ListCases(dir, tenant string, f CaseFilter) ([]alertcase.CaseProjection, error) {
	if tenant == "" {
		return nil, errors.New("tenant is required")
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	paths, e := filepath.Glob(filepath.Join(dir, "cases", "*", "projection.json"))
	if e != nil {
		return nil, e
	}
	o := []alertcase.CaseProjection{}
	for _, p := range paths {
		var x alertcase.CaseProjection
		if e = read(p, &x); e != nil {
			return nil, e
		}
		if x.TenantID != tenant || f.State != "" && x.State != f.State || f.AssignedTo != "" && x.AssignedTo != f.AssignedTo {
			continue
		}
		o = append(o, x)
	}
	sort.Slice(o, func(i, j int) bool {
		if o[i].UpdatedAt == o[j].UpdatedAt {
			return o[i].CaseID < o[j].CaseID
		}
		return o[i].UpdatedAt > o[j].UpdatedAt
	})
	if len(o) > f.Limit {
		o = o[:f.Limit]
	}
	return o, nil
}
func ListAlerts(dir, tenant string, limit int) ([]alertcase.AlertRecord, error) {
	if tenant == "" {
		return nil, errors.New("tenant is required")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	paths, e := filepath.Glob(filepath.Join(dir, "alerts", "*.json"))
	if e != nil {
		return nil, e
	}
	o := []alertcase.AlertRecord{}
	for _, p := range paths {
		var x alertcase.AlertRecord
		if e = read(p, &x); e != nil {
			return nil, e
		}
		if x.TenantID == tenant {
			o = append(o, x)
		}
	}
	sort.Slice(o, func(i, j int) bool { return o[i].CreatedAt > o[j].CreatedAt })
	if len(o) > limit {
		o = o[:limit]
	}
	return o, nil
}
func ListAssistance(dir, tenant, cid string, limit int) ([]assistancerag.AssistanceRecord, error) {
	if tenant == "" || cid == "" {
		return nil, errors.New("tenant and case ID are required")
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	paths, e := filepath.Glob(filepath.Join(dir, "assistance", "*.json"))
	if e != nil {
		return nil, e
	}
	o := []assistancerag.AssistanceRecord{}
	for _, p := range paths {
		var x assistancerag.AssistanceRecord
		if e = read(p, &x); e != nil {
			return nil, e
		}
		if x.TenantID == tenant && x.CaseID == cid {
			o = append(o, x)
		}
	}
	sort.Slice(o, func(i, j int) bool { return o[i].OccurredAt > o[j].OccurredAt })
	if len(o) > limit {
		o = o[:limit]
	}
	return o, nil
}
func ParseLimit(v string, d, max int) int {
	n, e := strconv.Atoi(strings.TrimSpace(v))
	if e != nil || n <= 0 {
		return d
	}
	if n > max {
		return max
	}
	return n
}
func read(p string, d any) error {
	b, e := os.ReadFile(p)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, d)
}
