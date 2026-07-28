package screeningapiv8d

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/candidatescoring"
)

const projectionRegistrySchemaV1 = "openwatchlist.candidate-projection-registry.v1"

type projectionRegistryDocument struct {
	SchemaVersion string                       `json:"schema_version"`
	Candidates    []candidatescoring.Candidate `json:"candidates"`
}

// ProjectionRegistry contains only the bounded attributes required by scoring.
type ProjectionRegistry struct {
	byID   map[string]candidatescoring.Candidate
	sha256 string
}

func LoadProjectionRegistry(path string) (*ProjectionRegistry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read projection registry: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc projectionRegistryDocument
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode projection registry: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, errors.New("decode projection registry: trailing JSON value")
		}
		return nil, fmt.Errorf("decode projection registry trailing content: %w", err)
	}
	if doc.SchemaVersion != projectionRegistrySchemaV1 {
		return nil, fmt.Errorf("projection schema_version %q is not %q", doc.SchemaVersion, projectionRegistrySchemaV1)
	}
	sort.Slice(doc.Candidates, func(i, j int) bool { return doc.Candidates[i].CandidateID < doc.Candidates[j].CandidateID })
	byID := make(map[string]candidatescoring.Candidate, len(doc.Candidates))
	for _, candidate := range doc.Candidates {
		id := strings.TrimSpace(candidate.CandidateID)
		if id == "" {
			return nil, errors.New("projection candidate_id is required")
		}
		if _, exists := byID[id]; exists {
			return nil, fmt.Errorf("duplicate projection candidate_id %q", id)
		}
		candidate.CandidateID = id
		byID[id] = candidate
	}
	canonical, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical projection registry: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return &ProjectionRegistry{byID: byID, sha256: hex.EncodeToString(digest[:])}, nil
}

func (r *ProjectionRegistry) SHA256() string { return r.sha256 }

func (r *ProjectionRegistry) Get(id string) (candidatescoring.Candidate, bool) {
	candidate, ok := r.byID[strings.TrimSpace(id)]
	return candidate, ok
}
