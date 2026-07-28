package ofacsource

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

func assignManifestID(m SourceManifest) (SourceManifest, error) {
	m.ManifestID = ""
	b, err := json.Marshal(m)
	if err != nil {
		return SourceManifest{}, fmt.Errorf("marshal manifest identity: %w", err)
	}
	s := sha256.Sum256(b)
	m.ManifestID = "ofac_source_" + hex.EncodeToString(s[:12])
	return m, nil
}

// AssignManifestID returns a copy of m with the deterministic manifest identity assigned.
func AssignManifestID(m SourceManifest) (SourceManifest, error) { return assignManifestID(m) }
