package iso20022coverage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

func LoadMatrix(path string) (*Matrix, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read matrix: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Matrix
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("decode matrix: %w", err)
	}
	if dec.More() {
		return nil, errors.New("decode matrix: trailing JSON values")
	}
	if err := validateMatrix(&m); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	m.SHA256 = hex.EncodeToString(sum[:])
	return &m, nil
}

func validateMatrix(m *Matrix) error {
	if m.SchemaVersion != "openwatchlist.iso20022-support-matrix.v1" {
		return fmt.Errorf("unsupported matrix schema_version %q", m.SchemaVersion)
	}
	if strings.TrimSpace(m.MatrixID) == "" || strings.TrimSpace(m.Version) == "" {
		return errors.New("matrix_id and version are required")
	}
	if len(m.Families) == 0 {
		return errors.New("matrix must contain at least one family")
	}
	seenProfile := map[string]bool{}
	seenKey := map[string]bool{}
	for i, f := range m.Families {
		if f.ProfileID == "" || f.MessageDefinitionID == "" || f.Namespace == "" || f.RootElement == "" {
			return fmt.Errorf("families[%d] missing required identity", i)
		}
		if f.SupportLevel != "end_to_end" && f.SupportLevel != "evidence_only" {
			return fmt.Errorf("families[%d] invalid support_level %q", i, f.SupportLevel)
		}
		if seenProfile[f.ProfileID] {
			return fmt.Errorf("duplicate profile_id %q", f.ProfileID)
		}
		seenProfile[f.ProfileID] = true
		key := f.Namespace + "\x00" + f.RootElement + "\x00" + f.ContainsElement
		if seenKey[key] {
			return fmt.Errorf("duplicate family discriminator for %q", f.ProfileID)
		}
		seenKey[key] = true
		if len(f.TransactionContainers) == 0 {
			return fmt.Errorf("families[%d] requires transaction_containers", i)
		}
	}
	return nil
}

func (m *Matrix) SortedProfiles() []FamilyProfile {
	out := append([]FamilyProfile(nil), m.Families...)
	sort.Slice(out, func(i, j int) bool { return out[i].ProfileID < out[j].ProfileID })
	return out
}
