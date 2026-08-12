package vendoradapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var canonicalFields = []string{"tenant_id", "source_system_id", "source_alert_id", "raw_list_name", "occurred_at", "external_score", "external_reason_codes", "matched_fields", "candidate_references", "message_references", "attachment_references", "subject", "correlation_id", "idempotency_key"}

func LoadProfile(path string) (Profile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, err
	}
	var p Profile
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Profile{}, fmt.Errorf("profile: %w", err)
	}
	if err := ValidateProfile(&p); err != nil {
		return Profile{}, err
	}
	return p, nil
}

func LoadProfiles(dir string) (map[string]Profile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]Profile{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var header struct {
			SchemaVersion string `json:"schema_version"`
		}
		if err := json.Unmarshal(raw, &header); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if header.SchemaVersion == "" {
			continue
		}
		if header.SchemaVersion != ProfileSchemaV1 {
			return nil, fmt.Errorf("%s: unsupported profile schema %q", e.Name(), header.SchemaVersion)
		}
		p, err := LoadProfile(path)
		if err != nil {
			return nil, err
		}
		if _, ok := out[p.AdapterID]; ok {
			return nil, fmt.Errorf("duplicate adapter_id %s", p.AdapterID)
		}
		out[p.AdapterID] = p
	}
	if len(out) == 0 {
		return nil, errors.New("no adapter profiles found")
	}
	return out, nil
}

func ValidateProfile(p *Profile) error {
	if p.SchemaVersion != ProfileSchemaV1 {
		return fmt.Errorf("unsupported profile schema %q", p.SchemaVersion)
	}
	if p.AdapterID == "" || p.Version == "" || p.Vendor == "" {
		return errors.New("profile requires adapter_id, version and vendor")
	}
	if p.InputFormat != "json-object" {
		return fmt.Errorf("unsupported input_format %q", p.InputFormat)
	}
	if p.MaxSourceBytes <= 0 || p.MaxSourceBytes > 16<<20 {
		return errors.New("max_source_bytes must be between 1 and 16777216")
	}
	if _, ok := p.Mappings["tenant_id"]; ok {
		return errors.New("tenant_id must be declared in constants only, not mappings (ADR-0006 D2): a vendor-payload value cannot be allowed to name its own tenant")
	}
	for _, f := range []string{"tenant_id", "source_system_id", "source_alert_id", "raw_list_name", "occurred_at", "correlation_id", "idempotency_key"} {
		if p.Mappings[f] == "" {
			if _, ok := p.Constants[f]; !ok {
				return fmt.Errorf("missing mapping for %s", f)
			}
		}
	}
	if v, ok := p.Constants["tenant_id"]; ok {
		if s, ok := v.(string); !ok || strings.TrimSpace(s) == "" {
			return errors.New("constants.tenant_id must be a non-empty string")
		}
	}
	allowed := map[string]bool{}
	for _, f := range canonicalFields {
		allowed[f] = true
	}
	for k, v := range p.Mappings {
		if !allowed[k] {
			return fmt.Errorf("unsupported canonical mapping %s", k)
		}
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("empty source path for %s", k)
		}
	}
	for k, v := range p.AdditionalEvidence {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			return errors.New("additional evidence keys and paths must be non-empty")
		}
	}
	if len(p.AdditionalEvidence) > 32 {
		return errors.New("at most 32 additional evidence mappings are allowed")
	}
	if len(p.ListMappings) == 0 {
		return errors.New("list_mappings is required")
	}
	for raw, m := range p.ListMappings {
		if strings.TrimSpace(raw) == "" || m.CanonicalListID == "" || m.MappingID == "" || m.MappingVersion == "" || m.Status != "active" {
			return fmt.Errorf("invalid active list mapping for %q", raw)
		}
	}
	h, err := profileHash(*p)
	if err != nil {
		return err
	}
	if p.ProfileSHA256 == "" {
		p.ProfileSHA256 = h
	} else if p.ProfileSHA256 != h {
		return fmt.Errorf("profile_sha256 mismatch: declared %s computed %s", p.ProfileSHA256, h)
	}
	sort.Strings(p.RequiredPaths)
	return nil
}

func ProfileSummary(profiles map[string]Profile) []map[string]any {
	ids := make([]string, 0, len(profiles))
	for id := range profiles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		p := profiles[id]
		out = append(out, map[string]any{"adapter_id": p.AdapterID, "version": p.Version, "vendor": p.Vendor, "profile_sha256": p.ProfileSHA256})
	}
	return out
}
