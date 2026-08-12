package vendoradapter

import "testing"

// baseValidProfile returns a minimal Profile that passes ValidateProfile
// unmodified, so each test below can mutate exactly the field under test.
func baseValidProfile() Profile {
	return Profile{
		SchemaVersion:  ProfileSchemaV1,
		AdapterID:      "test-adapter",
		Version:        "v1",
		Vendor:         "test",
		InputFormat:    "json-object",
		MaxSourceBytes: 1024,
		Mappings: map[string]string{
			"source_system_id": "system",
			"source_alert_id":  "alert_id",
			"raw_list_name":    "list_name",
			"occurred_at":      "occurred_at",
			"correlation_id":   "correlation_id",
			"idempotency_key":  "idempotency_key",
		},
		Constants: map[string]any{
			"tenant_id": "tenant-a",
		},
		ListMappings: map[string]ListResolution{
			"OFAC SDN": {CanonicalListID: "ofac-sdn", MappingID: "m1", MappingVersion: "r1", Status: "active"},
		},
	}
}

// TestValidateProfileRejectsMappedTenantID is the regression test for
// ADR-0006 D2: tenant_id must be Constants-only. A profile that still maps
// tenant_id out of the vendor payload must fail to load, so the mixed state
// (a mapped value and a declared constant disagreeing) is unreachable by
// construction rather than resolved at request time (ADR-0006 §4).
func TestValidateProfileRejectsMappedTenantID(t *testing.T) {
	p := baseValidProfile()
	p.Mappings["tenant_id"] = "tenant_id"
	if err := ValidateProfile(&p); err == nil {
		t.Fatal("ValidateProfile with mappings.tenant_id set = nil error, want a rejection (ADR-0006 D2)")
	}
}

// TestValidateProfileAcceptsConstantTenantID is the positive counterpart:
// a profile declaring tenant_id only in constants loads cleanly.
func TestValidateProfileAcceptsConstantTenantID(t *testing.T) {
	p := baseValidProfile()
	if err := ValidateProfile(&p); err != nil {
		t.Fatalf("ValidateProfile with constants.tenant_id set = %v, want nil", err)
	}
}

// TestValidateProfileRejectsMissingTenantID guards against a profile that
// declares tenant_id in neither mappings nor constants: it must still fail
// the existing required-field rule, not silently pass now that mappings is
// off the table.
func TestValidateProfileRejectsMissingTenantID(t *testing.T) {
	p := baseValidProfile()
	delete(p.Constants, "tenant_id")
	if err := ValidateProfile(&p); err == nil {
		t.Fatal("ValidateProfile with no tenant_id source = nil error, want a rejection")
	}
}
