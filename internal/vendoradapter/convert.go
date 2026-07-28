package vendoradapter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertcase"
)

type convertError struct{ code, msg string }

func (e convertError) Error() string { return e.msg }
func errorCode(err error) string {
	var e convertError
	if errors.As(err, &e) {
		return e.code
	}
	return "conversion_error"
}

func Convert(p Profile, sourceRef string, raw []byte, now time.Time) (Envelope, error) {
	if int64(len(raw)) > p.MaxSourceBytes {
		return Envelope{}, convertError{"source_too_large", fmt.Sprintf("source exceeds %d bytes", p.MaxSourceBytes)}
	}
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return Envelope{}, convertError{"invalid_json", err.Error()}
	}
	if doc == nil {
		return Envelope{}, convertError{"invalid_json", "top-level JSON object is required"}
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Envelope{}, convertError{"multiple_json_values", "multiple JSON values are not allowed"}
	}
	for _, path := range p.RequiredPaths {
		v, ok := lookup(doc, path)
		if !ok || isEmpty(v) {
			return Envelope{}, convertError{"missing_required_field", "missing required path " + path}
		}
	}
	traces := make([]MappingTrace, 0, len(p.Mappings)+len(p.Constants))
	vals := map[string]any{}
	for _, field := range canonicalFields {
		if path, ok := p.Mappings[field]; ok {
			v, found := lookup(doc, path)
			if found {
				vals[field] = v
				traces = append(traces, trace(field, path, v, "mapped"))
			} else {
				traces = append(traces, MappingTrace{CanonicalField: field, SourcePath: path, Status: "absent"})
			}
		}
		if v, ok := p.Constants[field]; ok {
			vals[field] = v
			traces = append(traces, trace(field, "$constant", v, "constant"))
		}
	}
	tenant, err := asRequiredString(vals["tenant_id"], "tenant_id")
	if err != nil {
		return Envelope{}, err
	}
	sourceSystem, err := asRequiredString(vals["source_system_id"], "source_system_id")
	if err != nil {
		return Envelope{}, err
	}
	sourceAlert, err := asRequiredString(vals["source_alert_id"], "source_alert_id")
	if err != nil {
		return Envelope{}, err
	}
	rawList, err := asRequiredString(vals["raw_list_name"], "raw_list_name")
	if err != nil {
		return Envelope{}, err
	}
	occurred, err := asRequiredString(vals["occurred_at"], "occurred_at")
	if err != nil {
		return Envelope{}, err
	}
	if _, e := time.Parse(time.RFC3339, occurred); e != nil {
		return Envelope{}, convertError{"invalid_occurred_at", e.Error()}
	}
	corr, err := asRequiredString(vals["correlation_id"], "correlation_id")
	if err != nil {
		return Envelope{}, err
	}
	idem, err := asRequiredString(vals["idempotency_key"], "idempotency_key")
	if err != nil {
		return Envelope{}, err
	}
	score, err := asScore(vals["external_score"])
	if err != nil {
		return Envelope{}, err
	}
	lm, ok := p.ListMappings[rawList]
	if !ok {
		return Envelope{}, convertError{"unmapped_list", "raw list name is not mapped: " + rawList}
	}
	resolution := map[string]any{"schema_version": "openwatchlist.alert-list-resolution.v1", "raw_list_name": rawList, "canonical_list_id": lm.CanonicalListID, "mapping_id": lm.MappingID, "mapping_version": lm.MappingVersion, "mapping_status": lm.Status, "adapter_profile_sha256": p.ProfileSHA256}
	resolutionRaw, _ := json.Marshal(resolution)
	evidence := map[string]string{}
	keys := make([]string, 0, len(p.AdditionalEvidence))
	for k := range p.AdditionalEvidence {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		path := p.AdditionalEvidence[k]
		if v, ok := lookup(doc, path); ok && !isEmpty(v) {
			s := fmt.Sprint(v)
			if len(s) > 256 {
				s = s[:256]
			}
			evidence[k] = s
			traces = append(traces, trace("additional_evidence."+k, path, v, "mapped"))
		}
	}
	subject := json.RawMessage(nil)
	if v, ok := vals["subject"]; ok && !isEmpty(v) {
		b, e := json.Marshal(v)
		if e != nil {
			return Envelope{}, e
		}
		subject = b
	}
	ext := &alertcase.ExternalAlert{SchemaVersion: alertcase.ExternalAlertSchemaV1, SourceSystemID: sourceSystem, SourceAlertID: sourceAlert, RawListName: rawList, OccurredAt: occurred, ExternalScore: score, ExternalReasons: asStrings(vals["external_reason_codes"]), MatchedFields: asStrings(vals["matched_fields"]), CandidateReferences: asStrings(vals["candidate_references"]), MessageReferences: asStrings(vals["message_references"]), AttachmentReferences: asStrings(vals["attachment_references"]), AlertListResolution: resolutionRaw, AdditionalEvidence: evidence}
	req := alertcase.CreateAlertRequest{TenantID: tenant, SourceType: "external_alert", ExternalAlert: ext, Subject: subject, CorrelationID: corr, IdempotencyKey: idem, OccurredAt: occurred}
	sort.Slice(traces, func(i, j int) bool {
		if traces[i].CanonicalField != traces[j].CanonicalField {
			return traces[i].CanonicalField < traces[j].CanonicalField
		}
		return traces[i].SourcePath < traces[j].SourcePath
	})
	sourceHash := SHA256Bytes(raw)
	recordBase := p.AdapterID + "\x00" + p.ProfileSHA256 + "\x00" + sourceSystem + "\x00" + sourceAlert + "\x00" + sourceHash
	e := Envelope{SchemaVersion: EnvelopeSchemaV1, RecordID: "vadp_" + SHA256String(recordBase)[:32], AdapterID: p.AdapterID, AdapterVersion: p.Version, Vendor: p.Vendor, ProfileSHA256: p.ProfileSHA256, SourceRef: sourceRef, SourceSHA256: sourceHash, MappingTrace: traces, CreateAlertRequest: req, ConvertedAt: now.UTC().Format(time.RFC3339)}
	h, err := envelopeHash(e)
	if err != nil {
		return Envelope{}, err
	}
	e.EnvelopeSHA256 = h
	return e, nil
}

func trace(field, path string, v any, status string) MappingTrace {
	b, _ := json.Marshal(v)
	return MappingTrace{CanonicalField: field, SourcePath: path, ValueSHA256: SHA256Bytes(b), Status: status}
}
func lookup(doc map[string]any, path string) (any, bool) {
	var cur any = doc
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}
func isEmpty(v any) bool {
	if v == nil {
		return true
	}
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s) == ""
	}
	return false
}
func asRequiredString(v any, field string) (string, error) {
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", convertError{"invalid_" + field, field + " must be a non-empty string"}
	}
	if len(s) > 512 {
		return "", convertError{"invalid_" + field, field + " exceeds 512 characters"}
	}
	return s, nil
}
func asScore(v any) (int, error) {
	if v == nil {
		return 0, nil
	}
	var n int64
	switch x := v.(type) {
	case json.Number:
		i, e := strconv.ParseInt(string(x), 10, 64)
		if e != nil {
			return 0, convertError{"invalid_score", "external_score must be an integer"}
		}
		n = i
	case float64:
		n = int64(x)
		if float64(n) != x {
			return 0, convertError{"invalid_score", "external_score must be an integer"}
		}
	case int:
		n = int64(x)
	default:
		return 0, convertError{"invalid_score", "external_score must be numeric"}
	}
	if n < 0 || n > 100 {
		return 0, convertError{"invalid_score", "external_score must be between 0 and 100"}
	}
	return int(n), nil
}
func asStrings(v any) []string {
	var out []string
	switch x := v.(type) {
	case []any:
		for _, item := range x {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
	case []string:
		out = append(out, x...)
	case string:
		if strings.TrimSpace(x) != "" {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	j := 0
	for _, s := range out {
		if j == 0 || out[j-1] != s {
			out[j] = s
			j++
		}
	}
	return out[:j]
}
