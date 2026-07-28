package catalogruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	GenerationStampSchemaVersion  = "catalog-generation-stamp/v1alpha1"
	ReadinessReportSchemaVersion  = "catalog-readiness-report/v1alpha1"
	ActivationRecordSchemaVersion = "catalog-activation-record/v1alpha1"
	RollbackRecordSchemaVersion   = "catalog-rollback-record/v1alpha1"
	ActivePointerSchemaVersion    = "catalog-active-pointer/v1alpha1"
)

var (
	ErrInvalidGenerationStamp = errors.New("invalid catalog generation stamp")
	ErrInvalidReadiness       = errors.New("invalid catalog readiness report")
	ErrInvalidActivation      = errors.New("invalid catalog activation record")
	ErrInvalidRollback        = errors.New("invalid catalog rollback record")
)

type ActivationAction string

const (
	ActivationActionActivate ActivationAction = "activate"
	ActivationActionRollback ActivationAction = "rollback"
)

type CheckStatus string

const (
	CheckPass CheckStatus = "pass"
	CheckFail CheckStatus = "fail"
)

type GenerationStamp struct {
	SchemaVersion    string    `json:"schema_version"`
	GenerationID     string    `json:"generation_id"`
	ActivationEpoch  uint64    `json:"activation_epoch"`
	PackageID        string    `json:"package_id"`
	PackageChecksum  string    `json:"package_checksum"`
	CatalogID        string    `json:"catalog_id"`
	CatalogVersion   string    `json:"catalog_version"`
	CatalogChecksum  string    `json:"catalog_checksum"`
	SourceManifestID string    `json:"source_manifest_id"`
	CompiledAt       time.Time `json:"compiled_at"`
	ActivatedAt      time.Time `json:"activated_at"`
}

type ReadinessCheck struct {
	Name   string      `json:"name"`
	Status CheckStatus `json:"status"`
	Detail string      `json:"detail"`
}

type ReadinessReport struct {
	SchemaVersion    string           `json:"schema_version"`
	ReportID         string           `json:"report_id"`
	PackageID        string           `json:"package_id"`
	PackageChecksum  string           `json:"package_checksum"`
	CatalogID        string           `json:"catalog_id"`
	CatalogVersion   string           `json:"catalog_version"`
	CatalogChecksum  string           `json:"catalog_checksum"`
	SourceManifestID string           `json:"source_manifest_id"`
	CheckedAt        time.Time        `json:"checked_at"`
	Ready            bool             `json:"ready"`
	Checks           []ReadinessCheck `json:"checks"`
}

type PackageActivationInput struct {
	PackageID        string
	PackageChecksum  string
	CatalogID        string
	CatalogVersion   string
	CatalogChecksum  string
	SourceManifestID string
	CompiledAt       time.Time
}

type ActivationRecord struct {
	SchemaVersion     string           `json:"schema_version"`
	ActivationID      string           `json:"activation_id"`
	Action            ActivationAction `json:"action"`
	ReadinessReportID string           `json:"readiness_report_id"`
	ActivatedAt       time.Time        `json:"activated_at"`
	Previous          *GenerationStamp `json:"previous_generation,omitempty"`
	Active            GenerationStamp  `json:"active_generation"`
}

type RollbackRecord struct {
	SchemaVersion   string          `json:"schema_version"`
	RollbackID      string          `json:"rollback_id"`
	Reason          string          `json:"reason"`
	RequestedAt     time.Time       `json:"requested_at"`
	ActivationID    string          `json:"activation_id"`
	FromGeneration  GenerationStamp `json:"from_generation"`
	TargetPackageID string          `json:"target_package_id"`
	NewGeneration   GenerationStamp `json:"new_generation"`
}

type ActivePointer struct {
	SchemaVersion string          `json:"schema_version"`
	Generation    GenerationStamp `json:"generation"`
}

func StampFromMetadata(m GenerationMetadata) (GenerationStamp, error) {
	stamp := GenerationStamp{
		SchemaVersion:    GenerationStampSchemaVersion,
		GenerationID:     m.GenerationID,
		ActivationEpoch:  m.ActivationEpoch,
		PackageID:        m.PackageID,
		PackageChecksum:  m.PackageChecksum,
		CatalogID:        m.CatalogID,
		CatalogVersion:   m.CatalogVersion,
		CatalogChecksum:  m.CatalogChecksum,
		SourceManifestID: m.SourceManifestID,
		CompiledAt:       m.CompiledAt,
		ActivatedAt:      m.ActivatedAt,
	}
	if err := ValidateGenerationStamp(stamp); err != nil {
		return GenerationStamp{}, err
	}
	return stamp, nil
}

func ValidateGenerationStamp(stamp GenerationStamp) error {
	if stamp.SchemaVersion != GenerationStampSchemaVersion {
		return fmt.Errorf("%w: schema_version must be %q", ErrInvalidGenerationStamp, GenerationStampSchemaVersion)
	}
	for field, value := range map[string]string{
		"generation_id":      stamp.GenerationID,
		"package_id":         stamp.PackageID,
		"package_checksum":   stamp.PackageChecksum,
		"catalog_id":         stamp.CatalogID,
		"catalog_version":    stamp.CatalogVersion,
		"catalog_checksum":   stamp.CatalogChecksum,
		"source_manifest_id": stamp.SourceManifestID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidGenerationStamp, field)
		}
	}
	if stamp.ActivationEpoch == 0 || stamp.CompiledAt.IsZero() || stamp.ActivatedAt.IsZero() {
		return fmt.Errorf("%w: activation_epoch, compiled_at, and activated_at are required", ErrInvalidGenerationStamp)
	}
	if err := validateSHA256(stamp.PackageChecksum, "package_checksum", ErrInvalidGenerationStamp); err != nil {
		return err
	}
	if err := validateSHA256(stamp.CatalogChecksum, "catalog_checksum", ErrInvalidGenerationStamp); err != nil {
		return err
	}
	return nil
}

func NewReadinessReport(input PackageActivationInput, checkedAt time.Time, checks []ReadinessCheck) (ReadinessReport, error) {
	if checkedAt.IsZero() {
		return ReadinessReport{}, fmt.Errorf("%w: checked_at is required", ErrInvalidReadiness)
	}
	copied := append([]ReadinessCheck(nil), checks...)
	ready := len(copied) > 0
	for _, check := range copied {
		if check.Status != CheckPass {
			ready = false
		}
	}
	report := ReadinessReport{
		SchemaVersion:    ReadinessReportSchemaVersion,
		PackageID:        input.PackageID,
		PackageChecksum:  input.PackageChecksum,
		CatalogID:        input.CatalogID,
		CatalogVersion:   input.CatalogVersion,
		CatalogChecksum:  input.CatalogChecksum,
		SourceManifestID: input.SourceManifestID,
		CheckedAt:        checkedAt.UTC(),
		Ready:            ready,
		Checks:           copied,
	}
	report.ReportID = readinessID(report)
	if err := ValidateReadinessReport(report); err != nil {
		return ReadinessReport{}, err
	}
	return report, nil
}

func ValidateReadinessReport(report ReadinessReport) error {
	if report.SchemaVersion != ReadinessReportSchemaVersion {
		return fmt.Errorf("%w: invalid schema_version", ErrInvalidReadiness)
	}
	for field, value := range map[string]string{
		"report_id":          report.ReportID,
		"package_id":         report.PackageID,
		"package_checksum":   report.PackageChecksum,
		"catalog_id":         report.CatalogID,
		"catalog_version":    report.CatalogVersion,
		"catalog_checksum":   report.CatalogChecksum,
		"source_manifest_id": report.SourceManifestID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidReadiness, field)
		}
	}
	if report.CheckedAt.IsZero() || len(report.Checks) == 0 {
		return fmt.Errorf("%w: checked_at and checks are required", ErrInvalidReadiness)
	}
	if err := validateSHA256(report.PackageChecksum, "package_checksum", ErrInvalidReadiness); err != nil {
		return err
	}
	if err := validateSHA256(report.CatalogChecksum, "catalog_checksum", ErrInvalidReadiness); err != nil {
		return err
	}
	seen := map[string]struct{}{}
	expectedReady := true
	for index, check := range report.Checks {
		if strings.TrimSpace(check.Name) == "" || strings.TrimSpace(check.Detail) == "" {
			return fmt.Errorf("%w: checks[%d] name and detail are required", ErrInvalidReadiness, index)
		}
		if _, ok := seen[check.Name]; ok {
			return fmt.Errorf("%w: duplicate check %q", ErrInvalidReadiness, check.Name)
		}
		seen[check.Name] = struct{}{}
		if check.Status != CheckPass && check.Status != CheckFail {
			return fmt.Errorf("%w: checks[%d] invalid status %q", ErrInvalidReadiness, index, check.Status)
		}
		if check.Status != CheckPass {
			expectedReady = false
		}
	}
	if report.Ready != expectedReady {
		return fmt.Errorf("%w: ready does not match checks", ErrInvalidReadiness)
	}
	if expected := readinessID(report); report.ReportID != expected {
		return fmt.Errorf("%w: report_id=%q expected %q", ErrInvalidReadiness, report.ReportID, expected)
	}
	return nil
}

func BuildActivation(previous *GenerationStamp, input PackageActivationInput, readinessReportID string, action ActivationAction, reason string, at time.Time) (ActivationRecord, *RollbackRecord, error) {
	if action != ActivationActionActivate && action != ActivationActionRollback {
		return ActivationRecord{}, nil, fmt.Errorf("%w: unsupported action %q", ErrInvalidActivation, action)
	}
	if strings.TrimSpace(readinessReportID) == "" || at.IsZero() {
		return ActivationRecord{}, nil, fmt.Errorf("%w: readiness_report_id and activated_at are required", ErrInvalidActivation)
	}
	if action == ActivationActionRollback && (previous == nil || strings.TrimSpace(reason) == "") {
		return ActivationRecord{}, nil, fmt.Errorf("%w: rollback requires previous generation and reason", ErrInvalidRollback)
	}
	epoch := uint64(1)
	if previous != nil {
		if err := ValidateGenerationStamp(*previous); err != nil {
			return ActivationRecord{}, nil, err
		}
		epoch = previous.ActivationEpoch + 1
	}
	activated := at.UTC()
	stamp := GenerationStamp{
		SchemaVersion:    GenerationStampSchemaVersion,
		ActivationEpoch:  epoch,
		PackageID:        input.PackageID,
		PackageChecksum:  input.PackageChecksum,
		CatalogID:        input.CatalogID,
		CatalogVersion:   input.CatalogVersion,
		CatalogChecksum:  input.CatalogChecksum,
		SourceManifestID: input.SourceManifestID,
		CompiledAt:       input.CompiledAt.UTC(),
		ActivatedAt:      activated,
	}
	stamp.GenerationID = generationID(stamp, action)
	if err := ValidateGenerationStamp(stamp); err != nil {
		return ActivationRecord{}, nil, err
	}
	record := ActivationRecord{
		SchemaVersion:     ActivationRecordSchemaVersion,
		Action:            action,
		ReadinessReportID: readinessReportID,
		ActivatedAt:       activated,
		Previous:          previous,
		Active:            stamp,
	}
	record.ActivationID = activationID(record)
	if err := ValidateActivationRecord(record); err != nil {
		return ActivationRecord{}, nil, err
	}
	if action != ActivationActionRollback {
		return record, nil, nil
	}
	rollback := &RollbackRecord{
		SchemaVersion:   RollbackRecordSchemaVersion,
		Reason:          strings.TrimSpace(reason),
		RequestedAt:     activated,
		ActivationID:    record.ActivationID,
		FromGeneration:  *previous,
		TargetPackageID: input.PackageID,
		NewGeneration:   stamp,
	}
	rollback.RollbackID = rollbackID(*rollback)
	if err := ValidateRollbackRecord(*rollback); err != nil {
		return ActivationRecord{}, nil, err
	}
	return record, rollback, nil
}

func ValidateActivationRecord(record ActivationRecord) error {
	if record.SchemaVersion != ActivationRecordSchemaVersion || strings.TrimSpace(record.ActivationID) == "" || strings.TrimSpace(record.ReadinessReportID) == "" || record.ActivatedAt.IsZero() {
		return fmt.Errorf("%w: invalid header", ErrInvalidActivation)
	}
	if record.Action != ActivationActionActivate && record.Action != ActivationActionRollback {
		return fmt.Errorf("%w: unsupported action", ErrInvalidActivation)
	}
	if err := ValidateGenerationStamp(record.Active); err != nil {
		return fmt.Errorf("%w: active_generation: %v", ErrInvalidActivation, err)
	}
	if !record.ActivatedAt.Equal(record.Active.ActivatedAt) {
		return fmt.Errorf("%w: activated_at differs from active generation", ErrInvalidActivation)
	}
	if record.Previous != nil {
		if err := ValidateGenerationStamp(*record.Previous); err != nil {
			return fmt.Errorf("%w: previous_generation: %v", ErrInvalidActivation, err)
		}
		if record.Active.ActivationEpoch != record.Previous.ActivationEpoch+1 {
			return fmt.Errorf("%w: activation epoch is not monotonic", ErrInvalidActivation)
		}
	} else if record.Active.ActivationEpoch != 1 {
		return fmt.Errorf("%w: first activation epoch must be 1", ErrInvalidActivation)
	}
	if expected := activationID(record); record.ActivationID != expected {
		return fmt.Errorf("%w: activation_id=%q expected %q", ErrInvalidActivation, record.ActivationID, expected)
	}
	return nil
}

func ValidateRollbackRecord(record RollbackRecord) error {
	if record.SchemaVersion != RollbackRecordSchemaVersion || strings.TrimSpace(record.RollbackID) == "" || strings.TrimSpace(record.Reason) == "" || strings.TrimSpace(record.ActivationID) == "" || strings.TrimSpace(record.TargetPackageID) == "" || record.RequestedAt.IsZero() {
		return fmt.Errorf("%w: invalid header", ErrInvalidRollback)
	}
	if err := ValidateGenerationStamp(record.FromGeneration); err != nil {
		return fmt.Errorf("%w: from_generation: %v", ErrInvalidRollback, err)
	}
	if err := ValidateGenerationStamp(record.NewGeneration); err != nil {
		return fmt.Errorf("%w: new_generation: %v", ErrInvalidRollback, err)
	}
	if record.TargetPackageID != record.NewGeneration.PackageID || record.NewGeneration.ActivationEpoch != record.FromGeneration.ActivationEpoch+1 {
		return fmt.Errorf("%w: target package or activation epoch mismatch", ErrInvalidRollback)
	}
	if expected := rollbackID(record); record.RollbackID != expected {
		return fmt.Errorf("%w: rollback_id=%q expected %q", ErrInvalidRollback, record.RollbackID, expected)
	}
	return nil
}

func (r *Registry) ActivatePackage(input PackageActivationInput, payload any, readinessReportID string, at time.Time) (ActivationRecord, *Generation, error) {
	return r.activatePackage(input, payload, readinessReportID, ActivationActionActivate, "", at)
}

func (r *Registry) RollbackPackage(input PackageActivationInput, payload any, readinessReportID, reason string, at time.Time) (ActivationRecord, RollbackRecord, *Generation, error) {
	record, retired, rollback, err := r.activatePackageWithRollback(input, payload, readinessReportID, reason, at)
	if err != nil {
		return ActivationRecord{}, RollbackRecord{}, nil, err
	}
	return record, rollback, retired, nil
}

func (r *Registry) activatePackage(input PackageActivationInput, payload any, readinessReportID string, action ActivationAction, reason string, at time.Time) (ActivationRecord, *Generation, error) {
	record, retired, _, err := r.activatePackageLocked(input, payload, readinessReportID, action, reason, at)
	return record, retired, err
}

func (r *Registry) activatePackageWithRollback(input PackageActivationInput, payload any, readinessReportID, reason string, at time.Time) (ActivationRecord, *Generation, RollbackRecord, error) {
	record, retired, rollback, err := r.activatePackageLocked(input, payload, readinessReportID, ActivationActionRollback, reason, at)
	if err != nil {
		return ActivationRecord{}, nil, RollbackRecord{}, err
	}
	if rollback == nil {
		return ActivationRecord{}, nil, RollbackRecord{}, fmt.Errorf("%w: rollback record missing", ErrInvalidRollback)
	}
	return record, retired, *rollback, nil
}

func (r *Registry) activatePackageLocked(input PackageActivationInput, payload any, readinessReportID string, action ActivationAction, reason string, at time.Time) (ActivationRecord, *Generation, *RollbackRecord, error) {
	if payload == nil {
		return ActivationRecord{}, nil, nil, fmt.Errorf("%w: payload is required", ErrInvalidActivation)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var previous *GenerationStamp
	old := r.active.Load()
	if old != nil {
		stamp, err := StampFromMetadata(old.metadata)
		if err != nil {
			return ActivationRecord{}, nil, nil, fmt.Errorf("%w: active generation is not package-backed: %v", ErrInvalidActivation, err)
		}
		previous = &stamp
	}
	record, rollback, err := BuildActivation(previous, input, readinessReportID, action, reason, at)
	if err != nil {
		return ActivationRecord{}, nil, nil, err
	}
	if record.Active.ActivationEpoch != r.epoch.Load()+1 {
		return ActivationRecord{}, nil, nil, fmt.Errorf("%w: registry epoch differs from active generation", ErrInvalidActivation)
	}
	g := &Generation{
		metadata: GenerationMetadata{
			SchemaVersion:    GenerationSchemaVersion,
			GenerationID:     record.Active.GenerationID,
			PackageID:        record.Active.PackageID,
			PackageChecksum:  record.Active.PackageChecksum,
			CatalogID:        record.Active.CatalogID,
			CatalogVersion:   record.Active.CatalogVersion,
			CatalogChecksum:  record.Active.CatalogChecksum,
			SourceManifestID: record.Active.SourceManifestID,
			CompiledAt:       record.Active.CompiledAt,
			ActivatedAt:      record.Active.ActivatedAt,
			ActivationEpoch:  record.Active.ActivationEpoch,
		},
		payload: payload,
		drained: make(chan struct{}),
	}
	r.epoch.Store(record.Active.ActivationEpoch)
	retired := r.active.Swap(g)
	if retired != nil {
		retired.retired.Store(true)
		retired.signal()
	}
	return record, retired, rollback, nil
}

func generationID(stamp GenerationStamp, action ActivationAction) string {
	return digest("generation_", []string{stamp.PackageID, stamp.PackageChecksum, strconv.FormatUint(stamp.ActivationEpoch, 10), stamp.ActivatedAt.Format(time.RFC3339Nano), string(action)})
}

func readinessID(report ReadinessReport) string {
	parts := []string{ReadinessReportSchemaVersion, report.PackageID, report.PackageChecksum, report.CatalogID, report.CatalogVersion, report.CatalogChecksum, report.SourceManifestID, report.CheckedAt.Format(time.RFC3339Nano), strconv.FormatBool(report.Ready)}
	for _, check := range report.Checks {
		parts = append(parts, check.Name, string(check.Status), check.Detail)
	}
	return digest("readiness_", parts)
}

func activationID(record ActivationRecord) string {
	parts := []string{ActivationRecordSchemaVersion, string(record.Action), record.ReadinessReportID, record.ActivatedAt.Format(time.RFC3339Nano), record.Active.GenerationID}
	if record.Previous != nil {
		parts = append(parts, record.Previous.GenerationID)
	}
	return digest("activation_", parts)
}

func rollbackID(record RollbackRecord) string {
	return digest("rollback_", []string{RollbackRecordSchemaVersion, record.Reason, record.RequestedAt.Format(time.RFC3339Nano), record.ActivationID, record.FromGeneration.GenerationID, record.TargetPackageID, record.NewGeneration.GenerationID})
}

func digest(prefix string, parts []string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return prefix + hex.EncodeToString(sum[:12])
}

func validateSHA256(value, field string, sentinel error) error {
	if len(value) != 64 {
		return fmt.Errorf("%w: %s must be a 64-character SHA-256 digest", sentinel, field)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("%w: %s is not hexadecimal", sentinel, field)
	}
	return nil
}
