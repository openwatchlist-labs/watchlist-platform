package catalogregistry

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed migrations/0001_catalog_component_registry.sql
var postgresMigration string

// PostgresMigration returns the Phase 7C-B control-plane schema. The caller owns
// driver selection and connection lifecycle; catalog rows remain immutable file
// artifacts and are not inserted into PostgreSQL.
func PostgresMigration() string { return postgresMigration }

type PostgresStore struct {
	DB *sql.DB
}

func (s PostgresStore) ApplyMigration(ctx context.Context) error {
	if s.DB == nil {
		return fmt.Errorf("postgres database is required")
	}
	_, err := s.DB.ExecContext(ctx, postgresMigration)
	return err
}

func (s PostgresStore) Initialize(ctx context.Context, registry Registry) error {
	if s.DB == nil {
		return fmt.Errorf("postgres database is required")
	}
	if err := ValidateRegistry(registry); err != nil {
		return err
	}
	_, err := s.DB.ExecContext(ctx, `
INSERT INTO catalog_registry_namespaces(namespace, registry_id, engine_version, last_sequence, audit_head)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (namespace) DO UPDATE SET
  registry_id = EXCLUDED.registry_id,
  engine_version = EXCLUDED.engine_version
WHERE catalog_registry_namespaces.registry_id = EXCLUDED.registry_id`,
		registry.Namespace, registry.RegistryID, registry.EngineVersion, registry.LastSequence, registry.AuditHead)
	return err
}

func (s PostgresStore) RegisterComponent(ctx context.Context, component Component) error {
	if s.DB == nil {
		return fmt.Errorf("postgres database is required")
	}
	if err := ValidateComponent(component); err != nil {
		return err
	}
	labels, err := json.Marshal(component.Labels)
	if err != nil {
		return err
	}
	result, err := s.DB.ExecContext(ctx, `
INSERT INTO catalog_components(
  component_id, namespace, component_key, display_name, catalog_mode, status,
  description, labels, created_at, created_by, component_checksum)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
ON CONFLICT (component_id) DO NOTHING`,
		component.ComponentID, component.Namespace, component.ComponentKey, component.DisplayName,
		component.CatalogMode, component.Status, component.Description, labels, component.CreatedAt,
		component.CreatedBy, component.ComponentChecksum)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows == 1 {
		return err
	}
	var checksum string
	if err := s.DB.QueryRowContext(ctx, `SELECT component_checksum FROM catalog_components WHERE component_id=$1`, component.ComponentID).Scan(&checksum); err != nil {
		return err
	}
	if checksum != component.ComponentChecksum {
		return fmt.Errorf("immutable component collision for %s", component.ComponentID)
	}
	return nil
}

func (s PostgresStore) RegisterVersion(ctx context.Context, version CatalogVersion, component Component) error {
	if s.DB == nil {
		return fmt.Errorf("postgres database is required")
	}
	if err := ValidateVersion(version, component); err != nil {
		return err
	}
	source, err := json.Marshal(version.Source)
	if err != nil {
		return err
	}
	metadata, err := json.Marshal(version.Metadata)
	if err != nil {
		return err
	}
	var sourceManifestHash any
	if version.SourceManifestHash != "" {
		sourceManifestHash = version.SourceManifestHash
	}
	result, err := s.DB.ExecContext(ctx, `
INSERT INTO catalog_component_versions(
  version_id, component_id, catalog_id, catalog_version, catalog_checksum,
  catalog_schema, artifact_uri, artifact_sha256, source_manifest_id,
  source_manifest_checksum, record_count, producer_version, source_descriptor,
  metadata, registered_at, registered_by, version_checksum)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
ON CONFLICT (version_id) DO NOTHING`,
		version.VersionID, version.ComponentID, version.CatalogID, version.CatalogVersion,
		version.CatalogChecksum, version.CatalogSchema, version.ArtifactURI, version.ArtifactSHA256,
		version.SourceManifestID, sourceManifestHash, version.RecordCount, version.ProducerVersion,
		source, metadata, version.RegisteredAt, version.RegisteredBy, version.VersionChecksum)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows == 1 {
		return err
	}
	var checksum string
	if err := s.DB.QueryRowContext(ctx, `SELECT version_checksum FROM catalog_component_versions WHERE version_id=$1`, version.VersionID).Scan(&checksum); err != nil {
		return err
	}
	if checksum != version.VersionChecksum {
		return fmt.Errorf("immutable version collision for %s", version.VersionID)
	}
	return nil
}

// PersistActivation applies an already validated activation record and pointer
// in one transaction. Activation construction remains shared with the file store
// so both persistence implementations use identical IDs, epochs, and hash-chain
// semantics.
func (s PostgresStore) PersistActivation(ctx context.Context, record ActivationRecord, pointer ActivePointer) error {
	if s.DB == nil {
		return fmt.Errorf("postgres database is required")
	}
	if err := ValidatePointer(pointer); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var lastSequence uint64
	var auditHead string
	if err := tx.QueryRowContext(ctx, `
SELECT last_sequence, audit_head FROM catalog_registry_namespaces
WHERE registry_id=$1 FOR UPDATE`, record.RegistryID).Scan(&lastSequence, &auditHead); err != nil {
		return err
	}
	if record.Sequence != lastSequence+1 || record.PreviousEventHash != auditHead {
		return fmt.Errorf("postgres activation chain precondition failed")
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO catalog_component_activations(
  activation_id, namespace, sequence, component_id, action, target_version_id,
  previous_version_id, component_epoch, reason, activated_at, activated_by,
  previous_event_hash, event_hash)
SELECT $1, namespace, $2, $3, $4, $5, NULLIF($6,''), $7, $8, $9, $10, $11, $12
FROM catalog_registry_namespaces WHERE registry_id=$13`,
		record.ActivationID, record.Sequence, record.ComponentID, record.Action,
		record.TargetVersionID, record.PreviousVersionID, record.ComponentEpoch,
		record.Reason, record.ActivatedAt, record.ActivatedBy, record.PreviousEventHash,
		record.EventHash, record.RegistryID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO active_catalog_component_versions(component_id, version_id, activation_id, epoch, activated_at, activated_by)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (component_id) DO UPDATE SET
  version_id=EXCLUDED.version_id,
  activation_id=EXCLUDED.activation_id,
  epoch=EXCLUDED.epoch,
  activated_at=EXCLUDED.activated_at,
  activated_by=EXCLUDED.activated_by`,
		pointer.ComponentID, pointer.VersionID, pointer.ActivationID, pointer.Epoch,
		pointer.ActivatedAt, pointer.ActivatedBy); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE catalog_registry_namespaces SET last_sequence=$1, audit_head=$2
WHERE registry_id=$3`, record.Sequence, record.EventHash, record.RegistryID); err != nil {
		return err
	}
	return tx.Commit()
}
