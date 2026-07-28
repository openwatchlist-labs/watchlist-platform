package alertlistmapping

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/catalogregistry"
)

//go:embed migrations/0002_alert_list_mapping.sql
var postgresMigration string

func PostgresMigration() string { return postgresMigration }

type PostgresStore struct {
	DB        *sql.DB
	Namespace string
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
	if err := ValidateRegistry(registry, catalogregistry.Registry{}); err != nil {
		return err
	}
	_, err := s.DB.ExecContext(ctx, `
INSERT INTO alert_list_mapping_namespaces(namespace, mapping_registry_id, engine_version, last_sequence, audit_head)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (namespace) DO UPDATE SET
  engine_version = EXCLUDED.engine_version
WHERE alert_list_mapping_namespaces.mapping_registry_id = EXCLUDED.mapping_registry_id`,
		registry.Namespace, registry.RegistryID, registry.EngineVersion, registry.LastSequence, registry.AuditHead)
	return err
}

func (s PostgresStore) Register(ctx context.Context, key MappingKey, version MappingVersion, registry Registry, catalog catalogregistry.Registry) error {
	if s.DB == nil {
		return fmt.Errorf("postgres database is required")
	}
	if err := ValidateKey(key); err != nil {
		return err
	}
	if err := ValidateVersion(version, registry, catalog); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO alert_list_mapping_keys(
  mapping_id, mapping_registry_id, namespace, source_system_id, raw_list_name,
  created_at, created_by, key_checksum)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (mapping_id) DO NOTHING`,
		key.MappingID, key.RegistryID, key.Namespace, key.SourceSystemID, key.RawListName,
		key.CreatedAt, key.CreatedBy, key.KeyChecksum); err != nil {
		return err
	}
	var existingKeyChecksum string
	if err := tx.QueryRowContext(ctx, `SELECT key_checksum FROM alert_list_mapping_keys WHERE mapping_id=$1`, key.MappingID).Scan(&existingKeyChecksum); err != nil {
		return err
	}
	if existingKeyChecksum != key.KeyChecksum {
		return fmt.Errorf("immutable mapping key collision for %s", key.MappingID)
	}
	var effectiveTo any
	if version.EffectiveTo != nil {
		effectiveTo = *version.EffectiveTo
	}
	var componentID any
	if version.ComponentID != "" {
		componentID = version.ComponentID
	}
	var supersedes any
	if version.SupersedesVersionID != "" {
		supersedes = version.SupersedesVersionID
	}
	result, err := tx.ExecContext(ctx, `
INSERT INTO alert_list_mapping_versions(
  mapping_version_id, mapping_id, mapping_registry_id, namespace, sequence,
  source_system_id, raw_list_name, action, component_id, effective_from,
  effective_to, supersedes_version_id, reason, created_at, created_by,
  previous_event_hash, event_hash, version_checksum)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
ON CONFLICT (mapping_version_id) DO NOTHING`,
		version.MappingVersionID, version.MappingID, version.RegistryID, version.Namespace, version.Sequence,
		version.SourceSystemID, version.RawListName, version.Action, componentID, version.EffectiveFrom,
		effectiveTo, supersedes, version.Reason, version.CreatedAt, version.CreatedBy,
		version.PreviousEventHash, version.EventHash, version.VersionChecksum)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		var checksum string
		if err := tx.QueryRowContext(ctx, `SELECT version_checksum FROM alert_list_mapping_versions WHERE mapping_version_id=$1`, version.MappingVersionID).Scan(&checksum); err != nil {
			return err
		}
		if checksum != version.VersionChecksum {
			return fmt.Errorf("immutable mapping version collision for %s", version.MappingVersionID)
		}
		return tx.Commit()
	}
	update, err := tx.ExecContext(ctx, `
UPDATE alert_list_mapping_namespaces
SET last_sequence=$1, audit_head=$2, updated_at=now()
WHERE namespace=$3 AND last_sequence=$4 AND audit_head=$5`,
		version.Sequence, version.EventHash, version.Namespace, version.Sequence-1, version.PreviousEventHash)
	if err != nil {
		return err
	}
	updated, err := update.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return fmt.Errorf("mapping registry sequence precondition failed")
	}
	return tx.Commit()
}

func (s PostgresStore) ResolveExact(ctx context.Context, request ResolveRequest) (Resolution, error) {
	if s.DB == nil {
		return Resolution{}, fmt.Errorf("postgres database is required")
	}
	if !sourceSystemPattern.MatchString(request.SourceSystemID) {
		return Resolution{}, fmt.Errorf("invalid source_system_id")
	}
	if err := validateRawListName(request.RawListName); err != nil {
		return Resolution{}, err
	}
	if request.At.IsZero() {
		return Resolution{}, fmt.Errorf("resolution time is required")
	}
	if s.Namespace == "" {
		return Resolution{}, fmt.Errorf("mapping namespace is required")
	}
	at := request.At.UTC()
	result := Resolution{SchemaVersion: ResolutionSchemaVersion, SourceSystemID: request.SourceSystemID, RawListName: request.RawListName, ResolvedAt: at}
	var mappingID, registryID, namespace string
	err := s.DB.QueryRowContext(ctx, `
SELECT k.mapping_id, k.mapping_registry_id, k.namespace
FROM alert_list_mapping_keys k
WHERE k.namespace=$1 AND k.source_system_id=$2 AND k.raw_list_name=$3`, s.Namespace, request.SourceSystemID, request.RawListName).Scan(&mappingID, &registryID, &namespace)
	if err == sql.ErrNoRows {
		return blocked(result, ResolutionUnmapped, BlockerMappingRequired, false), nil
	}
	if err != nil {
		return Resolution{}, err
	}
	result.MappingRegistryID, result.Namespace, result.MappingID, result.ExactMatch = registryID, namespace, mappingID, true
	var versionID, action string
	var componentID sql.NullString
	var effectiveFrom time.Time
	var effectiveTo sql.NullTime
	err = s.DB.QueryRowContext(ctx, `
SELECT mapping_version_id, action, component_id, effective_from, effective_to
FROM alert_list_mapping_versions
WHERE mapping_id=$1 AND effective_from <= $2
ORDER BY effective_from DESC
LIMIT 1`, mappingID, at).Scan(&versionID, &action, &componentID, &effectiveFrom, &effectiveTo)
	if err == sql.ErrNoRows {
		return blocked(result, ResolutionNotEffective, BlockerMappingNotEffective, true), nil
	}
	if err != nil {
		return Resolution{}, err
	}
	result.MappingVersionID = versionID
	from := effectiveFrom.UTC()
	result.MappingEffectiveFrom = &from
	if effectiveTo.Valid {
		to := effectiveTo.Time.UTC()
		result.MappingEffectiveTo = &to
		if !at.Before(to) {
			return blocked(result, ResolutionExpired, BlockerMappingExpired, true), nil
		}
	}
	if MappingAction(action) == MappingActionRetire {
		return blocked(result, ResolutionRetired, BlockerMappingRetired, true), nil
	}
	if !componentID.Valid {
		return blocked(result, ResolutionComponentMissing, BlockerComponentMissing, true), nil
	}
	result.ComponentID = componentID.String
	var status, mode string
	var pointerVersionID, componentKey, displayName sql.NullString
	var catalogID, catalogVersion, catalogChecksum, artifactURI sql.NullString
	err = s.DB.QueryRowContext(ctx, `
SELECT c.component_key, c.display_name, c.catalog_mode, c.status,
       p.version_id, v.catalog_id, v.catalog_version, v.catalog_checksum, v.artifact_uri
FROM catalog_components c
LEFT JOIN active_catalog_component_versions p ON p.component_id=c.component_id
LEFT JOIN catalog_component_versions v ON v.version_id=p.version_id
WHERE c.component_id=$1`, componentID.String).Scan(
		&componentKey, &displayName, &mode, &status,
		&pointerVersionID, &catalogID, &catalogVersion, &catalogChecksum, &artifactURI)
	if err == sql.ErrNoRows {
		return blocked(result, ResolutionComponentMissing, BlockerComponentMissing, true), nil
	}
	if err != nil {
		return Resolution{}, err
	}
	result.ComponentKey, result.ComponentDisplayName, result.CatalogMode = componentKey.String, displayName.String, mode
	if status != string(catalogregistry.ComponentStatusActive) {
		return blocked(result, ResolutionComponentRetired, BlockerComponentRetired, true), nil
	}
	if !pointerVersionID.Valid {
		return blocked(result, ResolutionCatalogNotActive, BlockerCatalogNotActive, true), nil
	}
	result.Status, result.Available = ResolutionResolved, true
	result.ActiveCatalogVersionID = pointerVersionID.String
	result.ActiveCatalogID = catalogID.String
	result.ActiveCatalogVersion = catalogVersion.String
	result.ActiveCatalogChecksum = catalogChecksum.String
	result.ActiveArtifactURI = artifactURI.String
	return result, nil
}
