package providerrefresh

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed migrations/0003_provider_refresh_governance.sql
var postgresMigration string

func PostgresMigration() string { return postgresMigration }

type PostgresRepository struct{ DB *sql.DB }

func (r PostgresRepository) PersistCandidate(ctx context.Context, candidate RefreshCandidate) error {
	if r.DB == nil {
		return fmt.Errorf("database is required")
	}
	policy, _ := json.Marshal(candidate.Policy)
	changes, _ := json.Marshal(candidate.Changes)
	impacts, _ := json.Marshal(candidate.MappingImpacts)
	violations, _ := json.Marshal(candidate.PolicyViolations)
	version, _ := json.Marshal(candidate.CandidateVersion)
	_, err := r.DB.ExecContext(ctx, `INSERT INTO provider_refresh_candidates(candidate_id,registry_id,target_component_id,status,expected_current_version_id,previous_inventory_checksum,candidate_inventory_checksum,policy,component_changes,mapping_impacts,policy_violations,candidate_version_metadata,analyzed_at,analyzed_by,reason,candidate_checksum) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) ON CONFLICT (candidate_id) DO NOTHING`, candidate.CandidateID, candidate.RegistryID, candidate.TargetComponentID, candidate.Status, candidate.CandidateVersion.ExpectedCurrentVersionID, candidate.PreviousInventoryID, candidate.CandidateInventoryID, policy, changes, impacts, violations, version, candidate.AnalyzedAt, candidate.AnalyzedBy, candidate.Reason, candidate.CandidateChecksum)
	return err
}

func (r PostgresRepository) PersistDecision(ctx context.Context, decision PromotionDecision) error {
	if r.DB == nil {
		return fmt.Errorf("database is required")
	}
	_, err := r.DB.ExecContext(ctx, `INSERT INTO provider_refresh_decisions(decision_id,registry_id,sequence,candidate_id,action,reason,decided_at,decided_by,previous_event_hash,event_hash,decision_checksum) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (decision_id) DO NOTHING`, decision.DecisionID, decision.RegistryID, decision.Sequence, decision.CandidateID, decision.Action, decision.Reason, decision.DecidedAt, decision.DecidedBy, decision.PreviousEventHash, decision.EventHash, decision.DecisionChecksum)
	return err
}

func (r PostgresRepository) PersistExecution(ctx context.Context, execution PromotionExecution) error {
	if r.DB == nil {
		return fmt.Errorf("database is required")
	}
	_, err := r.DB.ExecContext(ctx, `INSERT INTO provider_refresh_executions(execution_id,registry_id,sequence,action,candidate_id,decision_id,component_id,previous_version_id,target_version_id,catalog_activation_id,reason,executed_at,executed_by,previous_event_hash,event_hash,execution_checksum) VALUES($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) ON CONFLICT (execution_id) DO NOTHING`, execution.ExecutionID, execution.RegistryID, execution.Sequence, execution.Action, execution.CandidateID, execution.DecisionID, execution.ComponentID, execution.PreviousVersionID, execution.TargetVersionID, execution.CatalogActivationID, execution.Reason, execution.ExecutedAt, execution.ExecutedBy, execution.PreviousEventHash, execution.EventHash, execution.ExecutionChecksum)
	return err
}
