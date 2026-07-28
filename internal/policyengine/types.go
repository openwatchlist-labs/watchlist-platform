package policyengine

import "github.com/openwatchlist-labs/watchlist-platform/internal/falsepositive"

const (
	PolicySchemaVersion   = "transaction-screening-policy/v1alpha1"
	OverlaySchemaVersion  = "tenant-policy-overlay/v1alpha1"
	DecisionSchemaVersion = "transaction-screening-decision/v1alpha1"
	DecisionBatchSchema   = "transaction-screening-decision-batch/v1alpha1"
	ScoreComponentSchema  = "policy-score-component/v1alpha1"
	RuleTraceSchema       = "policy-rule-trace/v1alpha1"
	PolicyEngineVersion   = "transaction-policy-engine/v0.1.0"
)

type Disposition string

const (
	DispositionClear       Disposition = "clear"
	DispositionInvestigate Disposition = "investigate"
	DispositionEscalate    Disposition = "escalate"
)

type ReviewRoute string

const (
	ReviewRouteAutoRelease      ReviewRoute = "auto_release"
	ReviewRouteStandardReview   ReviewRoute = "standard_review"
	ReviewRouteManualReview     ReviewRoute = "manual_review"
	ReviewRouteEscalationReview ReviewRoute = "escalation_review"
)

type ScoreWeights struct {
	ScreeningScore        int `json:"screening_score"`
	CountervailingSupport int `json:"countervailing_support"`
	ReleaseSupport        int `json:"release_support"`
}

type Thresholds struct {
	ClearMaximum                     int `json:"clear_maximum"`
	EscalateMinimum                  int `json:"escalate_minimum"`
	MinimumReleaseSupportForClear    int `json:"minimum_release_support_for_clear"`
	MinimumCountervailingForEscalate int `json:"minimum_countervailing_for_escalate"`
}

type Controls struct {
	AllowAutoClear  bool `json:"allow_auto_clear"`
	AllowEscalation bool `json:"allow_escalation"`
}

type PatternRule struct {
	ScoreAdjustmentBasisPoints int         `json:"score_adjustment_basis_points"`
	MaximumDisposition         Disposition `json:"maximum_disposition"`
	ReasonCode                 string      `json:"reason_code"`
}

type BlockerRule struct {
	MaximumDisposition Disposition `json:"maximum_disposition"`
	ReasonCode         string      `json:"reason_code"`
}

type RouteHintRule struct {
	ReviewRoute        ReviewRoute `json:"review_route"`
	MaximumDisposition Disposition `json:"maximum_disposition"`
	ReasonCode         string      `json:"reason_code"`
}

type Policy struct {
	SchemaVersion  string                   `json:"schema_version"`
	PolicyID       string                   `json:"policy_id"`
	PolicyVersion  string                   `json:"policy_version"`
	PolicyChecksum string                   `json:"policy_checksum"`
	Weights        ScoreWeights             `json:"weights_basis_points"`
	Thresholds     Thresholds               `json:"thresholds_basis_points"`
	Controls       Controls                 `json:"controls"`
	PatternRules   map[string]PatternRule   `json:"pattern_rules"`
	BlockerRules   map[string]BlockerRule   `json:"blocker_rules"`
	RouteHintRules map[string]RouteHintRule `json:"route_hint_rules"`
	ReasonCodes    map[string]string        `json:"reason_codes"`
}

type PolicyReference struct {
	PolicyID       string `json:"policy_id"`
	PolicyVersion  string `json:"policy_version"`
	PolicyChecksum string `json:"policy_checksum"`
}

type PatternRuleOverride struct {
	ScoreAdjustmentBasisPoints *int         `json:"score_adjustment_basis_points,omitempty"`
	MaximumDisposition         *Disposition `json:"maximum_disposition,omitempty"`
	ReasonCode                 *string      `json:"reason_code,omitempty"`
}

type Overlay struct {
	SchemaVersion        string                         `json:"schema_version"`
	OverlayID            string                         `json:"overlay_id"`
	OverlayVersion       string                         `json:"overlay_version"`
	OverlayChecksum      string                         `json:"overlay_checksum"`
	TenantID             string                         `json:"tenant_id"`
	BasePolicy           PolicyReference                `json:"base_policy"`
	WeightOverrides      map[string]int                 `json:"weight_overrides_basis_points,omitempty"`
	ThresholdOverrides   map[string]int                 `json:"threshold_overrides_basis_points,omitempty"`
	ControlOverrides     map[string]bool                `json:"control_overrides,omitempty"`
	PatternRuleOverrides map[string]PatternRuleOverride `json:"pattern_rule_overrides,omitempty"`
}

type OverlayReference struct {
	OverlayID       string `json:"overlay_id"`
	OverlayVersion  string `json:"overlay_version"`
	OverlayChecksum string `json:"overlay_checksum"`
	TenantID        string `json:"tenant_id"`
}

type ScoreComponent struct {
	SchemaVersion      string `json:"schema_version"`
	Code               string `json:"code"`
	InputBasisPoints   int    `json:"input_basis_points"`
	WeightOrAdjustment int    `json:"weight_or_adjustment_basis_points"`
	DeltaBasisPoints   int    `json:"delta_basis_points"`
	Detail             string `json:"detail"`
}

type RuleTrace struct {
	SchemaVersion string `json:"schema_version"`
	Rule          string `json:"rule"`
	Outcome       string `json:"outcome"`
	Detail        string `json:"detail"`
}

type ThresholdSnapshot struct {
	ClearMaximum                     int `json:"clear_maximum"`
	EscalateMinimum                  int `json:"escalate_minimum"`
	MinimumReleaseSupportForClear    int `json:"minimum_release_support_for_clear"`
	MinimumCountervailingForEscalate int `json:"minimum_countervailing_for_escalate"`
}

type Decision struct {
	SchemaVersion      string                       `json:"schema_version"`
	DecisionID         string                       `json:"decision_id"`
	Classification     falsepositive.Classification `json:"classification"`
	EngineVersion      string                       `json:"engine_version"`
	Policy             PolicyReference              `json:"policy"`
	Overlay            *OverlayReference            `json:"overlay,omitempty"`
	ScoreComponents    []ScoreComponent             `json:"score_components"`
	ScoreBeforeClamp   int                          `json:"score_before_clamp_basis_points"`
	PolicyScore        int                          `json:"policy_score_basis_points"`
	Disposition        Disposition                  `json:"disposition"`
	ReviewRoute        ReviewRoute                  `json:"review_route"`
	EscalationBlockers []string                     `json:"escalation_blockers,omitempty"`
	RequiredEvidence   []string                     `json:"required_evidence,omitempty"`
	ReasonCodes        []string                     `json:"reason_codes"`
	Thresholds         ThresholdSnapshot            `json:"thresholds_applied_basis_points"`
	RuleTrace          []RuleTrace                  `json:"rule_trace"`
}

type NamedCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type DecisionBatchSummary struct {
	TotalDecisions    int          `json:"total_decisions"`
	DispositionCounts []NamedCount `json:"disposition_counts"`
	ReviewRouteCounts []NamedCount `json:"review_route_counts"`
	ReasonCodeCounts  []NamedCount `json:"reason_code_counts,omitempty"`
	BlockerCounts     []NamedCount `json:"blocker_counts,omitempty"`
}

type DecisionBatch struct {
	SchemaVersion              string               `json:"schema_version"`
	DecisionBatchID            string               `json:"decision_batch_id"`
	InputClassificationBatchID string               `json:"input_classification_batch_id"`
	EngineVersion              string               `json:"engine_version"`
	Policy                     PolicyReference      `json:"policy"`
	Overlay                    *OverlayReference    `json:"overlay,omitempty"`
	Summary                    DecisionBatchSummary `json:"summary"`
	Decisions                  []Decision           `json:"decisions"`
}
