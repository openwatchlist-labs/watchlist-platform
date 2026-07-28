package releasequalification

type Thresholds struct {
	MinFunctionalPassRate            float64 `json:"min_functional_pass_rate"`
	MinReplayMatchRate               float64 `json:"min_replay_match_rate"`
	MinPrecision                     float64 `json:"min_precision"`
	MinRecall                        float64 `json:"min_recall"`
	MaxFalseNegatives                int     `json:"max_false_negatives"`
	MinFalsePositiveReduction        float64 `json:"min_false_positive_reduction"`
	MinPolicyStabilityRate           float64 `json:"min_policy_stability_rate"`
	MaxP95LatencyMS                  float64 `json:"max_p95_latency_ms"`
	MinThroughputRPS                 float64 `json:"min_throughput_rps"`
	MinBatchCapacity                 int     `json:"min_batch_capacity"`
	MinRAGRelevanceRate              float64 `json:"min_rag_relevance_rate"`
	MinCitationCorrectnessRate       float64 `json:"min_citation_correctness_rate"`
	MinUnsupportedClaimRejectionRate float64 `json:"min_unsupported_claim_rejection_rate"`
	MinDurabilityPassRate            float64 `json:"min_durability_pass_rate"`
	MinTenantIsolationPassRate       float64 `json:"min_tenant_isolation_pass_rate"`
	MinSecurityScanPassRate          float64 `json:"min_security_scan_pass_rate"`
	MinDocumentationPassRate         float64 `json:"min_documentation_pass_rate"`
	MinRollbackPassRate              float64 `json:"min_rollback_pass_rate"`
	MinMultiInstanceConsistencyRate  float64 `json:"min_multi_instance_consistency_rate"`
}
type GateSet struct {
	SchemaVersion      string     `json:"schema_version"`
	GateSetID          string     `json:"gate_set_id"`
	Version            string     `json:"version"`
	Thresholds         Thresholds `json:"thresholds"`
	RequiredCategories []string   `json:"required_categories"`
	GateSetSHA256      string     `json:"gate_set_sha256,omitempty"`
}
type Scenario struct {
	ScenarioID               string `json:"scenario_id"`
	Category                 string `json:"category"`
	Truth                    string `json:"truth"`
	Prediction               string `json:"prediction"`
	TopScore                 int    `json:"top_score"`
	ExpectedRoute            string `json:"expected_route"`
	ActualRoute              string `json:"actual_route"`
	FunctionalPass           bool   `json:"functional_pass"`
	ReplayMatch              bool   `json:"replay_match"`
	PolicyStable             bool   `json:"policy_stable"`
	TenantIsolationPass      bool   `json:"tenant_isolation_pass"`
	DurabilityPass           bool   `json:"durability_pass"`
	MultiInstanceConsistent  bool   `json:"multi_instance_consistent"`
	RAGRelevant              bool   `json:"rag_relevant"`
	CitationsValid           bool   `json:"citations_valid"`
	UnsupportedClaimRejected bool   `json:"unsupported_claim_rejected"`
	RollbackPass             bool   `json:"rollback_pass"`
	DocumentationPass        bool   `json:"documentation_pass"`
	SecurityScanPass         bool   `json:"security_scan_pass"`
	BaselineFalsePositive    bool   `json:"baseline_false_positive"`
	CurrentFalsePositive     bool   `json:"current_false_positive"`
}
type Benchmarks struct {
	P50LatencyMS  float64 `json:"p50_latency_ms"`
	P95LatencyMS  float64 `json:"p95_latency_ms"`
	P99LatencyMS  float64 `json:"p99_latency_ms"`
	ThroughputRPS float64 `json:"throughput_rps"`
	BatchCapacity int     `json:"batch_capacity"`
}
type ScanResults struct {
	DependencyScan bool `json:"dependency_scan"`
	ContainerScan  bool `json:"container_scan"`
	SecretScan     bool `json:"secret_scan"`
	LicenseScan    bool `json:"license_scan"`
}
type Suite struct {
	SchemaVersion string      `json:"schema_version"`
	SuiteID       string      `json:"suite_id"`
	Version       string      `json:"version"`
	Scenarios     []Scenario  `json:"scenarios"`
	Benchmarks    Benchmarks  `json:"benchmarks"`
	ScanResults   ScanResults `json:"scan_results"`
	SuiteSHA256   string      `json:"suite_sha256,omitempty"`
}
type Metrics struct {
	ScenarioCount                 int        `json:"scenario_count"`
	TruePositive                  int        `json:"true_positive"`
	TrueNegative                  int        `json:"true_negative"`
	FalsePositive                 int        `json:"false_positive"`
	FalseNegative                 int        `json:"false_negative"`
	Precision                     float64    `json:"precision"`
	Recall                        float64    `json:"recall"`
	FalsePositiveReduction        float64    `json:"false_positive_reduction"`
	FunctionalPassRate            float64    `json:"functional_pass_rate"`
	ReplayMatchRate               float64    `json:"replay_match_rate"`
	PolicyStabilityRate           float64    `json:"policy_stability_rate"`
	RAGRelevanceRate              float64    `json:"rag_relevance_rate"`
	CitationCorrectnessRate       float64    `json:"citation_correctness_rate"`
	UnsupportedClaimRejectionRate float64    `json:"unsupported_claim_rejection_rate"`
	DurabilityPassRate            float64    `json:"durability_pass_rate"`
	TenantIsolationPassRate       float64    `json:"tenant_isolation_pass_rate"`
	MultiInstanceConsistencyRate  float64    `json:"multi_instance_consistency_rate"`
	SecurityScanPassRate          float64    `json:"security_scan_pass_rate"`
	DocumentationPassRate         float64    `json:"documentation_pass_rate"`
	RollbackPassRate              float64    `json:"rollback_pass_rate"`
	Benchmarks                    Benchmarks `json:"benchmarks"`
}
type GateResult struct {
	GateID    string   `json:"gate_id"`
	Status    string   `json:"status"`
	Observed  float64  `json:"observed"`
	Operator  string   `json:"operator"`
	Threshold float64  `json:"threshold"`
	Evidence  []string `json:"evidence"`
}
type Report struct {
	SchemaVersion   string       `json:"schema_version"`
	QualificationID string       `json:"qualification_id"`
	GateSetID       string       `json:"gate_set_id"`
	GateSetSHA256   string       `json:"gate_set_sha256"`
	SuiteID         string       `json:"suite_id"`
	SuiteSHA256     string       `json:"suite_sha256"`
	Status          string       `json:"status"`
	Metrics         Metrics      `json:"metrics"`
	Gates           []GateResult `json:"gates"`
	Blockers        []string     `json:"blockers,omitempty"`
	ReportSHA256    string       `json:"report_sha256"`
}
