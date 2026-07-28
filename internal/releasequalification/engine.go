package releasequalification

import (
	"fmt"
	"sort"
)

func rate(n, d int) float64 {
	if d == 0 {
		return 1
	}
	return float64(n) / float64(d)
}
func Evaluate(g GateSet, s Suite) (Report, error) {
	cats := map[string]bool{}
	for _, x := range s.Scenarios {
		if x.ScenarioID == "" || cats[x.ScenarioID] {
			return Report{}, fmt.Errorf("duplicate/empty scenario id")
		}
		cats[x.ScenarioID] = true
	}
	category := map[string]bool{}
	m := Metrics{ScenarioCount: len(s.Scenarios), Benchmarks: s.Benchmarks}
	var functional, replay, stable, rag, ragN, cite, citeN, unsup, unsupN, durable, durableN, tenant, tenantN, multi, multiN, docs, docsN, rollback, rollbackN int
	baselineFP, currentFP := 0, 0
	for _, x := range s.Scenarios {
		category[x.Category] = true
		if x.Truth == "match" {
			if x.Prediction == "match" {
				m.TruePositive++
			} else {
				m.FalseNegative++
			}
		} else {
			if x.Prediction == "match" {
				m.FalsePositive++
			} else {
				m.TrueNegative++
			}
		}
		if x.FunctionalPass && x.ExpectedRoute == x.ActualRoute {
			functional++
		}
		if x.ReplayMatch {
			replay++
		}
		if x.PolicyStable {
			stable++
		}
		if x.BaselineFalsePositive {
			baselineFP++
		}
		if x.CurrentFalsePositive {
			currentFP++
		}
		if x.Category == "rag_relevance" {
			ragN++
			if x.RAGRelevant {
				rag++
			}
			citeN++
			if x.CitationsValid {
				cite++
			}
		}
		if x.Category == "unsupported_claim" {
			unsupN++
			if x.UnsupportedClaimRejected {
				unsup++
			}
		}
		if x.Category == "durability" {
			durableN++
			multiN++
			if x.DurabilityPass {
				durable++
			}
			if x.MultiInstanceConsistent {
				multi++
			}
		}
		if x.Category == "tenant_isolation" {
			tenantN++
			if x.TenantIsolationPass {
				tenant++
			}
		}
		if x.Category == "documentation" {
			docsN++
			if x.DocumentationPass {
				docs++
			}
		}
		if x.Category == "rollback" {
			rollbackN++
			if x.RollbackPass {
				rollback++
			}
		}
	}
	for _, c := range g.RequiredCategories {
		if !category[c] {
			return Report{}, fmt.Errorf("required category missing: %s", c)
		}
	}
	m.Precision = rate(m.TruePositive, m.TruePositive+m.FalsePositive)
	m.Recall = rate(m.TruePositive, m.TruePositive+m.FalseNegative)
	m.FunctionalPassRate = rate(functional, len(s.Scenarios))
	m.ReplayMatchRate = rate(replay, len(s.Scenarios))
	m.PolicyStabilityRate = rate(stable, len(s.Scenarios))
	m.RAGRelevanceRate = rate(rag, ragN)
	m.CitationCorrectnessRate = rate(cite, citeN)
	m.UnsupportedClaimRejectionRate = rate(unsup, unsupN)
	m.DurabilityPassRate = rate(durable, durableN)
	m.TenantIsolationPassRate = rate(tenant, tenantN)
	m.MultiInstanceConsistencyRate = rate(multi, multiN)
	m.DocumentationPassRate = rate(docs, docsN)
	m.RollbackPassRate = rate(rollback, rollbackN)
	scans := 0
	if s.ScanResults.DependencyScan {
		scans++
	}
	if s.ScanResults.ContainerScan {
		scans++
	}
	if s.ScanResults.SecretScan {
		scans++
	}
	if s.ScanResults.LicenseScan {
		scans++
	}
	m.SecurityScanPassRate = rate(scans, 4)
	if baselineFP == 0 {
		m.FalsePositiveReduction = 1
	} else {
		m.FalsePositiveReduction = float64(baselineFP-currentFP) / float64(baselineFP)
	}
	r := Report{SchemaVersion: "openwatchlist.release-qualification-report.v1", QualificationID: "qualification_" + s.SuiteSHA256[:24], GateSetID: g.GateSetID, GateSetSHA256: g.GateSetSHA256, SuiteID: s.SuiteID, SuiteSHA256: s.SuiteSHA256, Status: "qualified", Metrics: m}
	ev := func(id string, obs float64, op string, th float64, evidence ...string) {
		pass := false
		if op == ">=" {
			pass = obs >= th
		} else {
			pass = obs <= th
		}
		st := "pass"
		if !pass {
			st = "block"
			r.Blockers = append(r.Blockers, id)
		}
		r.Gates = append(r.Gates, GateResult{GateID: id, Status: st, Observed: obs, Operator: op, Threshold: th, Evidence: evidence})
	}
	t := g.Thresholds
	ev("functional_regression", m.FunctionalPassRate, ">=", t.MinFunctionalPassRate, "scenario_matrix")
	ev("deterministic_replay", m.ReplayMatchRate, ">=", t.MinReplayMatchRate, "historical_and_duplicate_replay")
	ev("matcher_precision", m.Precision, ">=", t.MinPrecision, "truth_labels")
	ev("matcher_recall", m.Recall, ">=", t.MinRecall, "truth_labels")
	ev("false_negative_protection", float64(m.FalseNegative), "<=", float64(t.MaxFalseNegatives), "truth_labels")
	ev("false_positive_reduction", m.FalsePositiveReduction, ">=", t.MinFalsePositiveReduction, "baseline_comparison")
	ev("policy_stability", m.PolicyStabilityRate, ">=", t.MinPolicyStabilityRate, "policy_change_scenarios")
	ev("p95_latency_ms", m.Benchmarks.P95LatencyMS, "<=", t.MaxP95LatencyMS, "benchmark_fixture")
	ev("throughput_rps", m.Benchmarks.ThroughputRPS, ">=", t.MinThroughputRPS, "benchmark_fixture")
	ev("batch_capacity", float64(m.Benchmarks.BatchCapacity), ">=", float64(t.MinBatchCapacity), "benchmark_fixture")
	ev("rag_relevance", m.RAGRelevanceRate, ">=", t.MinRAGRelevanceRate, "rag_scenarios")
	ev("citation_correctness", m.CitationCorrectnessRate, ">=", t.MinCitationCorrectnessRate, "rag_scenarios")
	ev("unsupported_claim_governance", m.UnsupportedClaimRejectionRate, ">=", t.MinUnsupportedClaimRejectionRate, "guardian_scenarios")
	ev("postgres_and_backup_durability", m.DurabilityPassRate, ">=", t.MinDurabilityPassRate, "durability_scenarios")
	ev("tenant_isolation", m.TenantIsolationPassRate, ">=", t.MinTenantIsolationPassRate, "authz_scenarios")
	ev("multi_instance_consistency", m.MultiInstanceConsistencyRate, ">=", t.MinMultiInstanceConsistencyRate, "idempotency_scenarios")
	ev("dependency_container_scanning", m.SecurityScanPassRate, ">=", t.MinSecurityScanPassRate, "scan_results")
	ev("operational_rollback", m.RollbackPassRate, ">=", t.MinRollbackPassRate, "rollback_scenarios")
	ev("documentation_completeness", m.DocumentationPassRate, ">=", t.MinDocumentationPassRate, "documentation_scenarios")
	sort.Strings(r.Blockers)
	if len(r.Blockers) > 0 {
		r.Status = "blocked"
	}
	r.ReportSHA256 = ""
	h, e := hash(r)
	if e != nil {
		return Report{}, e
	}
	r.ReportSHA256 = h
	return r, nil
}
