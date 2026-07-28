package policyengine

import (
	"fmt"
	"sort"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/falsepositive"
)

type Engine struct {
	base      Policy
	effective Policy
	overlay   *Overlay
}

func NewEngine(policy Policy, overlay *Overlay) (*Engine, error) {
	if err := ValidatePolicy(policy); err != nil {
		return nil, err
	}
	effective := policy
	if overlay != nil {
		if err := ValidateOverlay(*overlay, policy); err != nil {
			return nil, err
		}
		effective = ApplyOverlay(policy, *overlay)
	}
	return &Engine{base: policy, effective: effective, overlay: overlay}, nil
}

func (engine *Engine) EvaluateBatch(input falsepositive.ClassificationBatch) (DecisionBatch, error) {
	if err := falsepositive.ValidateClassificationBatch(input); err != nil {
		return DecisionBatch{}, err
	}
	output := DecisionBatch{
		SchemaVersion:              DecisionBatchSchema,
		InputClassificationBatchID: input.ClassificationBatchID,
		EngineVersion:              PolicyEngineVersion,
		Policy:                     engine.base.Reference(),
		Decisions:                  make([]Decision, 0, len(input.Classifications)),
	}
	if engine.overlay != nil {
		ref := engine.overlay.Reference()
		output.Overlay = &ref
	}
	for _, classification := range input.Classifications {
		decision := engine.evaluate(classification)
		output.Decisions = append(output.Decisions, decision)
	}
	output.Summary = summarize(output.Decisions)
	output.DecisionBatchID = stableBatchID(output)
	if err := ValidateDecisionBatch(output); err != nil {
		return DecisionBatch{}, err
	}
	return output, nil
}

func (engine *Engine) evaluate(classification falsepositive.Classification) Decision {
	policy := engine.effective
	components := []ScoreComponent{}
	trace := []RuleTrace{}
	reasons := []string{}
	blockers := append([]string(nil), classification.EscalationBlockers...)
	required := append([]string(nil), classification.RequiresEvidence...)

	addWeighted := func(code string, input, weight int, sign int, detail string) int {
		delta := input * weight / 10000 * sign
		components = append(components, ScoreComponent{SchemaVersion: ScoreComponentSchema, Code: code, InputBasisPoints: input, WeightOrAdjustment: weight * sign, DeltaBasisPoints: delta, Detail: detail})
		return delta
	}
	score := 0
	score += addWeighted("screening_score", classification.Observation.ScreeningScoreBasisPoints, policy.Weights.ScreeningScore, 1, "weighted matcher screening score")
	score += addWeighted("countervailing_support", classification.Summary.CountervailingSupportBasisPoints, policy.Weights.CountervailingSupport, 1, "weighted primary or secondary countervailing evidence")
	score += addWeighted("release_support", classification.Summary.ReleaseSupportBasisPoints, policy.Weights.ReleaseSupport, -1, "weighted false-positive release support")

	patterns := append([]falsepositive.PatternEvidence(nil), classification.Patterns...)
	sort.Slice(patterns, func(i, j int) bool { return patterns[i].Code < patterns[j].Code })
	maximum := DispositionEscalate
	for _, pattern := range patterns {
		rule := policy.PatternRules[pattern.Code]
		delta := rule.ScoreAdjustmentBasisPoints
		score += delta
		components = append(components, ScoreComponent{SchemaVersion: ScoreComponentSchema, Code: "pattern:" + pattern.Code, InputBasisPoints: pattern.StrengthBasisPoints, WeightOrAdjustment: delta, DeltaBasisPoints: delta, Detail: "configured false-positive pattern adjustment"})
		reasons = append(reasons, rule.ReasonCode)
		maximum = minDisposition(maximum, rule.MaximumDisposition)
		trace = append(trace, RuleTrace{SchemaVersion: RuleTraceSchema, Rule: "pattern_rule:" + pattern.Code, Outcome: "applied", Detail: fmt.Sprintf("adjustment=%d maximum_disposition=%s", delta, rule.MaximumDisposition)})
	}
	for _, blocker := range classification.EscalationBlockers {
		if rule, ok := policy.BlockerRules[blocker]; ok {
			maximum = minDisposition(maximum, rule.MaximumDisposition)
			reasons = append(reasons, rule.ReasonCode)
			trace = append(trace, RuleTrace{SchemaVersion: RuleTraceSchema, Rule: "blocker_rule:" + blocker, Outcome: "applied", Detail: "maximum_disposition=" + string(rule.MaximumDisposition)})
		}
	}
	routeRule := policy.RouteHintRules[string(classification.RouteHint)]
	maximum = minDisposition(maximum, routeRule.MaximumDisposition)
	reasons = append(reasons, routeRule.ReasonCode)
	trace = append(trace, RuleTrace{SchemaVersion: RuleTraceSchema, Rule: "route_hint:" + string(classification.RouteHint), Outcome: "applied", Detail: "review_route=" + string(routeRule.ReviewRoute)})

	beforeClamp := score
	if score < 0 {
		score = 0
	}
	if score > 10000 {
		score = 10000
	}
	trace = append(trace, RuleTrace{SchemaVersion: RuleTraceSchema, Rule: "score_clamp", Outcome: "applied", Detail: fmt.Sprintf("before=%d after=%d", beforeClamp, score)})

	disposition := DispositionInvestigate
	reviewRoute := routeRule.ReviewRoute
	escalationAllowed := engine.effective.Controls.AllowEscalation &&
		classification.Observation.TriggerPolicy == canonical.TriggerCandidateAlert &&
		classification.Summary.CountervailingSupportBasisPoints >= policy.Thresholds.MinimumCountervailingForEscalate &&
		len(classification.EscalationBlockers) == 0 &&
		dispositionRank(maximum) >= dispositionRank(DispositionEscalate)
	if score >= policy.Thresholds.EscalateMinimum && escalationAllowed {
		disposition = DispositionEscalate
		reviewRoute = ReviewRouteEscalationReview
		reasons = append(reasons, policy.ReasonCodes["escalate"])
		trace = append(trace, RuleTrace{SchemaVersion: RuleTraceSchema, Rule: "escalation_gate", Outcome: "pass", Detail: "score and primary-evidence requirements satisfied"})
	} else {
		outcome := "fail"
		if !policy.Controls.AllowEscalation {
			reasons = append(reasons, policy.ReasonCodes["escalation_disabled"])
			blockers = append(blockers, "policy_escalation_disabled")
		}
		trace = append(trace, RuleTrace{SchemaVersion: RuleTraceSchema, Rule: "escalation_gate", Outcome: outcome, Detail: fmt.Sprintf("score=%d threshold=%d countervailing=%d blockers=%d maximum=%s", score, policy.Thresholds.EscalateMinimum, classification.Summary.CountervailingSupportBasisPoints, len(classification.EscalationBlockers), maximum)})
	}
	if disposition != DispositionEscalate {
		clearAllowed := policy.Controls.AllowAutoClear &&
			classification.RouteHint == falsepositive.RouteClearEligible &&
			classification.Summary.ReleaseSupportBasisPoints >= policy.Thresholds.MinimumReleaseSupportForClear &&
			score <= policy.Thresholds.ClearMaximum &&
			dispositionRank(maximum) >= dispositionRank(DispositionClear)
		if clearAllowed {
			disposition = DispositionClear
			reviewRoute = ReviewRouteAutoRelease
			reasons = append(reasons, policy.ReasonCodes["clear"])
			trace = append(trace, RuleTrace{SchemaVersion: RuleTraceSchema, Rule: "clear_gate", Outcome: "pass", Detail: "release support and score requirements satisfied"})
		} else {
			disposition = DispositionInvestigate
			if classification.RouteHint == falsepositive.RouteManualReview {
				reviewRoute = ReviewRouteManualReview
			} else {
				reviewRoute = ReviewRouteStandardReview
			}
			reasons = append(reasons, policy.ReasonCodes["investigate"], policy.ReasonCodes["threshold_score"])
			if !policy.Controls.AllowAutoClear && classification.RouteHint == falsepositive.RouteClearEligible {
				reasons = append(reasons, policy.ReasonCodes["auto_clear_disabled"])
				blockers = append(blockers, "policy_auto_clear_disabled")
			}
			trace = append(trace, RuleTrace{SchemaVersion: RuleTraceSchema, Rule: "clear_gate", Outcome: "fail", Detail: fmt.Sprintf("score=%d threshold=%d release_support=%d route_hint=%s", score, policy.Thresholds.ClearMaximum, classification.Summary.ReleaseSupportBasisPoints, classification.RouteHint)})
		}
	}
	if classification.Observation.TriggerPolicy == canonical.TriggerSupportingEvidence {
		reasons = append(reasons, policy.ReasonCodes["supporting_evidence_non_escalation"])
	}
	decision := Decision{
		SchemaVersion:      DecisionSchemaVersion,
		Classification:     classification,
		EngineVersion:      PolicyEngineVersion,
		Policy:             engine.base.Reference(),
		ScoreComponents:    components,
		ScoreBeforeClamp:   beforeClamp,
		PolicyScore:        score,
		Disposition:        disposition,
		ReviewRoute:        reviewRoute,
		EscalationBlockers: canonicalStrings(blockers),
		RequiredEvidence:   canonicalStrings(required),
		ReasonCodes:        canonicalStrings(reasons),
		Thresholds:         ThresholdSnapshot(policy.Thresholds),
		RuleTrace:          trace,
	}
	if engine.overlay != nil {
		ref := engine.overlay.Reference()
		decision.Overlay = &ref
	}
	decision.DecisionID = stableDecisionID(decision)
	return decision
}

func minDisposition(a, b Disposition) Disposition {
	if dispositionRank(a) < dispositionRank(b) {
		return a
	}
	return b
}
func dispositionRank(value Disposition) int {
	switch value {
	case DispositionClear:
		return 0
	case DispositionInvestigate:
		return 1
	case DispositionEscalate:
		return 2
	default:
		return -1
	}
}

func canonicalStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
	out := values[:0]
	for _, value := range values {
		if value != "" && (len(out) == 0 || out[len(out)-1] != value) {
			out = append(out, value)
		}
	}
	return out
}

func summarize(decisions []Decision) DecisionBatchSummary {
	dispositions, routes, reasons, blockers := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	for _, decision := range decisions {
		dispositions[string(decision.Disposition)]++
		routes[string(decision.ReviewRoute)]++
		for _, reason := range decision.ReasonCodes {
			reasons[reason]++
		}
		for _, blocker := range decision.EscalationBlockers {
			blockers[blocker]++
		}
	}
	return DecisionBatchSummary{TotalDecisions: len(decisions), DispositionCounts: namedCounts(dispositions), ReviewRouteCounts: namedCounts(routes), ReasonCodeCounts: namedCounts(reasons), BlockerCounts: namedCounts(blockers)}
}

func namedCounts(values map[string]int) []NamedCount {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]NamedCount, 0, len(keys))
	for _, key := range keys {
		out = append(out, NamedCount{Name: key, Count: values[key]})
	}
	return out
}
