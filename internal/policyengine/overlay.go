package policyengine

func ApplyOverlay(base Policy, overlay Overlay) Policy {
	effective := base
	effective.PatternRules = make(map[string]PatternRule, len(base.PatternRules))
	for code, rule := range base.PatternRules {
		effective.PatternRules[code] = rule
	}
	effective.BlockerRules = make(map[string]BlockerRule, len(base.BlockerRules))
	for code, rule := range base.BlockerRules {
		effective.BlockerRules[code] = rule
	}
	effective.RouteHintRules = make(map[string]RouteHintRule, len(base.RouteHintRules))
	for code, rule := range base.RouteHintRules {
		effective.RouteHintRules[code] = rule
	}
	effective.ReasonCodes = make(map[string]string, len(base.ReasonCodes))
	for code, value := range base.ReasonCodes {
		effective.ReasonCodes[code] = value
	}

	if value, ok := overlay.WeightOverrides["screening_score"]; ok {
		effective.Weights.ScreeningScore = value
	}
	if value, ok := overlay.WeightOverrides["countervailing_support"]; ok {
		effective.Weights.CountervailingSupport = value
	}
	if value, ok := overlay.WeightOverrides["release_support"]; ok {
		effective.Weights.ReleaseSupport = value
	}
	if value, ok := overlay.ThresholdOverrides["clear_maximum"]; ok {
		effective.Thresholds.ClearMaximum = value
	}
	if value, ok := overlay.ThresholdOverrides["escalate_minimum"]; ok {
		effective.Thresholds.EscalateMinimum = value
	}
	if value, ok := overlay.ThresholdOverrides["minimum_release_support_for_clear"]; ok {
		effective.Thresholds.MinimumReleaseSupportForClear = value
	}
	if value, ok := overlay.ThresholdOverrides["minimum_countervailing_for_escalate"]; ok {
		effective.Thresholds.MinimumCountervailingForEscalate = value
	}
	if value, ok := overlay.ControlOverrides["allow_auto_clear"]; ok {
		effective.Controls.AllowAutoClear = value
	}
	if value, ok := overlay.ControlOverrides["allow_escalation"]; ok {
		effective.Controls.AllowEscalation = value
	}
	for code, override := range overlay.PatternRuleOverrides {
		rule := effective.PatternRules[code]
		if override.ScoreAdjustmentBasisPoints != nil {
			rule.ScoreAdjustmentBasisPoints = *override.ScoreAdjustmentBasisPoints
		}
		if override.MaximumDisposition != nil {
			rule.MaximumDisposition = *override.MaximumDisposition
		}
		if override.ReasonCode != nil {
			rule.ReasonCode = *override.ReasonCode
		}
		effective.PatternRules[code] = rule
	}
	return effective
}
