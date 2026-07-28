package policyengine

import (
	"fmt"

	"github.com/openwatchlist-labs/watchlist-platform/internal/falsepositive"
)

func ValidatePolicy(policy Policy) error {
	if policy.SchemaVersion != PolicySchemaVersion {
		return fmt.Errorf("%w: schema_version must be %q", ErrInvalidPolicy, PolicySchemaVersion)
	}
	for path, value := range map[string]string{"policy_id": policy.PolicyID, "policy_version": policy.PolicyVersion, "policy_checksum": policy.PolicyChecksum} {
		if err := required(value, path, ErrInvalidPolicy); err != nil {
			return err
		}
	}
	for path, value := range map[string]int{
		"weights_basis_points.screening_score":        policy.Weights.ScreeningScore,
		"weights_basis_points.countervailing_support": policy.Weights.CountervailingSupport,
		"weights_basis_points.release_support":        policy.Weights.ReleaseSupport,
	} {
		if value < 0 || value > 10000 {
			return fmt.Errorf("%w: %s outside 0..10000", ErrInvalidPolicy, path)
		}
	}
	if policy.Thresholds.ClearMaximum < 0 || policy.Thresholds.ClearMaximum > 10000 ||
		policy.Thresholds.EscalateMinimum < 0 || policy.Thresholds.EscalateMinimum > 10000 ||
		policy.Thresholds.ClearMaximum >= policy.Thresholds.EscalateMinimum {
		return fmt.Errorf("%w: thresholds must satisfy 0 <= clear_maximum < escalate_minimum <= 10000", ErrInvalidPolicy)
	}
	for path, value := range map[string]int{
		"minimum_release_support_for_clear":   policy.Thresholds.MinimumReleaseSupportForClear,
		"minimum_countervailing_for_escalate": policy.Thresholds.MinimumCountervailingForEscalate,
	} {
		if value < 0 || value > 10000 {
			return fmt.Errorf("%w: %s outside 0..10000", ErrInvalidPolicy, path)
		}
	}
	requiredPatterns := []string{
		falsepositive.PatternAcronymCollision,
		falsepositive.PatternEntityTypeMismatch,
		falsepositive.PatternLegalControlContext,
		falsepositive.PatternMissingQualifier,
		falsepositive.PatternNarrativeDenialContext,
		falsepositive.PatternPhoneticTransliterationOnly,
		falsepositive.PatternRoutingBICCollision,
		falsepositive.PatternSubstringContainment,
		falsepositive.PatternTechnicalSystemArtifact,
		falsepositive.PatternWrongFieldDataType,
	}
	for _, code := range requiredPatterns {
		rule, ok := policy.PatternRules[code]
		if !ok {
			return fmt.Errorf("%w: pattern_rules.%s is required", ErrInvalidPolicy, code)
		}
		if err := validatePatternRule(rule, "pattern_rules."+code, ErrInvalidPolicy); err != nil {
			return err
		}
	}
	for code, rule := range policy.PatternRules {
		if err := validatePatternRule(rule, "pattern_rules."+code, ErrInvalidPolicy); err != nil {
			return err
		}
	}
	for code, rule := range policy.BlockerRules {
		if err := validateDisposition(rule.MaximumDisposition, "blocker_rules."+code+".maximum_disposition", ErrInvalidPolicy); err != nil {
			return err
		}
		if err := required(rule.ReasonCode, "blocker_rules."+code+".reason_code", ErrInvalidPolicy); err != nil {
			return err
		}
	}
	for _, hint := range []falsepositive.RouteHint{falsepositive.RouteClearEligible, falsepositive.RouteInvestigate, falsepositive.RouteManualReview, falsepositive.RouteEscalationCandidate} {
		rule, ok := policy.RouteHintRules[string(hint)]
		if !ok {
			return fmt.Errorf("%w: route_hint_rules.%s is required", ErrInvalidPolicy, hint)
		}
		if err := validateDisposition(rule.MaximumDisposition, "route_hint_rules."+string(hint)+".maximum_disposition", ErrInvalidPolicy); err != nil {
			return err
		}
		if err := validateReviewRoute(rule.ReviewRoute, "route_hint_rules."+string(hint)+".review_route", ErrInvalidPolicy); err != nil {
			return err
		}
		if err := required(rule.ReasonCode, "route_hint_rules."+string(hint)+".reason_code", ErrInvalidPolicy); err != nil {
			return err
		}
	}
	for _, key := range []string{"clear", "investigate", "escalate", "auto_clear_disabled", "escalation_disabled", "threshold_score", "supporting_evidence_non_escalation"} {
		if err := required(policy.ReasonCodes[key], "reason_codes."+key, ErrInvalidPolicy); err != nil {
			return err
		}
	}
	if expected := PolicyChecksum(policy); policy.PolicyChecksum != expected {
		return fmt.Errorf("%w: policy_checksum=%q expected %q", ErrInvalidPolicy, policy.PolicyChecksum, expected)
	}
	return nil
}

func ValidateOverlay(overlay Overlay, base Policy) error {
	if overlay.SchemaVersion != OverlaySchemaVersion {
		return fmt.Errorf("%w: schema_version must be %q", ErrInvalidOverlay, OverlaySchemaVersion)
	}
	for path, value := range map[string]string{"overlay_id": overlay.OverlayID, "overlay_version": overlay.OverlayVersion, "overlay_checksum": overlay.OverlayChecksum, "tenant_id": overlay.TenantID} {
		if err := required(value, path, ErrInvalidOverlay); err != nil {
			return err
		}
	}
	if overlay.BasePolicy != base.Reference() {
		return fmt.Errorf("%w: base_policy does not match loaded policy", ErrInvalidOverlay)
	}
	for key, value := range overlay.WeightOverrides {
		if !contains([]string{"screening_score", "countervailing_support", "release_support"}, key) {
			return fmt.Errorf("%w: unknown weight override %q", ErrInvalidOverlay, key)
		}
		if value < 0 || value > 10000 {
			return fmt.Errorf("%w: weight override %s outside 0..10000", ErrInvalidOverlay, key)
		}
	}
	for key, value := range overlay.ThresholdOverrides {
		if !contains([]string{"clear_maximum", "escalate_minimum", "minimum_release_support_for_clear", "minimum_countervailing_for_escalate"}, key) {
			return fmt.Errorf("%w: unknown threshold override %q", ErrInvalidOverlay, key)
		}
		if value < 0 || value > 10000 {
			return fmt.Errorf("%w: threshold override %s outside 0..10000", ErrInvalidOverlay, key)
		}
	}
	for key := range overlay.ControlOverrides {
		if !contains([]string{"allow_auto_clear", "allow_escalation"}, key) {
			return fmt.Errorf("%w: unknown control override %q", ErrInvalidOverlay, key)
		}
	}
	for code, override := range overlay.PatternRuleOverrides {
		if _, ok := base.PatternRules[code]; !ok {
			return fmt.Errorf("%w: unknown pattern rule override %q", ErrInvalidOverlay, code)
		}
		if override.ScoreAdjustmentBasisPoints != nil && (*override.ScoreAdjustmentBasisPoints < -10000 || *override.ScoreAdjustmentBasisPoints > 10000) {
			return fmt.Errorf("%w: pattern adjustment override %s outside -10000..10000", ErrInvalidOverlay, code)
		}
		if override.MaximumDisposition != nil {
			if err := validateDisposition(*override.MaximumDisposition, "pattern_rule_overrides."+code+".maximum_disposition", ErrInvalidOverlay); err != nil {
				return err
			}
		}
		if override.ReasonCode != nil {
			if err := required(*override.ReasonCode, "pattern_rule_overrides."+code+".reason_code", ErrInvalidOverlay); err != nil {
				return err
			}
		}
	}
	if expected := OverlayChecksum(overlay); overlay.OverlayChecksum != expected {
		return fmt.Errorf("%w: overlay_checksum=%q expected %q", ErrInvalidOverlay, overlay.OverlayChecksum, expected)
	}
	effective := ApplyOverlay(base, overlay)
	if effective.Thresholds.ClearMaximum >= effective.Thresholds.EscalateMinimum {
		return fmt.Errorf("%w: effective clear threshold must be below escalate threshold", ErrInvalidOverlay)
	}
	return nil
}

func validatePatternRule(rule PatternRule, path string, sentinel error) error {
	if rule.ScoreAdjustmentBasisPoints < -10000 || rule.ScoreAdjustmentBasisPoints > 10000 {
		return fmt.Errorf("%w: %s.score_adjustment_basis_points outside -10000..10000", sentinel, path)
	}
	if err := validateDisposition(rule.MaximumDisposition, path+".maximum_disposition", sentinel); err != nil {
		return err
	}
	return required(rule.ReasonCode, path+".reason_code", sentinel)
}

func validateDisposition(value Disposition, path string, sentinel error) error {
	switch value {
	case DispositionClear, DispositionInvestigate, DispositionEscalate:
		return nil
	default:
		return fmt.Errorf("%w: %s has invalid disposition %q", sentinel, path, value)
	}
}

func validateReviewRoute(value ReviewRoute, path string, sentinel error) error {
	switch value {
	case ReviewRouteAutoRelease, ReviewRouteStandardReview, ReviewRouteManualReview, ReviewRouteEscalationReview:
		return nil
	default:
		return fmt.Errorf("%w: %s has invalid review route %q", sentinel, path, value)
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
