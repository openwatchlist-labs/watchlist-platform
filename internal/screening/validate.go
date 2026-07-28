package screening

import (
	"fmt"
	"reflect"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
)

func ValidateBundle(bundle EvidenceBundle) error {
	if bundle.SchemaVersion != EvidenceBundleSchemaVersion {
		return fmt.Errorf("%w: schema_version must be %q", ErrInvalidEvidenceBundle, EvidenceBundleSchemaVersion)
	}
	for field, value := range map[string]string{
		"bundle_id":                    bundle.BundleID,
		"message_id":                   bundle.MessageID,
		"message_definition":           string(bundle.MessageDefinition),
		"message_namespace":            bundle.MessageNamespace,
		"source_payload_reference":     bundle.SourcePayloadReference,
		"parser_version":               bundle.ParserVersion,
		"executor_version":             bundle.ExecutorVersion,
		"screening_plan.plan_id":       bundle.ScreeningPlan.PlanID,
		"screening_plan.plan_version":  bundle.ScreeningPlan.PlanVersion,
		"screening_plan.plan_checksum": bundle.ScreeningPlan.PlanChecksum,
	} {
		if err := requireNonBlank(value, field); err != nil {
			return err
		}
	}
	if len(bundle.Elements) == 0 {
		return fmt.Errorf("%w: elements must not be empty", ErrInvalidEvidenceBundle)
	}
	seenEvidence := map[string]struct{}{}
	seenElements := map[string]struct{}{}
	for index, element := range bundle.Elements {
		if element.SchemaVersion != ElementEvidenceSchemaVersion {
			return fmt.Errorf("%w: elements[%d].schema_version must be %q", ErrInvalidEvidenceBundle, index, ElementEvidenceSchemaVersion)
		}
		for field, value := range map[string]string{
			"evidence_id":                      element.EvidenceID,
			"element_id":                       element.ElementID,
			"message_id":                       element.MessageID,
			"message_definition":               string(element.MessageDefinition),
			"message_namespace":                element.MessageNamespace,
			"native_path":                      element.NativePath,
			"source_payload_reference":         element.SourcePayloadReference,
			"parser_version":                   element.ParserVersion,
			"resolution.entry_id":              element.Resolution.EntryID,
			"resolution.semantic_role":         string(element.Resolution.SemanticRole),
			"resolution.value_type":            string(element.Resolution.ValueType),
			"resolution.normalization_profile": element.Resolution.NormalizationProfile,
			"resolution.threshold_profile":     element.Resolution.ThresholdProfile,
			"resolution.effective_action":      string(element.Resolution.EffectiveAction),
		} {
			if err := requireNonBlank(value, fmt.Sprintf("elements[%d].%s", index, field)); err != nil {
				return err
			}
		}
		if element.MessageID != bundle.MessageID || element.MessageDefinition != bundle.MessageDefinition || element.MessageNamespace != bundle.MessageNamespace {
			return fmt.Errorf("%w: elements[%d] message identity differs from bundle", ErrInvalidEvidenceBundle, index)
		}
		if element.SourcePayloadReference != bundle.SourcePayloadReference || element.ParserVersion != bundle.ParserVersion {
			return fmt.Errorf("%w: elements[%d] source lineage differs from bundle", ErrInvalidEvidenceBundle, index)
		}
		if element.Resolution.Status != ResolutionResolved {
			return fmt.Errorf("%w: elements[%d].resolution.status must be %q", ErrInvalidEvidenceBundle, index, ResolutionResolved)
		}
		expectedEvidenceID := stableEvidenceIDFromEvidence(element, bundle.ScreeningPlan.PlanChecksum)
		if element.EvidenceID != expectedEvidenceID {
			return fmt.Errorf("%w: elements[%d].evidence_id=%q expected %q", ErrInvalidEvidenceBundle, index, element.EvidenceID, expectedEvidenceID)
		}
		if _, exists := seenEvidence[element.EvidenceID]; exists {
			return fmt.Errorf("%w: duplicate evidence_id %q", ErrInvalidEvidenceBundle, element.EvidenceID)
		}
		seenEvidence[element.EvidenceID] = struct{}{}
		if _, exists := seenElements[element.ElementID]; exists {
			return fmt.Errorf("%w: duplicate element_id %q", ErrInvalidEvidenceBundle, element.ElementID)
		}
		seenElements[element.ElementID] = struct{}{}
		if err := validateResolution(index, element); err != nil {
			return err
		}
	}
	expected := summarize(bundle.Elements)
	if !reflect.DeepEqual(bundle.Summary, expected) {
		return fmt.Errorf("%w: summary does not match element evidence", ErrInvalidEvidenceBundle)
	}
	expectedBundleID := stableBundleID(bundle)
	if bundle.BundleID != expectedBundleID {
		return fmt.Errorf("%w: bundle_id=%q expected %q", ErrInvalidEvidenceBundle, bundle.BundleID, expectedBundleID)
	}
	return nil
}

func validateResolution(index int, element ElementEvidence) error {
	resolution := element.Resolution
	switch resolution.TriggerPolicy {
	case canonical.TriggerCandidateAlert, canonical.TriggerSupportingEvidence:
		if len(resolution.MatchRoutes) == 0 {
			return fmt.Errorf("%w: elements[%d] matching trigger requires routes", ErrInvalidEvidenceBundle, index)
		}
		expectedEligible := element.Presence == canonical.PresencePresent
		if resolution.EligibleForMatching != expectedEligible {
			return fmt.Errorf("%w: elements[%d] eligible_for_matching conflicts with presence", ErrInvalidEvidenceBundle, index)
		}
		if element.Presence == canonical.PresenceEmpty && resolution.EffectiveAction != ActionSkipEmpty {
			return fmt.Errorf("%w: elements[%d] empty matching value must use skip_empty", ErrInvalidEvidenceBundle, index)
		}
		if element.Presence == canonical.PresenceInvalid && resolution.EffectiveAction != ActionSkipInvalid {
			return fmt.Errorf("%w: elements[%d] invalid matching value must use skip_invalid", ErrInvalidEvidenceBundle, index)
		}
		if element.Presence == canonical.PresencePresent {
			expected := ActionCandidateLookup
			if resolution.TriggerPolicy == canonical.TriggerSupportingEvidence {
				expected = ActionSupportingLookup
			}
			if resolution.EffectiveAction != expected {
				return fmt.Errorf("%w: elements[%d] present matching value has action %q expected %q", ErrInvalidEvidenceBundle, index, resolution.EffectiveAction, expected)
			}
		}
	case canonical.TriggerRetainOnly:
		if resolution.EligibleForMatching || len(resolution.MatchRoutes) != 0 || resolution.EffectiveAction != ActionRetainOnly {
			return fmt.Errorf("%w: elements[%d] retain_only resolution is inconsistent", ErrInvalidEvidenceBundle, index)
		}
	case canonical.TriggerDisabled:
		if resolution.EligibleForMatching || len(resolution.MatchRoutes) != 0 || resolution.EffectiveAction != ActionDisabled {
			return fmt.Errorf("%w: elements[%d] disabled resolution is inconsistent", ErrInvalidEvidenceBundle, index)
		}
	default:
		return fmt.Errorf("%w: elements[%d] unsupported trigger_policy %q", ErrInvalidEvidenceBundle, index, resolution.TriggerPolicy)
	}
	return nil
}
