package canonical

import (
	"errors"
	"fmt"
	"strings"
)

var ErrInvalidCanonicalMessage = errors.New("invalid canonical message")

func ValidateMessage(message ParsedMessage) error {
	if message.SchemaVersion != CanonicalSchemaVersion {
		return invalid("schema_version", "must be %q", CanonicalSchemaVersion)
	}
	if strings.TrimSpace(message.MessageID) == "" {
		return invalid("message_id", "is required")
	}
	if strings.TrimSpace(string(message.MessageDefinition)) == "" {
		return invalid("message_definition", "is required")
	}
	if strings.TrimSpace(message.MessageNamespace) == "" {
		return invalid("message_namespace", "is required")
	}
	if strings.TrimSpace(message.SourcePayloadReference) == "" {
		return invalid("source_payload_reference", "is required")
	}
	if strings.TrimSpace(message.ParserVersion) == "" {
		return invalid("parser_version", "is required")
	}
	if strings.TrimSpace(message.ScreeningPlanID) == "" || strings.TrimSpace(message.ScreeningPlanVersion) == "" || strings.TrimSpace(message.ScreeningPlanChecksum) == "" {
		return invalid("screening_plan", "id, version, and checksum are required")
	}
	if len(message.Elements) == 0 {
		return invalid("elements", "at least one element is required")
	}

	seen := make(map[string]struct{}, len(message.Elements))
	for index, element := range message.Elements {
		if err := ValidateElement(element); err != nil {
			return fmt.Errorf("%w: elements[%d]: %v", ErrInvalidCanonicalMessage, index, err)
		}
		if element.MessageID != message.MessageID {
			return invalid(fmt.Sprintf("elements[%d].message_id", index), "does not match message")
		}
		if element.MessageDefinition != message.MessageDefinition || element.MessageNamespace != message.MessageNamespace {
			return invalid(fmt.Sprintf("elements[%d].message_definition", index), "does not match message")
		}
		if _, exists := seen[element.ElementID]; exists {
			return invalid(fmt.Sprintf("elements[%d].element_id", index), "is duplicated")
		}
		seen[element.ElementID] = struct{}{}
	}
	return nil
}

func ValidateElement(element ScreenableElement) error {
	if element.SchemaVersion != ElementSchemaVersion {
		return invalid("schema_version", "must be %q", ElementSchemaVersion)
	}
	if strings.TrimSpace(element.ElementID) == "" {
		return invalid("element_id", "is required")
	}
	if element.TransactionIndex != nil && *element.TransactionIndex < 0 {
		return invalid("transaction_index", "must be non-negative")
	}
	if !strings.HasPrefix(element.NativePath, "/Document/") {
		return invalid("native_path", "must start with /Document/")
	}
	if strings.TrimSpace(string(element.SemanticRole)) == "" {
		return invalid("semantic_role", "is required")
	}
	if strings.TrimSpace(string(element.ValueType)) == "" {
		return invalid("value_type", "is required")
	}
	if element.Presence != PresencePresent && element.Presence != PresenceEmpty && element.Presence != PresenceInvalid {
		return invalid("presence", "has unsupported value %q", element.Presence)
	}
	if element.Presence == PresencePresent && strings.TrimSpace(element.OriginalValue) == "" {
		return invalid("original_value", "cannot be blank when presence is present")
	}
	if strings.TrimSpace(element.ScreeningPlan.PlanID) == "" || strings.TrimSpace(element.ScreeningPlan.PlanVersion) == "" || strings.TrimSpace(element.ScreeningPlan.PlanChecksum) == "" || strings.TrimSpace(element.ScreeningPlan.EntryID) == "" {
		return invalid("screening_plan", "all reference fields are required")
	}
	if strings.TrimSpace(element.Screening.NormalizationProfile) == "" || strings.TrimSpace(element.Screening.ThresholdProfile) == "" {
		return invalid("screening", "normalization_profile and threshold_profile are required")
	}
	if element.Screening.TriggerPolicy == TriggerRetainOnly || element.Screening.TriggerPolicy == TriggerDisabled {
		if len(element.Screening.MatchRoutes) != 0 {
			return invalid("screening.match_routes", "must be empty for %s", element.Screening.TriggerPolicy)
		}
	}
	if element.Screening.TriggerPolicy == TriggerCandidateAlert && len(element.Screening.MatchRoutes) == 0 {
		return invalid("screening.match_routes", "candidate_alert requires at least one route")
	}
	return nil
}

func invalid(field, format string, args ...any) error {
	return fmt.Errorf("%w: %s: %s", ErrInvalidCanonicalMessage, field, fmt.Sprintf(format, args...))
}
