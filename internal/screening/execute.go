package screening

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningplan"
)

var (
	ErrPlanMismatch           = errors.New("canonical message screening plan does not match executor plan")
	ErrPlanResolution         = errors.New("screening-plan resolution failed")
	ErrPlanAttachmentMismatch = errors.New("canonical element screening attachment does not match resolved plan entry")
	ErrInvalidEvidenceBundle  = errors.New("invalid screening evidence bundle")
)

type Executor struct {
	plan *screeningplan.CompiledPlan
}

func NewExecutor(plan *screeningplan.CompiledPlan) (*Executor, error) {
	if plan == nil {
		return nil, fmt.Errorf("compiled screening plan is required")
	}
	return &Executor{plan: plan}, nil
}

func (executor *Executor) Execute(message canonical.ParsedMessage) (EvidenceBundle, error) {
	if err := canonical.ValidateMessage(message); err != nil {
		return EvidenceBundle{}, err
	}
	if !executor.plan.Supports(message.MessageDefinition) {
		return EvidenceBundle{}, fmt.Errorf("%w: plan %s@%s does not support %s", ErrPlanMismatch, executor.plan.ID(), executor.plan.Version(), message.MessageDefinition)
	}
	if message.ScreeningPlanID != executor.plan.ID() ||
		message.ScreeningPlanVersion != executor.plan.Version() ||
		message.ScreeningPlanChecksum != executor.plan.Checksum() {
		return EvidenceBundle{}, fmt.Errorf(
			"%w: message=%s@%s/%s executor=%s@%s/%s",
			ErrPlanMismatch,
			message.ScreeningPlanID,
			message.ScreeningPlanVersion,
			message.ScreeningPlanChecksum,
			executor.plan.ID(),
			executor.plan.Version(),
			executor.plan.Checksum(),
		)
	}

	bundle := EvidenceBundle{
		SchemaVersion:          EvidenceBundleSchemaVersion,
		MessageID:              message.MessageID,
		MessageDefinition:      message.MessageDefinition,
		MessageNamespace:       message.MessageNamespace,
		SourcePayloadReference: message.SourcePayloadReference,
		ParserVersion:          message.ParserVersion,
		ExecutorVersion:        ExecutorVersion,
		ScreeningPlan: PlanReference{
			PlanID:       executor.plan.ID(),
			PlanVersion:  executor.plan.Version(),
			PlanChecksum: executor.plan.Checksum(),
		},
		Warnings: append([]canonical.ParserWarning(nil), message.Warnings...),
	}
	bundle.Elements = make([]ElementEvidence, 0, len(message.Elements))
	for index, element := range message.Elements {
		entry, err := executor.plan.Resolve(message.MessageDefinition, element.NativePath)
		if err != nil {
			return EvidenceBundle{}, fmt.Errorf("%w: elements[%d] %s: %v", ErrPlanResolution, index, element.NativePath, err)
		}
		if err := executor.verifyAttachment(element, entry); err != nil {
			return EvidenceBundle{}, fmt.Errorf("%w: elements[%d] %s: %v", ErrPlanAttachmentMismatch, index, element.NativePath, err)
		}
		resolution := resolutionFor(element.Presence, entry)
		bundle.Elements = append(bundle.Elements, ElementEvidence{
			SchemaVersion:          ElementEvidenceSchemaVersion,
			EvidenceID:             stableEvidenceID(element, executor.plan.Checksum(), entry.ID),
			ElementID:              element.ElementID,
			MessageID:              element.MessageID,
			TransactionID:          element.TransactionID,
			TransactionIndex:       copyIndex(element.TransactionIndex),
			MessageDefinition:      element.MessageDefinition,
			MessageNamespace:       element.MessageNamespace,
			NativePath:             element.NativePath,
			Occurrence:             element.Occurrence,
			Presence:               element.Presence,
			OriginalValue:          element.OriginalValue,
			NormalizedValue:        element.NormalizedValue,
			Attributes:             cloneMap(element.Attributes),
			Resolution:             resolution,
			SourcePayloadReference: element.SourcePayloadReference,
			ParserVersion:          element.ParserVersion,
			Warnings:               append([]canonical.ParserWarning(nil), element.Warnings...),
		})
	}
	bundle.Summary = summarize(bundle.Elements)
	bundle.BundleID = stableBundleID(bundle)
	if err := ValidateBundle(bundle); err != nil {
		return EvidenceBundle{}, err
	}
	return bundle, nil
}

func (executor *Executor) verifyAttachment(element canonical.ScreenableElement, entry screeningplan.Entry) error {
	expectedPlan := canonical.ScreeningPlanReference{
		PlanID:       executor.plan.ID(),
		PlanVersion:  executor.plan.Version(),
		PlanChecksum: executor.plan.Checksum(),
		EntryID:      entry.ID,
	}
	expectedDirective := canonical.ScreeningDirective{
		TriggerPolicy:         entry.TriggerPolicy,
		MatchRoutes:           append([]canonical.MatchRoute(nil), entry.MatchRoutes...),
		AllowedCandidateTypes: append([]canonical.CandidateType(nil), entry.AllowedCandidateTypes...),
		NormalizationProfile:  entry.NormalizationProfile,
		ThresholdProfile:      entry.ThresholdProfile,
		SupportingFields:      append([]canonical.SemanticRole(nil), entry.SupportingFields...),
	}
	if element.SemanticRole != entry.SemanticRole {
		return fmt.Errorf("semantic_role=%q expected %q", element.SemanticRole, entry.SemanticRole)
	}
	if element.PartyRole != entry.PartyRole {
		return fmt.Errorf("party_role=%q expected %q", element.PartyRole, entry.PartyRole)
	}
	if element.ValueType != entry.ValueType {
		return fmt.Errorf("value_type=%q expected %q", element.ValueType, entry.ValueType)
	}
	if !reflect.DeepEqual(element.ScreeningPlan, expectedPlan) {
		return fmt.Errorf("screening_plan attachment differs from entry %q", entry.ID)
	}
	if !reflect.DeepEqual(element.Screening, expectedDirective) {
		return fmt.Errorf("screening directive differs from entry %q", entry.ID)
	}
	return nil
}

func resolutionFor(presence canonical.PresenceState, entry screeningplan.Entry) PlanResolution {
	eligible := false
	action := ActionDisabled
	switch entry.TriggerPolicy {
	case canonical.TriggerCandidateAlert:
		eligible = presence == canonical.PresencePresent
		action = ActionCandidateLookup
	case canonical.TriggerSupportingEvidence:
		eligible = presence == canonical.PresencePresent
		action = ActionSupportingLookup
	case canonical.TriggerRetainOnly:
		action = ActionRetainOnly
	case canonical.TriggerDisabled:
		action = ActionDisabled
	}
	if entry.TriggerPolicy == canonical.TriggerCandidateAlert || entry.TriggerPolicy == canonical.TriggerSupportingEvidence {
		switch presence {
		case canonical.PresenceEmpty:
			action = ActionSkipEmpty
		case canonical.PresenceInvalid:
			action = ActionSkipInvalid
		}
	}
	return PlanResolution{
		Status:               ResolutionResolved,
		EntryID:              entry.ID,
		SemanticRole:         entry.SemanticRole,
		PartyRole:            entry.PartyRole,
		ValueType:            entry.ValueType,
		TriggerPolicy:        entry.TriggerPolicy,
		MatchRoutes:          append([]canonical.MatchRoute(nil), entry.MatchRoutes...),
		TargetEntityTypes:    append([]canonical.CandidateType(nil), entry.AllowedCandidateTypes...),
		NormalizationProfile: entry.NormalizationProfile,
		ThresholdProfile:     entry.ThresholdProfile,
		SupportingFields:     append([]canonical.SemanticRole(nil), entry.SupportingFields...),
		EligibleForMatching:  eligible,
		EffectiveAction:      action,
	}
}

func summarize(elements []ElementEvidence) EvidenceSummary {
	summary := EvidenceSummary{TotalElements: len(elements)}
	transactions := map[int]struct{}{}
	routes := map[string]int{}
	targets := map[string]int{}
	for _, element := range elements {
		if element.TransactionIndex != nil {
			transactions[*element.TransactionIndex] = struct{}{}
		}
		switch element.Resolution.TriggerPolicy {
		case canonical.TriggerCandidateAlert:
			summary.CandidateAlertElements++
		case canonical.TriggerSupportingEvidence:
			summary.SupportingEvidenceElements++
		case canonical.TriggerRetainOnly:
			summary.RetainOnlyElements++
		case canonical.TriggerDisabled:
			summary.DisabledElements++
		}
		if element.Resolution.EligibleForMatching {
			summary.MatchEligibleElements++
		}
		switch element.Resolution.EffectiveAction {
		case ActionSkipEmpty:
			summary.SkippedEmptyElements++
		case ActionSkipInvalid:
			summary.SkippedInvalidElements++
		}
		summary.ElementWarningCount += len(element.Warnings)
		for _, route := range element.Resolution.MatchRoutes {
			routes[string(route)]++
		}
		for _, target := range element.Resolution.TargetEntityTypes {
			targets[string(target)]++
		}
	}
	summary.TransactionCount = len(transactions)
	summary.RouteCounts = sortedCounts(routes)
	summary.TargetEntityTypeCounts = sortedCounts(targets)
	return summary
}

func sortedCounts(values map[string]int) []NamedCount {
	if len(values) == 0 {
		return nil
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]NamedCount, 0, len(names))
	for _, name := range names {
		result = append(result, NamedCount{Name: name, Count: values[name]})
	}
	return result
}

func copyIndex(value *int) *int {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneMap(value map[string]string) map[string]string {
	if len(value) == 0 {
		return nil
	}
	copy := make(map[string]string, len(value))
	for key, item := range value {
		copy[key] = item
	}
	return copy
}

func requireNonBlank(value, field string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: %s is required", ErrInvalidEvidenceBundle, field)
	}
	return nil
}
