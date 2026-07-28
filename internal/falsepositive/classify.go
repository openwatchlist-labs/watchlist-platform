package falsepositive

import (
	"fmt"
	"sort"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
)

const (
	PatternAcronymCollision            = "acronym_collision"
	PatternEntityTypeMismatch          = "entity_type_mismatch"
	PatternLegalControlContext         = "legal_control_context"
	PatternMissingQualifier            = "missing_qualifier"
	PatternNarrativeDenialContext      = "narrative_denial_context"
	PatternPhoneticTransliterationOnly = "phonetic_transliteration_only"
	PatternRoutingBICCollision         = "routing_bic_collision"
	PatternSubstringContainment        = "substring_containment"
	PatternTechnicalSystemArtifact     = "technical_system_artifact"
	PatternWrongFieldDataType          = "wrong_field_data_type"
)

type Classifier struct {
	library              PatternLibrary
	countervailingPolicy CountervailingPolicy
}

func NewClassifier(library PatternLibrary, countervailingPolicy CountervailingPolicy) (*Classifier, error) {
	if err := ValidatePatternLibrary(library); err != nil {
		return nil, err
	}
	required := []string{
		PatternAcronymCollision,
		PatternEntityTypeMismatch,
		PatternLegalControlContext,
		PatternMissingQualifier,
		PatternNarrativeDenialContext,
		PatternPhoneticTransliterationOnly,
		PatternRoutingBICCollision,
		PatternSubstringContainment,
		PatternTechnicalSystemArtifact,
		PatternWrongFieldDataType,
	}
	for _, code := range required {
		if _, ok := library.definition(code); !ok {
			return nil, fmt.Errorf("%w: required pattern %q is missing", ErrInvalidPatternLibrary, code)
		}
	}
	if err := ValidateCountervailingPolicy(countervailingPolicy); err != nil {
		return nil, err
	}
	return &Classifier{library: library, countervailingPolicy: countervailingPolicy}, nil
}

func (classifier *Classifier) ClassifyBatch(input ObservationBatch) (ClassificationBatch, error) {
	input = CanonicalizeObservationBatch(input)
	if err := ValidateObservationBatch(input); err != nil {
		return ClassificationBatch{}, err
	}
	output := ClassificationBatch{
		SchemaVersion:           ClassificationBatchSchema,
		InputObservationBatchID: input.BatchID,
		ClassifierVersion:       ClassifierVersion,
		PatternLibrary:          classifier.library.Reference(),
		CountervailingPolicy:    classifier.countervailingPolicy.Reference(),
		Classifications:         make([]Classification, 0, len(input.Observations)),
	}
	for _, observation := range input.Observations {
		classification := classifier.classify(observation)
		output.Classifications = append(output.Classifications, classification)
	}
	output.Summary = summarizeClassifications(output.Classifications)
	output.ClassificationBatchID = stableClassificationBatchID(output)
	if err := ValidateClassificationBatch(output); err != nil {
		return ClassificationBatch{}, err
	}
	return output, nil
}

func (classifier *Classifier) classify(observation Observation) Classification {
	patterns := make([]PatternEvidence, 0, 4)
	add := func(code, detail string) {
		definition, _ := classifier.library.definition(code)
		patterns = append(patterns, PatternEvidence{
			SchemaVersion:       PatternEvidenceSchema,
			Code:                code,
			StrengthBasisPoints: definition.DefaultStrengthBasisPoints,
			RouteHint:           definition.RouteHint,
			EscalationBlockers:  append([]string(nil), definition.EscalationBlockers...),
			ReasonCodes:         append([]string(nil), definition.ReasonCodes...),
			Detail:              detail,
		})
	}

	if strictSubstring(observation.InputValue, observation.WatchlistValue) {
		add(PatternSubstringContainment, fmt.Sprintf("watchlist value %q occurs only as a strict substring of input %q", observation.WatchlistValue, observation.InputValue))
	}
	if wrongFieldDataType(observation) {
		add(PatternWrongFieldDataType, fmt.Sprintf("%s field %q is incompatible with %s candidate retrieval through %s", observation.ValueType, observation.MatchedField, observation.WatchlistEntityType, observation.MatchRoute))
	}
	if entityTypeMismatch(observation) {
		add(PatternEntityTypeMismatch, fmt.Sprintf("candidate entity type %q is outside target entity types", observation.WatchlistEntityType))
	}
	if missing := missingQualifiers(observation); len(missing) > 0 {
		add(PatternMissingQualifier, "input is missing watchlist qualifier tokens: "+strings.Join(missing, ", "))
	}
	if routingBICCollision(observation) {
		add(PatternRoutingBICCollision, fmt.Sprintf("BIC value %q produced a non-exact identifier/name collision with %q", observation.InputValue, observation.WatchlistValue))
	}
	if acronymCollision(observation) {
		add(PatternAcronymCollision, fmt.Sprintf("short watchlist token %q collides with non-party field %q", observation.WatchlistValue, observation.MatchedField))
	}
	if phoneticTransliterationOnly(observation) {
		add(PatternPhoneticTransliterationOnly, "candidate is supported only by phonetic/transliteration evidence and lacks a secondary identifier")
	}
	if narrativeDenialContext(observation) {
		add(PatternNarrativeDenialContext, "matched narrative is inside explicit denial or non-relationship language")
	}
	if technicalArtifact(observation) {
		add(PatternTechnicalSystemArtifact, "matched value carries a migration, test, padding, or system-artifact marker")
	}
	if legalControlContext(observation) {
		add(PatternLegalControlContext, "matched party appears in trustee, receiver, liquidator, or other legal-control context")
	}

	sort.Slice(patterns, func(i, j int) bool { return patterns[i].Code < patterns[j].Code })
	countervailing := classifier.countervailingSignals(observation)
	blockers := make([]string, 0)
	requires := make([]string, 0)
	releaseSupport := 0
	strongest := 0
	for _, pattern := range patterns {
		blockers = append(blockers, pattern.EscalationBlockers...)
		if pattern.StrengthBasisPoints > strongest {
			strongest = pattern.StrengthBasisPoints
		}
		if pattern.RouteHint == RouteClearEligible {
			releaseSupport += pattern.StrengthBasisPoints
		}
		if pattern.Code == PatternPhoneticTransliterationOnly {
			requires = append(requires, "secondary_identifier")
		}
		if pattern.Code == PatternLegalControlContext {
			requires = append(requires, "legal_control_documentation")
		}
	}
	if releaseSupport > 10000 {
		releaseSupport = 10000
	}
	countervailingSupport := 0
	for _, signal := range countervailing {
		countervailingSupport += signal.StrengthBasisPoints
	}
	if countervailingSupport > 10000 {
		countervailingSupport = 10000
	}
	if len(countervailing) > 0 {
		if observation.TriggerPolicy != canonical.TriggerCandidateAlert {
			blockers = append(blockers, "supporting_evidence_cannot_escalate")
			requires = append(requires, "qualifying_candidate_alert")
		} else if !hasEscalationEligibleSignal(countervailing) {
			blockers = append(blockers, "primary_identifier_required")
			requires = append(requires, "primary_identifier")
		}
	}
	classification := Classification{
		SchemaVersion:         ClassificationSchemaVersion,
		Observation:           observation,
		ClassifierVersion:     ClassifierVersion,
		PatternLibrary:        classifier.library.Reference(),
		CountervailingPolicy:  classifier.countervailingPolicy.Reference(),
		Patterns:              patterns,
		CountervailingSignals: countervailing,
		RouteHint:             chooseRoute(patterns, countervailing, observation.TriggerPolicy),
		EscalationBlockers:    canonicalStrings(blockers),
		RequiresEvidence:      canonicalStrings(requires),
		Summary: ClassificationSummary{
			PatternCount:                     len(patterns),
			StrongestPatternBasisPoints:      strongest,
			ReleaseSupportBasisPoints:        releaseSupport,
			CountervailingSupportBasisPoints: countervailingSupport,
		},
	}
	classification.ClassificationID = stableClassificationID(classification)
	return classification
}

func strictSubstring(input, watchlist string) bool {
	left, right := compact(input), compact(watchlist)
	return len(right) >= 3 && left != right && strings.Contains(left, right) && !containsWholeTokenSequence(input, watchlist)
}

func wrongFieldDataType(observation Observation) bool {
	if observation.MatchRoute == canonical.RouteExactBIC || observation.MatchRoute == canonical.RouteExactLEI || observation.MatchRoute == canonical.RouteExactAccount || observation.MatchRoute == canonical.RouteExactDate {
		return false
	}
	switch string(observation.ValueType) {
	case "account_identifier", "iban", "payment_reference", "uetr", "amount", "count", "datetime":
		switch observation.MatchRoute {
		case canonical.RouteNormalizedName, canonical.RouteAlias, canonical.RouteTransliteration, canonical.RouteContextualPhrase:
			return true
		}
	}
	return false
}

func entityTypeMismatch(observation Observation) bool {
	if containsString(observation.MatcherDiagnosticCodes, "entity_type_mismatch") {
		return true
	}
	if len(observation.TargetEntityTypes) == 0 {
		return false
	}
	for _, candidateType := range observation.TargetEntityTypes {
		if candidateType == observation.WatchlistEntityType {
			return false
		}
	}
	return true
}

func missingQualifiers(observation Observation) []string {
	required := observation.RequiredQualifiers
	if len(required) == 0 {
		qualifierSet := map[string]struct{}{}
		for _, token := range tokens(observation.WatchlistValue) {
			switch token {
			case "BANK", "MINISTRY", "SHIPPING", "AIRWAYS", "FOUNDATION", "CORPORATION", "HOLDINGS", "TRUST", "AUTHORITY":
				qualifierSet[token] = struct{}{}
			}
		}
		for token := range qualifierSet {
			required = append(required, token)
		}
	}
	present := map[string]struct{}{}
	for _, token := range tokens(observation.InputValue) {
		present[token] = struct{}{}
	}
	for _, token := range observation.PresentQualifiers {
		present[normalizeText(token)] = struct{}{}
	}
	missing := make([]string, 0)
	for _, qualifier := range required {
		qualifier = normalizeText(qualifier)
		if qualifier == "" {
			continue
		}
		if _, exists := present[qualifier]; !exists {
			missing = append(missing, qualifier)
		}
	}
	return canonicalStrings(missing)
}

func routingBICCollision(observation Observation) bool {
	if string(observation.ValueType) != "bic" || observation.MatchRoute == canonical.RouteExactBIC {
		return false
	}
	needle := compact(observation.WatchlistValue)
	return len(needle) >= 2 && len(needle) <= 5 && strings.Contains(compact(observation.InputValue), needle)
}

func acronymCollision(observation Observation) bool {
	needle := compact(observation.WatchlistValue)
	if len(needle) < 2 || len(needle) > 5 || observation.Exact && observation.MatchRoute == canonical.RouteExactBIC {
		return false
	}
	switch string(observation.ValueType) {
	case "payment_reference", "account_identifier", "iban", "uetr":
		return strings.Contains(compact(observation.InputValue), needle)
	default:
		return false
	}
}

func phoneticTransliterationOnly(observation Observation) bool {
	if observation.Exact || len(observation.SecondaryIdentifierMatches) > 0 || len(observation.MatcherReasonCodes) == 0 {
		return false
	}
	allowed := map[string]struct{}{
		"name_fuzzy_phonetic":        {},
		"transliteration_fold_exact": {},
		"transliteration_only":       {},
	}
	for _, code := range observation.MatcherReasonCodes {
		if _, ok := allowed[code]; !ok {
			return false
		}
	}
	return true
}

func narrativeDenialContext(observation Observation) bool {
	if containsString(observation.MatcherDiagnosticCodes, "narrative_denial_context") {
		return true
	}
	value := normalizeText(observation.InputValue)
	markers := []string{"NO BUSINESS RELATIONSHIP", "NOT RELATED TO", "DO NOT PAY", "NO DEALINGS WITH", "REJECTED DUE TO"}
	for _, marker := range markers {
		if marker = normalizeText(marker); marker != "" && strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func technicalArtifact(observation Observation) bool {
	if len(observation.TechnicalMarkers) > 0 {
		return true
	}
	value := normalizeText(observation.InputValue)
	markers := []string{"MIGRATION", "TEST RECORD", "DUMMY", "SYSTEM GENERATED", "LEGACY PADDING"}
	for _, marker := range markers {
		if strings.Contains(value, marker) {
			return true
		}
	}
	compactValue := compact(value)
	return strings.Contains(compactValue, "0000000000") || strings.Contains(compactValue, "XXXXXXXXXX")
}

func legalControlContext(observation Observation) bool {
	value := normalizeText(observation.InputValue + " " + strings.Join(observation.ContextMarkers, " "))
	markers := []string{"BANKRUPTCY TRUSTEE", "COURT APPOINTED RECEIVER", "LIQUIDATOR", "INSOLVENCY ADMINISTRATOR", "RECEIVER FOR"}
	for _, marker := range markers {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func (classifier *Classifier) countervailingSignals(observation Observation) []CountervailingSignal {
	values := make([]CountervailingSignal, 0, 2)
	if observation.Exact {
		if rule, ok := classifier.countervailingPolicy.exactRouteRule(observation.MatchRoute, observation.TriggerPolicy); ok {
			values = append(values, CountervailingSignal{
				SchemaVersion:       CountervailingSignalSchemaVersion,
				Code:                rule.SignalCode,
				EvidenceClass:       rule.EvidenceClass,
				StrengthBasisPoints: rule.StrengthBasisPoints,
				EscalationEligible:  rule.EscalationEligible,
				Detail:              fmt.Sprintf("typed exact %s evidence is classified as %s", observation.MatchRoute, rule.EvidenceClass),
			})
		}
	}
	if len(observation.SecondaryIdentifierMatches) > 0 {
		rule := classifier.countervailingPolicy.SecondarySupportRule
		values = append(values, CountervailingSignal{
			SchemaVersion:       CountervailingSignalSchemaVersion,
			Code:                rule.SignalCode,
			EvidenceClass:       rule.EvidenceClass,
			StrengthBasisPoints: rule.StrengthBasisPoints,
			EscalationEligible:  rule.EscalationEligible,
			Detail:              "secondary identifiers matched: " + strings.Join(canonicalStrings(observation.SecondaryIdentifierMatches), ", "),
		})
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Code < values[j].Code })
	return values
}

func hasEscalationEligibleSignal(values []CountervailingSignal) bool {
	for _, signal := range values {
		if signal.EscalationEligible && signal.EvidenceClass == EvidenceClassPrimaryIdentifier {
			return true
		}
	}
	return false
}

func chooseRoute(patterns []PatternEvidence, countervailing []CountervailingSignal, triggerPolicy canonical.TriggerPolicy) RouteHint {
	hasStrongRelease := false
	hasManual := false
	hasInvestigate := false
	for _, pattern := range patterns {
		switch pattern.RouteHint {
		case RouteClearEligible:
			hasStrongRelease = true
		case RouteManualReview:
			hasManual = true
		case RouteInvestigate:
			hasInvestigate = true
		}
	}
	if len(countervailing) > 0 {
		if hasStrongRelease || hasManual || hasInvestigate {
			return RouteInvestigate
		}
		if triggerPolicy == canonical.TriggerCandidateAlert && hasEscalationEligibleSignal(countervailing) {
			return RouteEscalationCandidate
		}
		return RouteInvestigate
	}
	if hasManual {
		return RouteManualReview
	}
	if hasStrongRelease {
		return RouteClearEligible
	}
	return RouteInvestigate
}

func summarizeClassifications(values []Classification) BatchSummary {
	summary := BatchSummary{TotalObservations: len(values)}
	patterns := map[string]int{}
	routes := map[string]int{}
	blockers := map[string]int{}
	for _, classification := range values {
		routes[string(classification.RouteHint)]++
		for _, pattern := range classification.Patterns {
			patterns[pattern.Code]++
		}
		for _, blocker := range classification.EscalationBlockers {
			blockers[blocker]++
		}
	}
	summary.PatternCounts = namedCounts(patterns)
	summary.RouteHintCounts = namedCounts(routes)
	summary.BlockerCounts = namedCounts(blockers)
	return summary
}

func namedCounts(values map[string]int) []NamedCount {
	if len(values) == 0 {
		return nil
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]NamedCount, 0, len(names))
	for _, name := range names {
		out = append(out, NamedCount{Name: name, Count: values[name]})
	}
	return out
}
