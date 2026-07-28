package screeningplan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
	"github.com/openwatchlist-labs/watchlist-platform/internal/normalization"
)

var (
	ErrInvalidPlan = errors.New("invalid screening plan")
	ErrNoMatch     = errors.New("no screening-plan entry matched")
	ErrAmbiguous   = errors.New("multiple screening-plan entries matched")
)

type compiledEntry struct {
	entry Entry
	path  *regexp.Regexp
}

type CompiledPlan struct {
	plan        Plan
	checksum    string
	entries     []compiledEntry
	definitions map[canonical.MessageDefinition]struct{}
}

func Compile(plan Plan) (*CompiledPlan, error) {
	if err := validatePlan(plan); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		return nil, fmt.Errorf("%w: checksum encoding: %v", ErrInvalidPlan, err)
	}
	sum := sha256.Sum256(encoded)
	compiled := &CompiledPlan{
		plan:        plan,
		checksum:    "sha256:" + hex.EncodeToString(sum[:]),
		definitions: make(map[canonical.MessageDefinition]struct{}, len(plan.MessageDefinitions)),
	}
	for _, definition := range plan.MessageDefinitions {
		compiled.definitions[definition] = struct{}{}
	}
	for _, entry := range plan.Entries {
		path, err := compilePathPattern(entry.PathPattern)
		if err != nil {
			return nil, fmt.Errorf("%w: entry %q: %v", ErrInvalidPlan, entry.ID, err)
		}
		compiled.entries = append(compiled.entries, compiledEntry{entry: entry, path: path})
	}
	return compiled, nil
}

func (plan *CompiledPlan) ID() string       { return plan.plan.ID }
func (plan *CompiledPlan) Version() string  { return plan.plan.Version }
func (plan *CompiledPlan) Checksum() string { return plan.checksum }
func (plan *CompiledPlan) EntryCount() int  { return len(plan.entries) }

func (plan *CompiledPlan) Supports(definition canonical.MessageDefinition) bool {
	_, ok := plan.definitions[definition]
	return ok
}

func (plan *CompiledPlan) Resolve(definition canonical.MessageDefinition, nativePath string) (Entry, error) {
	if !plan.Supports(definition) {
		return Entry{}, fmt.Errorf("%w: message definition %q", ErrNoMatch, definition)
	}
	var matched *Entry
	for _, candidate := range plan.entries {
		if !candidate.path.MatchString(nativePath) {
			continue
		}
		if matched != nil {
			return Entry{}, fmt.Errorf("%w: path %q matched %q and %q", ErrAmbiguous, nativePath, matched.ID, candidate.entry.ID)
		}
		copy := candidate.entry
		matched = &copy
	}
	if matched == nil {
		return Entry{}, fmt.Errorf("%w: %s", ErrNoMatch, nativePath)
	}
	return *matched, nil
}

func (plan *CompiledPlan) Apply(element *canonical.ScreenableElement, entry Entry) {
	element.SemanticRole = entry.SemanticRole
	element.PartyRole = entry.PartyRole
	element.ValueType = entry.ValueType
	element.ScreeningPlan = canonical.ScreeningPlanReference{
		PlanID:       plan.ID(),
		PlanVersion:  plan.Version(),
		PlanChecksum: plan.Checksum(),
		EntryID:      entry.ID,
	}
	element.Screening = canonical.ScreeningDirective{
		TriggerPolicy:         entry.TriggerPolicy,
		MatchRoutes:           append([]canonical.MatchRoute(nil), entry.MatchRoutes...),
		AllowedCandidateTypes: append([]canonical.CandidateType(nil), entry.AllowedCandidateTypes...),
		NormalizationProfile:  entry.NormalizationProfile,
		ThresholdProfile:      entry.ThresholdProfile,
		SupportingFields:      append([]canonical.SemanticRole(nil), entry.SupportingFields...),
	}
}

func compilePathPattern(pattern string) (*regexp.Regexp, error) {
	if !strings.HasPrefix(pattern, "/Document/") {
		return nil, fmt.Errorf("path_pattern must start with /Document/")
	}
	withoutIndexes := strings.ReplaceAll(pattern, "[*]", "")
	if strings.Contains(withoutIndexes, "*") {
		return nil, fmt.Errorf("only [*] index wildcards are supported")
	}
	escaped := regexp.QuoteMeta(pattern)
	escaped = strings.ReplaceAll(escaped, `\[\*\]`, `\[\d+\]`)
	return regexp.Compile("^" + escaped + "$")
}

func validatePlan(plan Plan) error {
	if plan.SchemaVersion != SchemaVersion {
		return planError("schema_version must be %q", SchemaVersion)
	}
	if strings.TrimSpace(plan.ID) == "" || strings.TrimSpace(plan.Version) == "" {
		return planError("id and version are required")
	}
	if len(plan.MessageDefinitions) == 0 {
		return planError("at least one message_definition is required")
	}
	definitionSeen := map[canonical.MessageDefinition]struct{}{}
	for _, definition := range plan.MessageDefinitions {
		if strings.TrimSpace(string(definition)) == "" {
			return planError("message_definition cannot be empty")
		}
		if _, exists := definitionSeen[definition]; exists {
			return planError("duplicate message_definition %q", definition)
		}
		definitionSeen[definition] = struct{}{}
	}
	if len(plan.Entries) == 0 {
		return planError("at least one entry is required")
	}

	idSeen := map[string]struct{}{}
	pathSeen := map[string]struct{}{}
	for index, entry := range plan.Entries {
		prefix := fmt.Sprintf("entries[%d]", index)
		if strings.TrimSpace(entry.ID) == "" {
			return planError("%s.id is required", prefix)
		}
		if _, exists := idSeen[entry.ID]; exists {
			return planError("duplicate entry id %q", entry.ID)
		}
		idSeen[entry.ID] = struct{}{}
		if _, exists := pathSeen[entry.PathPattern]; exists {
			return planError("duplicate path_pattern %q", entry.PathPattern)
		}
		pathSeen[entry.PathPattern] = struct{}{}
		if _, err := compilePathPattern(entry.PathPattern); err != nil {
			return planError("%s.path_pattern: %v", prefix, err)
		}
		if strings.TrimSpace(string(entry.SemanticRole)) == "" || strings.TrimSpace(string(entry.ValueType)) == "" {
			return planError("%s semantic_role and value_type are required", prefix)
		}
		if _, err := normalization.Normalize(entry.NormalizationProfile, "test"); err != nil {
			return planError("%s.normalization_profile: %v", prefix, err)
		}
		if strings.TrimSpace(entry.ThresholdProfile) == "" {
			return planError("%s.threshold_profile is required", prefix)
		}
		switch entry.TriggerPolicy {
		case canonical.TriggerCandidateAlert:
			if len(entry.MatchRoutes) == 0 {
				return planError("%s candidate_alert requires match_routes", prefix)
			}
		case canonical.TriggerSupportingEvidence:
			if len(entry.MatchRoutes) == 0 {
				return planError("%s supporting_evidence requires match_routes", prefix)
			}
		case canonical.TriggerRetainOnly, canonical.TriggerDisabled:
			if len(entry.MatchRoutes) != 0 || len(entry.AllowedCandidateTypes) != 0 {
				return planError("%s %s cannot define routes or candidate types", prefix, entry.TriggerPolicy)
			}
		default:
			return planError("%s unsupported trigger_policy %q", prefix, entry.TriggerPolicy)
		}
		if err := validateRoutes(entry); err != nil {
			return planError("%s: %v", prefix, err)
		}
	}
	return nil
}

func validateRoutes(entry Entry) error {
	for _, route := range entry.MatchRoutes {
		switch route {
		case canonical.RouteNormalizedName, canonical.RouteAlias, canonical.RouteTransliteration:
			if entry.ValueType != "name" {
				return fmt.Errorf("route %q requires value_type name", route)
			}
		case canonical.RouteExactBIC:
			if entry.ValueType != "bic" {
				return fmt.Errorf("route exact_bic requires value_type bic")
			}
		case canonical.RouteExactLEI:
			if entry.ValueType != "lei" {
				return fmt.Errorf("route exact_lei requires value_type lei")
			}
		case canonical.RouteExactAccount:
			if entry.ValueType != "iban" && entry.ValueType != "account_identifier" {
				return fmt.Errorf("route exact_account requires iban or account_identifier")
			}
		case canonical.RouteExactDate:
			if entry.ValueType != "date" {
				return fmt.Errorf("route exact_date requires value_type date")
			}
		case canonical.RouteJurisdictionPolicy:
			if entry.ValueType != "country_code" {
				return fmt.Errorf("route jurisdiction_policy requires country_code")
			}
		case canonical.RouteContextualAddress:
			if entry.ValueType != "address_text" {
				return fmt.Errorf("route contextual_address requires address_text")
			}
		case canonical.RouteContextualPhrase:
			if entry.ValueType != "narrative" {
				return fmt.Errorf("route contextual_phrase_window requires narrative")
			}
		default:
			return fmt.Errorf("unsupported match route %q", route)
		}
	}
	return nil
}

func planError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidPlan, fmt.Sprintf(format, args...))
}
