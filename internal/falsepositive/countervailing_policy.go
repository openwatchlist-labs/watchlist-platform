package falsepositive

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
)

var ErrInvalidCountervailingPolicy = errors.New("invalid countervailing evidence policy")

func LoadCountervailingPolicy(path string) (CountervailingPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return CountervailingPolicy{}, fmt.Errorf("%w: read: %v", ErrInvalidCountervailingPolicy, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var policy CountervailingPolicy
	if err := decoder.Decode(&policy); err != nil {
		return CountervailingPolicy{}, fmt.Errorf("%w: decode: %v", ErrInvalidCountervailingPolicy, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return CountervailingPolicy{}, fmt.Errorf("%w: trailing JSON value", ErrInvalidCountervailingPolicy)
		}
		return CountervailingPolicy{}, fmt.Errorf("%w: trailing JSON: %v", ErrInvalidCountervailingPolicy, err)
	}
	if err := ValidateCountervailingPolicy(policy); err != nil {
		return CountervailingPolicy{}, err
	}
	return policy, nil
}

func ValidateCountervailingPolicy(policy CountervailingPolicy) error {
	if policy.SchemaVersion != CountervailingPolicySchemaVersion {
		return fmt.Errorf("%w: schema_version must be %q", ErrInvalidCountervailingPolicy, CountervailingPolicySchemaVersion)
	}
	for field, value := range map[string]string{
		"policy_id":       policy.PolicyID,
		"policy_version":  policy.PolicyVersion,
		"policy_checksum": policy.PolicyChecksum,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidCountervailingPolicy, field)
		}
	}
	if len(policy.ExactRouteRules) == 0 {
		return fmt.Errorf("%w: exact_route_rules are required", ErrInvalidCountervailingPolicy)
	}
	seen := map[canonical.MatchRoute]struct{}{}
	for index, rule := range policy.ExactRouteRules {
		if !isTypedExactRoute(rule.MatchRoute) {
			return fmt.Errorf("%w: exact_route_rules[%d].match_route %q is not a typed exact route", ErrInvalidCountervailingPolicy, index, rule.MatchRoute)
		}
		if _, exists := seen[rule.MatchRoute]; exists {
			return fmt.Errorf("%w: duplicate match route %q", ErrInvalidCountervailingPolicy, rule.MatchRoute)
		}
		seen[rule.MatchRoute] = struct{}{}
		if err := validateCountervailingRule(rule, fmt.Sprintf("exact_route_rules[%d]", index)); err != nil {
			return err
		}
	}
	if !sort.SliceIsSorted(policy.ExactRouteRules, func(i, j int) bool {
		return policy.ExactRouteRules[i].MatchRoute < policy.ExactRouteRules[j].MatchRoute
	}) {
		return fmt.Errorf("%w: exact_route_rules must be ordered by match_route", ErrInvalidCountervailingPolicy)
	}
	for _, route := range []canonical.MatchRoute{
		canonical.RouteExactAccount,
		canonical.RouteExactBIC,
		canonical.RouteExactDate,
		canonical.RouteExactLEI,
	} {
		if _, exists := seen[route]; !exists {
			return fmt.Errorf("%w: required typed exact route %q is missing", ErrInvalidCountervailingPolicy, route)
		}
	}
	secondary := policy.SecondarySupportRule
	if secondary.EvidenceClass != EvidenceClassSecondarySupport {
		return fmt.Errorf("%w: secondary_identifier_support_rule.evidence_class must be %q", ErrInvalidCountervailingPolicy, EvidenceClassSecondarySupport)
	}
	if strings.TrimSpace(secondary.SignalCode) == "" {
		return fmt.Errorf("%w: secondary_identifier_support_rule.signal_code is required", ErrInvalidCountervailingPolicy)
	}
	if secondary.StrengthBasisPoints < 0 || secondary.StrengthBasisPoints > 10000 {
		return fmt.Errorf("%w: secondary_identifier_support_rule strength outside 0..10000", ErrInvalidCountervailingPolicy)
	}
	if secondary.EscalationEligible {
		return fmt.Errorf("%w: secondary identifier support cannot independently escalate", ErrInvalidCountervailingPolicy)
	}
	if expected := CountervailingPolicyChecksum(policy); policy.PolicyChecksum != expected {
		return fmt.Errorf("%w: policy_checksum=%q expected %q", ErrInvalidCountervailingPolicy, policy.PolicyChecksum, expected)
	}
	return nil
}

func validateCountervailingRule(rule CountervailingRule, path string) error {
	if !validEvidenceClass(rule.EvidenceClass) {
		return fmt.Errorf("%w: %s.evidence_class %q is invalid", ErrInvalidCountervailingPolicy, path, rule.EvidenceClass)
	}
	if strings.TrimSpace(rule.SignalCode) == "" {
		return fmt.Errorf("%w: %s.signal_code is required", ErrInvalidCountervailingPolicy, path)
	}
	if rule.StrengthBasisPoints < 0 || rule.StrengthBasisPoints > 10000 {
		return fmt.Errorf("%w: %s strength outside 0..10000", ErrInvalidCountervailingPolicy, path)
	}
	if len(rule.AllowedTriggerPolicies) == 0 {
		return fmt.Errorf("%w: %s.allowed_trigger_policies are required", ErrInvalidCountervailingPolicy, path)
	}
	if !sort.SliceIsSorted(rule.AllowedTriggerPolicies, func(i, j int) bool {
		return rule.AllowedTriggerPolicies[i] < rule.AllowedTriggerPolicies[j]
	}) {
		return fmt.Errorf("%w: %s.allowed_trigger_policies must be sorted", ErrInvalidCountervailingPolicy, path)
	}
	canonicalTriggers := append([]canonical.TriggerPolicy(nil), rule.AllowedTriggerPolicies...)
	canonicalTriggers = compactTriggerPolicies(canonicalTriggers)
	if !reflect.DeepEqual(rule.AllowedTriggerPolicies, canonicalTriggers) {
		return fmt.Errorf("%w: %s.allowed_trigger_policies must be unique", ErrInvalidCountervailingPolicy, path)
	}
	for _, trigger := range rule.AllowedTriggerPolicies {
		switch trigger {
		case canonical.TriggerCandidateAlert, canonical.TriggerSupportingEvidence:
		default:
			return fmt.Errorf("%w: %s trigger policy %q is unsupported", ErrInvalidCountervailingPolicy, path, trigger)
		}
	}
	if rule.EscalationEligible && rule.EvidenceClass != EvidenceClassPrimaryIdentifier {
		return fmt.Errorf("%w: %s only primary identifiers may be escalation eligible", ErrInvalidCountervailingPolicy, path)
	}
	return nil
}

func CountervailingPolicyChecksum(policy CountervailingPolicy) string {
	copy := policy
	copy.PolicyChecksum = ""
	data, _ := json.Marshal(copy)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (policy CountervailingPolicy) Reference() CountervailingPolicyReference {
	return CountervailingPolicyReference{
		PolicyID:       policy.PolicyID,
		PolicyVersion:  policy.PolicyVersion,
		PolicyChecksum: policy.PolicyChecksum,
	}
}

func (policy CountervailingPolicy) exactRouteRule(route canonical.MatchRoute, trigger canonical.TriggerPolicy) (CountervailingRule, bool) {
	index := sort.Search(len(policy.ExactRouteRules), func(index int) bool {
		return policy.ExactRouteRules[index].MatchRoute >= route
	})
	if index >= len(policy.ExactRouteRules) || policy.ExactRouteRules[index].MatchRoute != route {
		return CountervailingRule{}, false
	}
	rule := policy.ExactRouteRules[index]
	for _, allowed := range rule.AllowedTriggerPolicies {
		if allowed == trigger {
			return rule, true
		}
	}
	return CountervailingRule{}, false
}

func isTypedExactRoute(route canonical.MatchRoute) bool {
	switch route {
	case canonical.RouteExactAccount, canonical.RouteExactBIC, canonical.RouteExactDate, canonical.RouteExactLEI:
		return true
	default:
		return false
	}
}

func validEvidenceClass(value EvidenceClass) bool {
	switch value {
	case EvidenceClassPrimaryIdentifier, EvidenceClassSecondaryAttribute, EvidenceClassSecondarySupport:
		return true
	default:
		return false
	}
}

func compactTriggerPolicies(values []canonical.TriggerPolicy) []canonical.TriggerPolicy {
	if len(values) == 0 {
		return nil
	}
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}
