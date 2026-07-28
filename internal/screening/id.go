package screening

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/canonical"
)

func stableBundleID(bundle EvidenceBundle) string {
	parts := []string{
		EvidenceBundleSchemaVersion,
		bundle.SourcePayloadReference,
		string(bundle.MessageDefinition),
		bundle.MessageID,
		bundle.ParserVersion,
		bundle.ExecutorVersion,
		bundle.ScreeningPlan.PlanID,
		bundle.ScreeningPlan.PlanVersion,
		bundle.ScreeningPlan.PlanChecksum,
	}
	for _, element := range bundle.Elements {
		parts = append(parts, element.EvidenceID)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return "bundle_" + hex.EncodeToString(sum[:12])
}

func stableEvidenceID(element canonical.ScreenableElement, planChecksum, entryID string) string {
	tx := ""
	if element.TransactionIndex != nil {
		tx = strconv.Itoa(*element.TransactionIndex)
	}
	warningParts := make([]string, 0, len(element.Warnings))
	for _, warning := range element.Warnings {
		warningParts = append(warningParts, strings.Join([]string{string(warning.Severity), warning.Code, warning.Message, warning.Path}, "\x1e"))
	}
	attributeKeys := make([]string, 0, len(element.Attributes))
	for key := range element.Attributes {
		attributeKeys = append(attributeKeys, key)
	}
	sort.Strings(attributeKeys)
	attributeParts := make([]string, 0, len(attributeKeys))
	for _, key := range attributeKeys {
		attributeParts = append(attributeParts, key+"="+element.Attributes[key])
	}
	parts := []string{
		ElementEvidenceSchemaVersion,
		element.ElementID,
		element.ParserVersion,
		planChecksum,
		entryID,
		tx,
		string(element.Presence),
		element.OriginalValue,
		element.NormalizedValue,
		strings.Join(attributeParts, "\x1e"),
		strings.Join(warningParts, "\x1d"),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return "evidence_" + hex.EncodeToString(sum[:12])
}

func stableEvidenceIDFromEvidence(element ElementEvidence, planChecksum string) string {
	canonicalElement := canonical.ScreenableElement{
		ElementID:        element.ElementID,
		TransactionIndex: element.TransactionIndex,
		Presence:         element.Presence,
		OriginalValue:    element.OriginalValue,
		NormalizedValue:  element.NormalizedValue,
		Attributes:       element.Attributes,
		ParserVersion:    element.ParserVersion,
		Warnings:         element.Warnings,
	}
	return stableEvidenceID(canonicalElement, planChecksum, element.Resolution.EntryID)
}
