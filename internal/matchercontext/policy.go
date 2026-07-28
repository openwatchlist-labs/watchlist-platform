package matchercontext

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

var ErrInvalidPolicySet = errors.New("invalid jurisdiction policy set")

func LoadPolicySet(reader io.Reader) (JurisdictionPolicySet, error) {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var set JurisdictionPolicySet
	if err := decoder.Decode(&set); err != nil {
		return JurisdictionPolicySet{}, fmt.Errorf("%w: decode: %v", ErrInvalidPolicySet, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return JurisdictionPolicySet{}, fmt.Errorf("%w: multiple JSON values are not allowed", ErrInvalidPolicySet)
		}
		return JurisdictionPolicySet{}, fmt.Errorf("%w: trailing data: %v", ErrInvalidPolicySet, err)
	}
	if err := ValidatePolicySet(set); err != nil {
		return JurisdictionPolicySet{}, err
	}
	return set, nil
}

func ValidatePolicySet(set JurisdictionPolicySet) error {
	if set.SchemaVersion != PolicySetSchemaVersion {
		return fmt.Errorf("%w: schema_version must be %q", ErrInvalidPolicySet, PolicySetSchemaVersion)
	}
	for field, value := range map[string]string{
		"policy_set_id": set.PolicySetID, "policy_set_version": set.PolicySetVersion,
		"policy_set_checksum": set.PolicySetChecksum, "source.source_id": set.Source.SourceID,
		"source.authority": set.Source.Authority, "source.list_id": set.Source.ListID,
		"source.source_version": set.Source.SourceVersion,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidPolicySet, field)
		}
	}
	if err := validateDigest(set.PolicySetChecksum, "policy_set_checksum", ErrInvalidPolicySet); err != nil {
		return err
	}
	if len(set.Entries) == 0 {
		return fmt.Errorf("%w: entries must not be empty", ErrInvalidPolicySet)
	}
	previous := ""
	aliases := map[string]string{}
	for index, entry := range set.Entries {
		for field, value := range map[string]string{
			"entry_id": entry.EntryID, "country_code_alpha2": entry.CountryCodeAlpha2,
			"country_name": entry.CountryName, "status": entry.Status,
		} {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("%w: entries[%d].%s is required", ErrInvalidPolicySet, index, field)
			}
		}
		if index > 0 && previous >= entry.EntryID {
			return fmt.Errorf("%w: entries must be sorted by unique entry_id", ErrInvalidPolicySet)
		}
		previous = entry.EntryID
		if entry.CountryCodeAlpha2 != strings.ToUpper(entry.CountryCodeAlpha2) || len(entry.CountryCodeAlpha2) != 2 {
			return fmt.Errorf("%w: entries[%d].country_code_alpha2 must be a two-letter uppercase code", ErrInvalidPolicySet, index)
		}
		if entry.CountryCodeAlpha3 != "" && (entry.CountryCodeAlpha3 != strings.ToUpper(entry.CountryCodeAlpha3) || len(entry.CountryCodeAlpha3) != 3) {
			return fmt.Errorf("%w: entries[%d].country_code_alpha3 must be a three-letter uppercase code", ErrInvalidPolicySet, index)
		}
		if entry.Status != PolicyStatusRestricted {
			return fmt.Errorf("%w: entries[%d].status must be %q", ErrInvalidPolicySet, index, PolicyStatusRestricted)
		}
		if fold(entry.CountryName) != entry.CountryName {
			return fmt.Errorf("%w: entries[%d].country_name must be folded uppercase", ErrInvalidPolicySet, index)
		}
		if !sort.StringsAreSorted(entry.Aliases) || !sort.StringsAreSorted(entry.Programs) {
			return fmt.Errorf("%w: entries[%d] aliases and programs must be sorted", ErrInvalidPolicySet, index)
		}
		all := append([]string{entry.CountryCodeAlpha2, entry.CountryCodeAlpha3, entry.CountryName}, entry.Aliases...)
		for _, alias := range all {
			if alias == "" {
				continue
			}
			if fold(alias) != alias {
				return fmt.Errorf("%w: entries[%d] aliases must be folded uppercase", ErrInvalidPolicySet, index)
			}
			if owner, exists := aliases[alias]; exists && owner != entry.EntryID {
				return fmt.Errorf("%w: alias %q is shared by entries %q and %q", ErrInvalidPolicySet, alias, owner, entry.EntryID)
			}
			aliases[alias] = entry.EntryID
		}
	}
	if expected := StablePolicySetChecksum(set); set.PolicySetChecksum != expected {
		return fmt.Errorf("%w: policy_set_checksum=%q expected %q", ErrInvalidPolicySet, set.PolicySetChecksum, expected)
	}
	return nil
}

func StablePolicySetChecksum(set JurisdictionPolicySet) string {
	parts := []string{PolicySetSchemaVersion, set.PolicySetID, set.PolicySetVersion, set.Source.SourceID, set.Source.Authority, set.Source.ListID, set.Source.SourceVersion}
	entries := append([]JurisdictionEntry(nil), set.Entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].EntryID < entries[j].EntryID })
	for _, entry := range entries {
		parts = append(parts, entry.EntryID, entry.CountryCodeAlpha2, entry.CountryCodeAlpha3, entry.CountryName, strings.Join(entry.Aliases, "\x1e"), entry.Status, strings.Join(entry.Programs, "\x1e"))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(sum[:])
}
