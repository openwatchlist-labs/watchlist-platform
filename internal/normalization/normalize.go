package normalization

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	ProfileNone        = "none"
	ProfilePartyName   = "party_name_v1"
	ProfileBIC         = "bic_v1"
	ProfileLEI         = "lei_v1"
	ProfileIBAN        = "iban_v1"
	ProfileCountryCode = "country_code_v1"
	ProfileAddress     = "address_v1"
	ProfileContextText = "text_context_v1"
	ProfileReference   = "reference_v1"
	ProfileIdentifier  = "identifier_v1"
	ProfileAmount      = "amount_v1"
	ProfileDate        = "date_v1"
	ProfileDateTime    = "datetime_v1"
)

func Normalize(profile, value string) (string, error) {
	switch profile {
	case ProfileNone:
		return value, nil
	case ProfilePartyName, ProfileAddress, ProfileContextText, ProfileReference:
		return strings.ToUpper(collapseWhitespace(value)), nil
	case ProfileBIC, ProfileLEI, ProfileIBAN, ProfileIdentifier:
		return strings.ToUpper(removeWhitespace(value)), nil
	case ProfileCountryCode:
		return strings.ToUpper(strings.TrimSpace(value)), nil
	case ProfileAmount, ProfileDate, ProfileDateTime:
		return strings.TrimSpace(value), nil
	default:
		return "", fmt.Errorf("unsupported normalization profile %q", profile)
	}
}

func collapseWhitespace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func removeWhitespace(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(value))
}
