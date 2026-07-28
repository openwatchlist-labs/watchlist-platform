package screeningapiv8e

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningapiv8d"
)

type boundUpstream struct {
	delegate screeningapiv8d.Upstream
	expected screeningapiv8d.Lineage
}

func (u *boundUpstream) Ready(ctx context.Context) error {
	return u.delegate.Ready(ctx)
}

func (u *boundUpstream) Post(ctx context.Context, path string, body []byte, correlationID, idempotencyKey string) (int, []byte, error) {
	status, raw, err := u.delegate.Post(ctx, path, body, correlationID, idempotencyKey)
	if err != nil {
		return status, raw, err
	}
	if err := validateResponseLineage(raw, u.expected); err != nil {
		return 0, nil, fmt.Errorf("active_catalog_lineage_mismatch: %w", err)
	}
	return status, raw, nil
}

func validateResponseLineage(raw []byte, expected screeningapiv8d.Lineage) error {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("decode upstream response: %w", err)
	}
	found := 0
	var walk func(any) error
	walk = func(current any) error {
		switch typed := current.(type) {
		case map[string]any:
			if lineageValue, ok := typed["lineage"]; ok {
				lineage, ok := lineageValue.(map[string]any)
				if !ok {
					return fmt.Errorf("lineage is not an object")
				}
				found++
				checks := map[string]string{
					"provider":              expected.Provider,
					"catalog_id":            expected.CatalogID,
					"component_id":          expected.ComponentID,
					"component_version":     expected.ComponentVersion,
					"activation_id":         expected.ActivationID,
					"normalization_profile": expected.NormalizationProfile,
				}
				for key, expectedValue := range checks {
					actual, _ := lineage[key].(string)
					if actual != expectedValue {
						return fmt.Errorf("%s=%q expected %q", key, actual, expectedValue)
					}
				}
			}
			for _, child := range typed {
				if err := walk(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range typed {
				if err := walk(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(value); err != nil {
		return err
	}
	if found == 0 {
		return fmt.Errorf("upstream response contains no catalog lineage")
	}
	return nil
}
