package catalogrefresh

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/openwatchlist-labs/watchlist-platform/internal/ofacsource"
)

var ErrInvalidRefresh = errors.New("invalid catalog refresh contract")

func ValidateDelta(delta Delta) error {
	if delta.SchemaVersion != DeltaSchemaVersion || delta.DeltaID == "" || delta.Sequence == 0 || delta.Base.CatalogChecksum == "" || delta.Target.CatalogChecksum == "" || delta.GeneratedAt.IsZero() {
		return fmt.Errorf("%w: invalid delta header", ErrInvalidRefresh)
	}
	if err := ofacsource.ValidateManifest(delta.TargetSourceManifest); err != nil {
		return fmt.Errorf("%w: target source manifest: %v", ErrInvalidRefresh, err)
	}
	if delta.TargetSourceManifest.ManifestID == "" || delta.Target.RecordCount < 1 {
		return fmt.Errorf("%w: invalid target identity", ErrInvalidRefresh)
	}
	seen := map[string]struct{}{}
	last := ""
	for i, operation := range delta.Operations {
		if operation.ProviderRecordID == "" || (last != "" && operation.ProviderRecordID < last) {
			return fmt.Errorf("%w: operations not canonically ordered at %d", ErrInvalidRefresh, i)
		}
		last = operation.ProviderRecordID
		if _, ok := seen[operation.ProviderRecordID]; ok {
			return fmt.Errorf("%w: duplicate operation for %s", ErrInvalidRefresh, operation.ProviderRecordID)
		}
		seen[operation.ProviderRecordID] = struct{}{}
		switch operation.Operation {
		case OperationAdd:
			if operation.After == nil || operation.BeforeRecordSHA256 != "" {
				return fmt.Errorf("%w: invalid add", ErrInvalidRefresh)
			}
		case OperationReplace:
			if operation.After == nil || len(operation.BeforeRecordSHA256) != 64 {
				return fmt.Errorf("%w: invalid replace", ErrInvalidRefresh)
			}
		case OperationRemove:
			if operation.After != nil || len(operation.BeforeRecordSHA256) != 64 {
				return fmt.Errorf("%w: invalid remove", ErrInvalidRefresh)
			}
		default:
			return fmt.Errorf("%w: unsupported operation", ErrInvalidRefresh)
		}
	}
	wantChecksum, err := deltaChecksum(delta)
	if err != nil || wantChecksum != delta.DeltaChecksum {
		return fmt.Errorf("%w: delta checksum mismatch", ErrInvalidRefresh)
	}
	wantID := stableID("catalog_delta", struct {
		Sequence     uint64
		Base, Target CatalogRef
		Checksum     string
	}{delta.Sequence, delta.Base, delta.Target, delta.DeltaChecksum})
	if delta.DeltaID != wantID {
		return fmt.Errorf("%w: delta id mismatch", ErrInvalidRefresh)
	}
	return nil
}

func ValidateDiff(report DiffReport) error {
	if report.SchemaVersion != DiffSchemaVersion || report.ReportID == "" || report.Base.CatalogChecksum == "" || report.Target.CatalogChecksum == "" {
		return fmt.Errorf("%w: invalid diff header", ErrInvalidRefresh)
	}
	if report.TotalChanges != report.Added+report.Modified+report.Removed || report.ChangeRatioBasisPoints < 0 || report.ChangeRatioBasisPoints > 10000 || report.DeletionRatioBasisPoints < 0 || report.DeletionRatioBasisPoints > 10000 {
		return fmt.Errorf("%w: invalid diff counts", ErrInvalidRefresh)
	}
	return nil
}

func ValidatePolicy(policy PromotionPolicy) error {
	if policy.SchemaVersion != PolicySchemaVersion || strings.TrimSpace(policy.PolicyID) == "" || strings.TrimSpace(policy.PolicyVersion) == "" {
		return fmt.Errorf("%w: invalid policy header", ErrInvalidRefresh)
	}
	if policy.MaxChangeRatioBasisPoints < 1 || policy.MaxChangeRatioBasisPoints > 10000 || policy.MaxDeletionRatioBasisPoints < 1 || policy.MaxDeletionRatioBasisPoints > 10000 || policy.MaxOperations < 1 {
		return fmt.Errorf("%w: invalid policy thresholds", ErrInvalidRefresh)
	}
	return nil
}

func LoadDelta(path string) (Delta, error) {
	var value Delta
	return value, decodeFile(path, &value, func() error { return ValidateDelta(value) })
}
func LoadPolicy(path string) (PromotionPolicy, error) {
	var value PromotionPolicy
	return value, decodeFile(path, &value, func() error { return ValidatePolicy(value) })
}

func decodeFile(path string, target any, validate func() error) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err = decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing JSON value")
	}
	return validate()
}

func CanonicalizeReasons(reasons []DecisionReason) []DecisionReason {
	out := append([]DecisionReason(nil), reasons...)
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}
