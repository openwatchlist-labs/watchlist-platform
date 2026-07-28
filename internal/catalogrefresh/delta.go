package catalogrefresh

import (
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/ofaccatalog"
)

func BuildDelta(base, target ofaccatalog.Catalog, sequence uint64, generatedAt time.Time) (Delta, error) {
	report, err := Diff(base, target)
	if err != nil {
		return Delta{}, err
	}
	baseMap := recordMap(base.Records)
	targetMap := recordMap(target.Records)
	var operations []DeltaOperation
	for _, id := range report.RemovedRecordIDs {
		hash, err := sha256JSON(baseMap[id])
		if err != nil {
			return Delta{}, err
		}
		operations = append(operations, DeltaOperation{Operation: OperationRemove, ProviderRecordID: id, BeforeRecordSHA256: hash})
	}
	for _, id := range report.ModifiedRecordIDs {
		hash, err := sha256JSON(baseMap[id])
		if err != nil {
			return Delta{}, err
		}
		record := targetMap[id]
		operations = append(operations, DeltaOperation{Operation: OperationReplace, ProviderRecordID: id, BeforeRecordSHA256: hash, After: &record})
	}
	for _, id := range report.AddedRecordIDs {
		record := targetMap[id]
		operations = append(operations, DeltaOperation{Operation: OperationAdd, ProviderRecordID: id, After: &record})
	}
	sort.Slice(operations, func(i, j int) bool { return operations[i].ProviderRecordID < operations[j].ProviderRecordID })
	delta := Delta{SchemaVersion: DeltaSchemaVersion, Sequence: sequence, Base: CatalogReference(base), Target: CatalogReference(target), TargetSourceManifest: target.SourceManifest, GeneratedAt: generatedAt.UTC(), Operations: operations}
	checksum, err := deltaChecksum(delta)
	if err != nil {
		return Delta{}, err
	}
	delta.DeltaChecksum = checksum
	delta.DeltaID = stableID("catalog_delta", struct {
		Sequence     uint64
		Base, Target CatalogRef
		Checksum     string
	}{sequence, delta.Base, delta.Target, checksum})
	return delta, ValidateDelta(delta)
}

func Apply(base ofaccatalog.Catalog, delta Delta, expectedSequence uint64) (ofaccatalog.Catalog, error) {
	if err := ofaccatalog.ValidateCatalog(base); err != nil {
		return ofaccatalog.Catalog{}, fmt.Errorf("base catalog: %w", err)
	}
	if err := ValidateDelta(delta); err != nil {
		return ofaccatalog.Catalog{}, err
	}
	if delta.Sequence != expectedSequence {
		return ofaccatalog.Catalog{}, fmt.Errorf("delta sequence mismatch: got %d want %d", delta.Sequence, expectedSequence)
	}
	if delta.Base != CatalogReference(base) {
		return ofaccatalog.Catalog{}, fmt.Errorf("delta base catalog mismatch")
	}
	records := recordMap(base.Records)
	for _, operation := range delta.Operations {
		current, exists := records[operation.ProviderRecordID]
		switch operation.Operation {
		case OperationAdd:
			if exists || operation.After == nil || operation.After.ProviderRecordID != operation.ProviderRecordID {
				return ofaccatalog.Catalog{}, fmt.Errorf("invalid add operation for %s", operation.ProviderRecordID)
			}
			records[operation.ProviderRecordID] = *operation.After
		case OperationReplace:
			if !exists || operation.After == nil || operation.After.ProviderRecordID != operation.ProviderRecordID {
				return ofaccatalog.Catalog{}, fmt.Errorf("invalid replace operation for %s", operation.ProviderRecordID)
			}
			hash, err := sha256JSON(current)
			if err != nil || hash != operation.BeforeRecordSHA256 {
				return ofaccatalog.Catalog{}, fmt.Errorf("replace precondition mismatch for %s", operation.ProviderRecordID)
			}
			records[operation.ProviderRecordID] = *operation.After
		case OperationRemove:
			if !exists || operation.After != nil {
				return ofaccatalog.Catalog{}, fmt.Errorf("invalid remove operation for %s", operation.ProviderRecordID)
			}
			hash, err := sha256JSON(current)
			if err != nil || hash != operation.BeforeRecordSHA256 {
				return ofaccatalog.Catalog{}, fmt.Errorf("remove precondition mismatch for %s", operation.ProviderRecordID)
			}
			delete(records, operation.ProviderRecordID)
		default:
			return ofaccatalog.Catalog{}, fmt.Errorf("unsupported delta operation %q", operation.Operation)
		}
	}
	out := ofaccatalog.Catalog{SchemaVersion: ofaccatalog.CatalogSchemaVersion, CatalogID: delta.Target.CatalogID, CatalogVersion: delta.Target.CatalogVersion, CatalogMode: base.CatalogMode, ProjectorVersion: base.ProjectorVersion, SourceManifest: delta.TargetSourceManifest}
	for _, record := range records {
		out.Records = append(out.Records, record)
	}
	sort.Slice(out.Records, func(i, j int) bool { return uidNumber(out.Records[i].SourceUID) < uidNumber(out.Records[j].SourceUID) })
	out.RecordCount = len(out.Records)
	checksum, err := ofaccatalog.Checksum(out)
	if err != nil {
		return ofaccatalog.Catalog{}, err
	}
	out.CatalogChecksum = checksum
	if out.RecordCount != delta.Target.RecordCount || out.CatalogChecksum != delta.Target.CatalogChecksum {
		return ofaccatalog.Catalog{}, fmt.Errorf("reconstructed target identity mismatch")
	}
	if err := ofaccatalog.ValidateCatalog(out); err != nil {
		return ofaccatalog.Catalog{}, err
	}
	return out, nil
}

func deltaChecksum(delta Delta) (string, error) {
	material := struct {
		SchemaVersion        string
		Sequence             uint64
		Base, Target         CatalogRef
		TargetSourceManifest any
		GeneratedAt          time.Time
		Operations           []DeltaOperation
	}{delta.SchemaVersion, delta.Sequence, delta.Base, delta.Target, delta.TargetSourceManifest, delta.GeneratedAt.UTC(), delta.Operations}
	return sha256JSON(material)
}

func uidNumber(value string) int { n, _ := strconv.Atoi(value); return n }
