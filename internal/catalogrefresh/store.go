package catalogrefresh

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func PersistDecision(root string, decision PromotionDecision) (string, error) {
	if decision.SchemaVersion != DecisionSchemaVersion || decision.DecisionID == "" {
		return "", fmt.Errorf("invalid promotion decision")
	}
	path := filepath.Join(root, "promotion-decisions", decision.DecisionID+".json")
	data, err := json.MarshalIndent(decision, "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if old, readErr := os.ReadFile(path); readErr == nil {
		if !bytes.Equal(old, data) {
			return "", fmt.Errorf("immutable promotion decision collision at %s", path)
		}
		return path, nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return "", readErr
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", err
	}
	if _, err = file.Write(data); err != nil {
		_ = file.Close()
		return "", err
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return "", err
	}
	return path, file.Close()
}

func PersistDelta(root string, delta Delta) (string, error) {
	if err := ValidateDelta(delta); err != nil {
		return "", err
	}
	path := filepath.Join(root, "deltas", delta.DeltaID+".json")
	data, err := json.MarshalIndent(delta, "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if old, readErr := os.ReadFile(path); readErr == nil {
		if !bytes.Equal(old, data) {
			return "", fmt.Errorf("immutable delta collision at %s", path)
		}
		return path, nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return "", readErr
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", err
	}
	if _, err = file.Write(data); err != nil {
		_ = file.Close()
		return "", err
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return "", err
	}
	return path, file.Close()
}
