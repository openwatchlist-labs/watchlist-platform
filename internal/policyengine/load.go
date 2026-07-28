package policyengine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

var (
	ErrInvalidPolicy  = errors.New("invalid transaction screening policy")
	ErrInvalidOverlay = errors.New("invalid tenant policy overlay")
)

func LoadPolicy(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("%w: read: %v", ErrInvalidPolicy, err)
	}
	mapping, err := parseYAMLMap(data)
	if err != nil {
		return Policy{}, fmt.Errorf("%w: yaml: %v", ErrInvalidPolicy, err)
	}
	var policy Policy
	if err := decodeStrictMapping(mapping, &policy); err != nil {
		return Policy{}, fmt.Errorf("%w: decode: %v", ErrInvalidPolicy, err)
	}
	if err := ValidatePolicy(policy); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

func LoadOverlay(path string, base Policy) (Overlay, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Overlay{}, fmt.Errorf("%w: read: %v", ErrInvalidOverlay, err)
	}
	mapping, err := parseYAMLMap(data)
	if err != nil {
		return Overlay{}, fmt.Errorf("%w: yaml: %v", ErrInvalidOverlay, err)
	}
	var overlay Overlay
	if err := decodeStrictMapping(mapping, &overlay); err != nil {
		return Overlay{}, fmt.Errorf("%w: decode: %v", ErrInvalidOverlay, err)
	}
	if err := ValidateOverlay(overlay, base); err != nil {
		return Overlay{}, err
	}
	return overlay, nil
}

func decodeStrictMapping(mapping map[string]any, target any) error {
	data, err := json.Marshal(mapping)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing value")
		}
		return err
	}
	return nil
}

func PolicyChecksum(policy Policy) string {
	copy := policy
	copy.PolicyChecksum = ""
	data, _ := json.Marshal(copy)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func OverlayChecksum(overlay Overlay) string {
	copy := overlay
	copy.OverlayChecksum = ""
	data, _ := json.Marshal(copy)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (policy Policy) Reference() PolicyReference {
	return PolicyReference{PolicyID: policy.PolicyID, PolicyVersion: policy.PolicyVersion, PolicyChecksum: policy.PolicyChecksum}
}

func (overlay Overlay) Reference() OverlayReference {
	return OverlayReference{OverlayID: overlay.OverlayID, OverlayVersion: overlay.OverlayVersion, OverlayChecksum: overlay.OverlayChecksum, TenantID: overlay.TenantID}
}

func required(value, path string, sentinel error) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: %s is required", sentinel, path)
	}
	return nil
}
