package ofacruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
)

const maxPackageBytes = 512 << 20

func Load(data []byte) (*LoadedPackage, error) {
	if len(data) < len(PackageMagic)+16 || len(data) > maxPackageBytes {
		return nil, fmt.Errorf("%w: invalid artifact size", ErrInvalidPackage)
	}
	artifactSum := sha256.Sum256(data)
	reader := bytes.NewReader(data)
	magic := make([]byte, len(PackageMagic))
	if _, err := io.ReadFull(reader, magic); err != nil || string(magic) != PackageMagic {
		return nil, fmt.Errorf("%w: invalid package magic", ErrInvalidPackage)
	}
	var manifestLength uint64
	if err := binary.Read(reader, binary.BigEndian, &manifestLength); err != nil || manifestLength == 0 || manifestLength > uint64(reader.Len()) {
		return nil, fmt.Errorf("%w: invalid manifest length", ErrInvalidPackage)
	}
	manifestBytes := make([]byte, manifestLength)
	if _, err := io.ReadFull(reader, manifestBytes); err != nil {
		return nil, fmt.Errorf("%w: read manifest: %v", ErrInvalidPackage, err)
	}
	var manifest PackageManifest
	if err := decodeStrict(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("%w: decode manifest: %v", ErrInvalidPackage, err)
	}
	if err := ValidateManifest(manifest); err != nil {
		return nil, err
	}
	var payloadLength uint64
	if err := binary.Read(reader, binary.BigEndian, &payloadLength); err != nil || payloadLength == 0 || payloadLength > uint64(reader.Len()) {
		return nil, fmt.Errorf("%w: invalid payload length", ErrInvalidPackage)
	}
	payloadBytes := make([]byte, payloadLength)
	if _, err := io.ReadFull(reader, payloadBytes); err != nil {
		return nil, fmt.Errorf("%w: read payload: %v", ErrInvalidPackage, err)
	}
	if reader.Len() != 0 {
		return nil, fmt.Errorf("%w: trailing bytes are not allowed", ErrInvalidPackage)
	}
	if int64(payloadLength) != manifest.PayloadSize {
		return nil, fmt.Errorf("%w: payload size mismatch", ErrInvalidPackage)
	}
	payloadSum := sha256.Sum256(payloadBytes)
	if hex.EncodeToString(payloadSum[:]) != manifest.PayloadSHA256 {
		return nil, fmt.Errorf("%w: payload checksum mismatch", ErrInvalidPackage)
	}
	var payload RuntimePayload
	if err := decodeStrict(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("%w: decode payload: %v", ErrInvalidPackage, err)
	}
	if err := ValidatePayload(payload); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(payload.Provider, manifest.Provider) || payload.SourceManifestID != manifest.SourceManifestID || payload.RecordCount != manifest.RecordCount || payload.EntryCount != manifest.EntryCount {
		return nil, fmt.Errorf("%w: manifest and payload lineage differ", ErrInvalidPackage)
	}
	provider, err := NewProvider(payload)
	if err != nil {
		return nil, err
	}
	info := PackageInfo{
		SchemaVersion:   PackageInfoSchemaVersion,
		PackageID:       manifest.PackageID,
		PackageChecksum: hex.EncodeToString(artifactSum[:]),
		ArtifactSize:    int64(len(data)),
		Manifest:        manifest,
	}
	if err := ValidateInfo(info); err != nil {
		return nil, err
	}
	return &LoadedPackage{Info: info, Payload: payload, Provider: provider}, nil
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}
