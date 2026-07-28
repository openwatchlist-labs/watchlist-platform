package ofacsource

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func Archive(root string, a Acquired, m SourceManifest) (string, error) {
	if err := ValidateManifest(m); err != nil {
		return "", err
	}
	if a.ContentSHA256 != m.ContentSHA256 || a.ContentLength != m.ContentLength {
		return "", fmt.Errorf("archive source differs from manifest")
	}
	if root == "" {
		return "", fmt.Errorf("archive root is required")
	}
	dir := filepath.Join(root, "ofac-sdn", a.ContentSHA256)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	if err := writeImmutable(filepath.Join(dir, "source.xml"), a.Bytes, 0o640); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	b = append(b, '\n')
	if err := writeImmutable(filepath.Join(dir, m.ManifestID+".manifest.json"), b, 0o640); err != nil {
		return "", err
	}
	return dir, nil
}
func writeImmutable(path string, data []byte, mode os.FileMode) error {
	old, err := os.ReadFile(path)
	if err == nil {
		if bytes.Equal(old, data) {
			return nil
		}
		return fmt.Errorf("immutable archive collision at %s", path)
	}
	if !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
