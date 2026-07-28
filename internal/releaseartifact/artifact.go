package releaseartifact

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const ManifestSchemaV1 = "openwatchlist.release-artifact-manifest.v1"

type Entry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
}
type Manifest struct {
	SchemaVersion   string  `json:"schema_version"`
	Version         string  `json:"version"`
	VCSRef          string  `json:"vcs_ref"`
	SourceDateEpoch int64   `json:"source_date_epoch"`
	Entries         []Entry `json:"entries"`
	EntryCount      int     `json:"entry_count"`
	TotalBytes      int64   `json:"total_bytes"`
	ContentSHA256   string  `json:"content_sha256"`
	ManifestSHA256  string  `json:"manifest_sha256"`
}

func BuildManifest(root, version, vcsRef string, epoch int64, excludes []string) (Manifest, error) {
	root, _ = filepath.Abs(root)
	ex := map[string]bool{}
	for _, x := range excludes {
		ex[filepath.ToSlash(strings.TrimPrefix(filepath.Clean(x), "./"))] = true
	}
	m := Manifest{SchemaVersion: ManifestSchemaV1, Version: version, VCSRef: vcsRef, SourceDateEpoch: epoch}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, e := filepath.Rel(root, p)
		if e != nil {
			return e
		}
		rel = filepath.ToSlash(rel)
		if ex[rel] {
			return nil
		}
		info, e := d.Info()
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular file in release tree: %s", rel)
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		h := sha256.Sum256(b)
		m.Entries = append(m.Entries, Entry{Path: rel, SHA256: hex.EncodeToString(h[:]), Size: int64(len(b)), Mode: uint32(info.Mode().Perm())})
		m.TotalBytes += int64(len(b))
		return nil
	})
	if err != nil {
		return Manifest{}, err
	}
	sort.Slice(m.Entries, func(i, j int) bool { return m.Entries[i].Path < m.Entries[j].Path })
	m.EntryCount = len(m.Entries)
	ch := sha256.New()
	for _, e := range m.Entries {
		fmt.Fprintf(ch, "%s  %s\n", e.SHA256, e.Path)
	}
	m.ContentSHA256 = hex.EncodeToString(ch.Sum(nil))
	mh, err := manifestHash(m)
	if err != nil {
		return Manifest{}, err
	}
	m.ManifestSHA256 = mh
	return m, nil
}
func manifestHash(m Manifest) (string, error) {
	m.ManifestSHA256 = ""
	b, e := json.Marshal(m)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func Verify(root string, m Manifest) error {
	if m.SchemaVersion != ManifestSchemaV1 {
		return fmt.Errorf("unsupported manifest schema %q", m.SchemaVersion)
	}
	h, e := manifestHash(m)
	if e != nil {
		return e
	}
	if h != m.ManifestSHA256 {
		return fmt.Errorf("manifest checksum mismatch")
	}
	actual, e := BuildManifest(root, m.Version, m.VCSRef, m.SourceDateEpoch, nil)
	if e != nil {
		return e
	}
	if actual.ContentSHA256 != m.ContentSHA256 || actual.EntryCount != m.EntryCount || actual.TotalBytes != m.TotalBytes {
		return errors.New("release tree content mismatch")
	}
	return nil
}
func WriteManifest(path string, m Manifest) error {
	b, e := json.MarshalIndent(m, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, append(b, '\n'), 0644)
}
func ReadManifest(path string) (Manifest, error) {
	var m Manifest
	b, e := os.ReadFile(path)
	if e != nil {
		return m, e
	}
	e = json.Unmarshal(b, &m)
	return m, e
}
func Bundle(root, out string, m Manifest) error {
	f, e := os.Create(out)
	if e != nil {
		return e
	}
	zw := zip.NewWriter(f)
	epoch := time.Unix(m.SourceDateEpoch, 0).UTC()
	if m.SourceDateEpoch == 0 {
		epoch = time.Unix(0, 0).UTC()
	}
	for _, x := range m.Entries {
		p := filepath.Join(root, filepath.FromSlash(x.Path))
		b, e := os.ReadFile(p)
		if e != nil {
			zw.Close()
			f.Close()
			return e
		}
		h := &zip.FileHeader{Name: x.Path, Method: zip.Deflate}
		h.SetMode(fs.FileMode(x.Mode))
		h.Modified = epoch
		w, e := zw.CreateHeader(h)
		if e != nil {
			zw.Close()
			f.Close()
			return e
		}
		if _, e = w.Write(b); e != nil {
			zw.Close()
			f.Close()
			return e
		}
	}
	if e = zw.Close(); e != nil {
		f.Close()
		return e
	}
	return f.Close()
}
func VerifyBundle(path string, m Manifest) error {
	r, e := zip.OpenReader(path)
	if e != nil {
		return e
	}
	defer r.Close()
	if len(r.File) != len(m.Entries) {
		return errors.New("bundle entry count mismatch")
	}
	for i, z := range r.File {
		exp := m.Entries[i]
		if z.Name != exp.Path {
			return fmt.Errorf("bundle order/path mismatch at %d", i)
		}
		rc, e := z.Open()
		if e != nil {
			return e
		}
		h := sha256.New()
		n, e := io.Copy(h, rc)
		rc.Close()
		if e != nil {
			return e
		}
		if n != exp.Size || hex.EncodeToString(h.Sum(nil)) != exp.SHA256 {
			return fmt.Errorf("bundle entry mismatch: %s", z.Name)
		}
	}
	return nil
}
