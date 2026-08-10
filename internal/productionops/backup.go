package productionops

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var fixedZipTime = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

func CreateBackup(archivePath string, roots []BackupRoot, createdAt time.Time) (BackupManifest, error) {
	var manifest BackupManifest
	if len(roots) == 0 {
		return manifest, errors.New("at least one backup root is required")
	}
	names := map[string]bool{}
	var entries []BackupEntry
	type src struct {
		entry BackupEntry
		path  string
	}
	var sources []src
	for _, root := range roots {
		if strings.TrimSpace(root.Name) == "" || strings.TrimSpace(root.Path) == "" {
			return manifest, errors.New("backup root name and path are required")
		}
		if names[root.Name] {
			return manifest, fmt.Errorf("duplicate backup root %s", root.Name)
		}
		names[root.Name] = true
		err := filepath.Walk(root.Path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			rel, err := filepath.Rel(root.Path, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			low := strings.ToLower(rel)
			if strings.Contains(low, "signing-key") || strings.HasSuffix(low, ".env") || strings.Contains(low, "secret") {
				return fmt.Errorf("backup refuses secret-like file %s", path)
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			e := BackupEntry{Root: root.Name, Path: rel, SHA256: sha256Hex(b), Size: int64(len(b)), Mode: uint32(info.Mode().Perm())}
			entries = append(entries, e)
			sources = append(sources, src{e, path})
			return nil
		})
		if err != nil {
			return manifest, err
		}
	}
	sort.Slice(sources, func(i, j int) bool {
		a, b := sources[i].entry, sources[j].entry
		if a.Root == b.Root {
			return a.Path < b.Path
		}
		return a.Root < b.Root
	})
	entries = entries[:0]
	var total int64
	for _, s := range sources {
		entries = append(entries, s.entry)
		total += s.entry.Size
	}
	contentHash, err := objectHash(entries)
	if err != nil {
		return manifest, err
	}
	manifest = BackupManifest{SchemaVersion: BackupManifestSchemaV1, BackupID: "backup_" + contentHash[:24], CreatedAt: createdAt.UTC().Format(time.RFC3339Nano), Entries: entries, EntryCount: len(entries), TotalBytes: total, ContentSHA256: contentHash}
	if err = os.MkdirAll(filepath.Dir(archivePath), 0700); err != nil {
		return manifest, err
	}
	tmp := archivePath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return manifest, err
	}
	zw := zip.NewWriter(f)
	mb, _ := json.Marshal(manifest)
	if err = zipWrite(zw, "manifest.json", mb, 0600); err == nil {
		for _, s := range sources {
			b, e := os.ReadFile(s.path)
			if e != nil {
				err = e
				break
			}
			if e = zipWrite(zw, "data/"+s.entry.Root+"/"+s.entry.Path, b, os.FileMode(s.entry.Mode)); e != nil {
				err = e
				break
			}
		}
	}
	cerr := zw.Close()
	ferr := f.Close()
	if err == nil {
		err = cerr
	}
	if err == nil {
		err = ferr
	}
	if err != nil {
		os.Remove(tmp)
		return manifest, err
	}
	if err = os.Rename(tmp, archivePath); err != nil {
		return manifest, err
	}
	return manifest, nil
}
func zipWrite(zw *zip.Writer, name string, b []byte, mode os.FileMode) error {
	h := &zip.FileHeader{Name: name, Method: zip.Deflate}
	h.Modified = fixedZipTime
	h.SetMode(mode)
	w, err := zw.CreateHeader(h)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}
func VerifyBackup(path string) (BackupManifest, error) {
	var m BackupManifest
	r, err := zip.OpenReader(path)
	if err != nil {
		return m, err
	}
	defer r.Close()
	files := map[string]*zip.File{}
	for _, f := range r.File {
		files[f.Name] = f
	}
	mf := files["manifest.json"]
	if mf == nil {
		return m, errors.New("backup manifest is missing")
	}
	b, err := readZip(mf)
	if err != nil {
		return m, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&m); err != nil {
		return m, err
	}
	if m.SchemaVersion != BackupManifestSchemaV1 {
		return m, errors.New("unsupported backup manifest")
	}
	if m.EntryCount != len(m.Entries) {
		return m, errors.New("backup entry count mismatch")
	}
	h, _ := objectHash(m.Entries)
	if h != m.ContentSHA256 || m.BackupID != "backup_"+h[:24] {
		return m, errors.New("backup manifest checksum mismatch")
	}
	var total int64
	for _, e := range m.Entries {
		zf := files["data/"+e.Root+"/"+e.Path]
		if zf == nil {
			return m, fmt.Errorf("backup entry missing: %s/%s", e.Root, e.Path)
		}
		raw, err := readZip(zf)
		if err != nil {
			return m, err
		}
		if int64(len(raw)) != e.Size || sha256Hex(raw) != e.SHA256 {
			return m, fmt.Errorf("backup entry checksum mismatch: %s/%s", e.Root, e.Path)
		}
		total += int64(len(raw))
	}
	if total != m.TotalBytes {
		return m, errors.New("backup total bytes mismatch")
	}
	return m, nil
}
func readZip(f *zip.File) ([]byte, error) {
	r, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, 64<<20))
}
func RestoreBackup(path, target string) (BackupManifest, error) {
	m, err := VerifyBackup(path)
	if err != nil {
		return m, err
	}
	r, err := zip.OpenReader(path)
	if err != nil {
		return m, err
	}
	defer r.Close()
	for _, f := range r.File {
		if !strings.HasPrefix(f.Name, "data/") {
			continue
		}
		rel := strings.TrimPrefix(f.Name, "data/")
		clean := filepath.Clean(filepath.FromSlash(rel))
		if clean == "." || strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return m, errors.New("unsafe backup path")
		}
		dst := filepath.Join(target, clean)
		if err = os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
			return m, err
		}
		raw, err := readZip(f)
		if err != nil {
			return m, err
		}
		tmp := dst + ".tmp"
		if err = os.WriteFile(tmp, raw, f.Mode().Perm()); err != nil {
			return m, err
		}
		if err = os.Rename(tmp, dst); err != nil {
			return m, err
		}
	}
	return m, nil
}
