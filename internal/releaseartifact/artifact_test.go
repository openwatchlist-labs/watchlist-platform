package releaseartifact

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManifestBundle(t *testing.T) {
	d := t.TempDir()
	os.Mkdir(filepath.Join(d, "x"), 0755)
	os.WriteFile(filepath.Join(d, "a.txt"), []byte("a\n"), 0644)
	os.WriteFile(filepath.Join(d, "x", "b.txt"), []byte("b\n"), 0755)
	m, e := BuildManifest(d, "v", "c", 1, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = Verify(d, m); e != nil {
		t.Fatal(e)
	}
	z := filepath.Join(t.TempDir(), "x.zip")
	if e = Bundle(d, z, m); e != nil {
		t.Fatal(e)
	}
	if e = VerifyBundle(z, m); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(d, "a.txt"), []byte("bad"), 0644)
	if Verify(d, m) == nil {
		t.Fatal("tamper accepted")
	}
}
