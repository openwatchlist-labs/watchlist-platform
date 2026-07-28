package assistancerag

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAssistanceIdentifiersRejectTraversal(t *testing.T) {
	invalidAssistance := []string{
		"", ".", "..", "../outside", `..\\outside`, "/tmp/outside", `C:\\outside`,
		"assistance_../../outside", "assistance_" + strings.Repeat("a", 23),
		"assistance_" + strings.Repeat("A", 24), "assistance_" + strings.Repeat("g", 24),
		"assistance_" + strings.Repeat("a", 24) + "\x00suffix",
	}
	for _, id := range invalidAssistance {
		if err := validateAssistanceID(id); err == nil {
			t.Fatalf("validateAssistanceID accepted %q", id)
		}
	}
	if err := validateAssistanceID("assistance_" + strings.Repeat("a", 24)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "../outside", `..\\outside`, "/tmp/outside", `C:\\outside`, "case_" + strings.Repeat("A", 32)} {
		if err := validateCaseID(id); err == nil {
			t.Fatalf("validateCaseID accepted %q", id)
		}
	}
}

func TestRecordBoundaryRejectsTraversalWithoutOutsideAccess(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "state")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "outside.json")
	if err := os.WriteFile(outside, []byte("sentinel\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := &Store{Dir: root}
	for _, id := range []string{"../outside", `..\\outside`, "/tmp/outside", `C:\\outside`} {
		if _, err := store.Record(id); err == nil {
			t.Fatalf("Record accepted %q", id)
		}
		if _, err := store.reviewBySequence(id, "1"); err == nil {
			t.Fatalf("reviewBySequence accepted %q", id)
		}
	}
	raw, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "sentinel\n" {
		t.Fatalf("outside file changed: %q", raw)
	}
}

func TestAssistancePathRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires platform privileges")
	}
	parent := t.TempDir()
	root := filepath.Join(parent, "state")
	outside := filepath.Join(parent, "outside")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "assistance")); err != nil {
		t.Fatal(err)
	}
	store := &Store{Dir: root}
	if _, err := store.assistancePath("assistance_" + strings.Repeat("a", 24)); err == nil {
		t.Fatal("assistancePath accepted symlinked state namespace")
	}
}
