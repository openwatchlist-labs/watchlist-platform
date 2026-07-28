package alertcase

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGeneratedIDValidationRejectsTraversal(t *testing.T) {
	invalid := []string{
		"", ".", "..", "../outside", `..\\outside`, "/tmp/outside",
		`C:\\outside`, "alert_../../outside", "alert_" + strings.Repeat("a", 31),
		"alert_" + strings.Repeat("A", 32), "alert_" + strings.Repeat("g", 32),
		"case_../../outside", "case_" + strings.Repeat("a", 31),
		"case_" + strings.Repeat("A", 32), "case_" + strings.Repeat("g", 32),
		"alert_" + strings.Repeat("a", 32) + "\x00suffix",
	}
	for _, value := range invalid {
		if strings.HasPrefix(value, "case_") || value == "" || value == "." || value == ".." || strings.Contains(value, "outside") {
			if err := validateCaseID(value); err == nil {
				t.Fatalf("validateCaseID accepted %q", value)
			}
		}
		if strings.HasPrefix(value, "alert_") || value == "" || value == "." || value == ".." || strings.Contains(value, "outside") {
			if err := validateAlertID(value); err == nil {
				t.Fatalf("validateAlertID accepted %q", value)
			}
		}
	}
	if err := validateAlertID("alert_" + strings.Repeat("a", 32)); err != nil {
		t.Fatal(err)
	}
	if err := validateCaseID("case_" + strings.Repeat("b", 32)); err != nil {
		t.Fatal(err)
	}
}

func TestStoreBoundariesRejectTraversalWithoutOutsideAccess(t *testing.T) {
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
		if _, err := store.Alert(id); err == nil {
			t.Fatalf("Alert accepted %q", id)
		}
		if _, err := store.Case(id); err == nil {
			t.Fatalf("Case accepted %q", id)
		}
		if _, err := store.VerifyCase(id); err == nil {
			t.Fatalf("VerifyCase accepted %q", id)
		}
		if _, err := store.LastCaseEvent(id); err == nil {
			t.Fatalf("LastCaseEvent accepted %q", id)
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

func TestConfinedStatePathRejectsSymlinkEscape(t *testing.T) {
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
	if err := os.Symlink(outside, filepath.Join(root, "alerts")); err != nil {
		t.Fatal(err)
	}
	store := &Store{Dir: root}
	if _, err := store.alertPath("alert_" + strings.Repeat("a", 32)); err == nil {
		t.Fatal("alertPath accepted symlinked state namespace")
	}
}
