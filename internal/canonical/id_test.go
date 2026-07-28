package canonical

import "testing"

func TestStableElementID(t *testing.T) {
	tx := 2
	first := StableElementID("fixture:one", "pacs.008.001.08", "MSG-1", &tx, "/Document/X[2]/Nm", 0)
	second := StableElementID("fixture:one", "pacs.008.001.08", "MSG-1", &tx, "/Document/X[2]/Nm", 0)
	if first != second {
		t.Fatalf("stable IDs differ: %q != %q", first, second)
	}
	if first == StableElementID("fixture:two", "pacs.008.001.08", "MSG-1", &tx, "/Document/X[2]/Nm", 0) {
		t.Fatal("source reference must participate in stable ID")
	}
}
