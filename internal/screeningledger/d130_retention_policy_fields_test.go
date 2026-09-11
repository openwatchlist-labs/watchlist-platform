// ADR-0007 Addendum 14 D130 (F-F/F-G, LOW) test file (D131 item 8).
// store.go:256's `if input.Retention.MaxSnapshotBytes <= 0` conflated
// "unset" (0) and "invalid" (negative) as the same fact -- a caller
// asking for a STRICTER cap than zero got the 2 MiB default instead of a
// refusal, D114(b)'s own conflation one field over. This mirrors
// TestRetentionDaysDeclaredDomain's own pattern for the sibling field.
package screeningledger

import (
	"math"
	"strings"
	"testing"
)

func TestMaxSnapshotBytesDeclaredDomain(t *testing.T) {
	appendWith := func(t *testing.T, bytes int) (AppendResult, error) {
		t.Helper()
		store, err := NewStore(t.TempDir(), testKey(), uniqueID("d130"))
		if err != nil {
			t.Fatal(err)
		}
		input := testAppendInput()
		input.Retention.MaxSnapshotBytes = bytes
		return store.Append(input)
	}

	t.Run("zero_still_defaults_to_2MiB", func(t *testing.T) {
		res, err := appendWith(t, 0)
		if err != nil {
			t.Fatalf("expected MaxSnapshotBytes=0 to default rather than refuse, got: %v", err)
		}
		if res.Event.EventID == "" {
			t.Fatal("expected a successful append")
		}
	})
	t.Run("negative_1_refused", func(t *testing.T) {
		_, err := appendWith(t, -1)
		if err == nil {
			t.Fatal("ADR-0007 Addendum 14 D130: expected MaxSnapshotBytes=-1 to be refused rather than silently inverted into the 2 MiB default")
		}
		if !strings.Contains(err.Error(), "D130") {
			t.Fatalf("expected the refusal to cite D130, got: %v", err)
		}
	})
	t.Run("negative_1024_refused", func(t *testing.T) {
		_, err := appendWith(t, -1024)
		if err == nil {
			t.Fatal("ADR-0007 Addendum 14 D130: expected MaxSnapshotBytes=-1024 to be refused rather than silently inverted into the 2 MiB default")
		}
		if !strings.Contains(err.Error(), "D130") {
			t.Fatalf("expected the refusal to cite D130, got: %v", err)
		}
	})
	t.Run("MinInt64_refused", func(t *testing.T) {
		_, err := appendWith(t, math.MinInt64)
		if err == nil {
			t.Fatal("ADR-0007 Addendum 14 D130: expected MaxSnapshotBytes=MinInt64 to be refused rather than silently inverted into the 2 MiB default")
		}
		if !strings.Contains(err.Error(), "D130") {
			t.Fatalf("expected the refusal to cite D130, got: %v", err)
		}
	})
	t.Run("MaxInt64_accepted", func(t *testing.T) {
		// ADR-0007 Addendum 15 D134: neither of D114(b)'s two reasons for
		// an upper bound transfers to MaxSnapshotBytes -- it is read only
		// in a comparison (no arithmetic, no wrap cliff even at MaxInt64)
		// and never reaches the Event (no unreviewable obligation is
		// committed). No third branch is invented; MaxInt64 is accepted.
		res, err := appendWith(t, math.MaxInt64)
		if err != nil {
			t.Fatalf("expected MaxSnapshotBytes=MaxInt64 to be accepted (no upper bound is declared), got: %v", err)
		}
		if res.Event.EventID == "" {
			t.Fatal("expected a successful append")
		}
	})
	t.Run("positive_cap_still_enforced", func(t *testing.T) {
		store, err := NewStore(t.TempDir(), testKey(), uniqueID("d130-cap"))
		if err != nil {
			t.Fatal(err)
		}
		input := testAppendInput()
		input.Retention.MaxSnapshotBytes = 4
		input.RequestBytes = []byte(`{"much":"too big for a 4-byte cap"}`)
		if _, err := store.Append(input); err == nil {
			t.Fatal("expected a positive, stricter MaxSnapshotBytes to still be enforced against an oversized request")
		}
	})
}
