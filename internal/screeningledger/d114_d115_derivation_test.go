// ADR-0007 Addendum 13 D122 items 1-5: the derivation axis's own test
// obligations for D114(a)/(b)/(c) and D115, DSN-free -- every value this
// addendum's CRITICAL and its own sweep-discovered defect touch is
// local-chain arithmetic and policy validation, none of it requiring a
// live Postgres mirror. Every test below failed before its change, per
// CLAUDE.md rule 5: TestMustExpiresUTCFirstBoundary and
// TestMustExpiresUnparseableOccurredAtIsANamedError against the shipped
// int64-nanosecond Duration arithmetic and the wall-clock substitution
// respectively; TestRetentionDaysDeclaredDomain against the shipped
// unbounded `<= 0` conflation; TestMinAnchorSequenceValidateBound
// against the shipped bare int64(...) conversion with no Validate()
// check at all.
package screeningledger

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// shippedMustExpires reconstructs the pre-D114 arithmetic verbatim
// (the shipped int64-nanosecond time.Duration form this addendum
// replaces), so TestMustExpiresUTCFirstBoundary can state, in one
// table, both where the two arithmetics part company and what each
// side actually produces there -- D106's own rule, discharged here in
// terms rather than by proxy.
func shippedMustExpires(occurred string, days int) (string, error) {
	parsed, err := time.Parse(time.RFC3339Nano, occurred)
	if err != nil {
		return "", err
	}
	return parsed.Add(time.Duration(days) * 24 * time.Hour).UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano), nil
}

// TestMustExpiresUTCFirstBoundary is D122 item 1: table-driven over the
// 106,751/106,752-day boundary and both sides of it, through the real
// unmodified mustExpires, set beside the shipped arithmetic it replaces.
// {1,2555,3650,90000,106750,106751} are correct (future, and the two
// arithmetics AGREE) both today and after; {106752,109500,200000,
// 1000000} are past-dated TODAY (the shipped arithmetic, reconstructed
// above) and correct (future) after (the real mustExpires -- unbounded
// in itself; D114(b)'s declared refusal for these values is
// Store.Append's job, covered by TestRetentionDaysDeclaredDomain, not
// mustExpires's). Plus math.MaxInt32, which is the case that proves the
// class rather than the values: under the SHIPPED arithmetic it is a
// plausible-looking FUTURE date (2165-11-23T16:17:09Z) despite having
// silently wrapped nowhere near that far -- no, despite the risk of
// wrapping being invisible at that scale -- so a test asserting only
// "the result is in the past" would not have caught the class the
// shipped arithmetic was vulnerable to.
func TestMustExpiresUTCFirstBoundary(t *testing.T) {
	occurred := "2000-01-01T00:00:00Z"
	occurredParsed, err := time.Parse(time.RFC3339Nano, occurred)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		days            int
		wantShippedPast bool
		wantAgree       bool
	}{
		{1, false, true}, {2555, false, true}, {3650, false, true}, {90000, false, true},
		{106750, false, true}, {106751, false, true},
		{106752, true, false}, {109500, true, false}, {200000, true, false}, {1000000, true, false},
	}
	for _, c := range cases {
		shipped, err := shippedMustExpires(occurred, c.days)
		if err != nil {
			t.Fatalf("days=%d: shippedMustExpires: %v", c.days, err)
		}
		shippedParsed, err := time.Parse(time.RFC3339Nano, shipped)
		if err != nil {
			t.Fatalf("days=%d: shipped value unparseable: %v", c.days, err)
		}
		shippedPast := shippedParsed.Before(occurredParsed)
		if shippedPast != c.wantShippedPast {
			t.Errorf("days=%d: shipped=%s past=%v, want past=%v", c.days, shipped, shippedPast, c.wantShippedPast)
		}

		fixed, err := mustExpires(occurred, c.days)
		if err != nil {
			t.Fatalf("days=%d: mustExpires: unexpected error: %v", c.days, err)
		}
		fixedParsed, err := time.Parse(time.RFC3339Nano, fixed)
		if err != nil {
			t.Fatalf("days=%d: mustExpires produced an unparseable result %q: %v", c.days, fixed, err)
		}
		if fixedParsed.Before(occurredParsed) && !c.wantShippedPast {
			t.Errorf("days=%d: fixed value %s is in the past, want future (this is an in-domain value)", c.days, fixed)
		}
		agree := shippedParsed.Equal(fixedParsed)
		if agree != c.wantAgree {
			t.Errorf("days=%d: shipped=%s fixed=%s agree=%v, want agree=%v", c.days, shipped, fixed, agree, c.wantAgree)
		}
	}

	// math.MaxInt32 is the case that proves the class rather than the
	// values, and it is out of both mustExpires's declared domain
	// (Store.Append's own 36525-day bound refuses it long before this
	// function ever runs) AND R53's own bound: the shipped arithmetic
	// produces a plausible-looking FUTURE date despite the surrounding
	// class's overflow risk (2165-11-23, not obviously wrong to a
	// reviewer eyeballing it -- the point CAP #12/D113 made about
	// detectability), while UTC-first AddDate -- which removes the
	// int64-ns wrap entirely -- moves the failure class rather than
	// erasing it (D114(b)'s own table): the result is year 5881610,
	// which time.RFC3339Nano cannot even format/re-parse round-trip.
	// This is R53's declared residual, kept out of reach by Store.Append's
	// bound rather than by mustExpires itself.
	shippedMax, err := shippedMustExpires(occurred, math.MaxInt32)
	if err != nil {
		t.Fatal(err)
	}
	shippedMaxParsed, err := time.Parse(time.RFC3339Nano, shippedMax)
	if err != nil {
		t.Fatalf("shipped math.MaxInt32 value unparseable: %v", err)
	}
	if !shippedMaxParsed.After(occurredParsed) {
		t.Fatalf("expected the shipped arithmetic's math.MaxInt32 result to be a plausible FUTURE date (the detectability finding), got %s", shippedMax)
	}
	fixedMax, err := mustExpires(occurred, math.MaxInt32)
	if err != nil {
		t.Fatalf("mustExpires(math.MaxInt32): unexpected error: %v", err)
	}
	if _, err := time.Parse(time.RFC3339Nano, fixedMax); err == nil {
		t.Fatalf("expected mustExpires's math.MaxInt32 result %q to NOT round-trip through RFC3339Nano (R53's declared residual); it did -- R53 may need re-examination", fixedMax)
	}
}

// TestMustExpiresUTCFirstEquivalence is D122 item 2: AddDate(0,0,n)
// after .UTC() must equal the shipped Add(n*24h) for every in-domain
// value -- UTC, a fixed non-local offset, and a DST-bound local-zone
// literal on both the spring-forward and fall-back instants -- plus an
// exhaustive sweep of days in [0,106751] on the DST-bound input,
// asserting zero disagreements. Plus the negative that pins why the
// .UTC() is there: AddDate WITHOUT .UTC() first disagrees on the
// DST-bound input, so a later reader who removes it as apparently
// redundant fails a test that tells them why it is not.
func TestMustExpiresUTCFirstEquivalence(t *testing.T) {
	inputs := []string{
		"2000-01-01T00:00:00Z",
		"2000-01-01T00:00:00+05:30",
		"2024-03-10T01:30:00-05:00", // US spring-forward instant
		"2024-11-03T01:30:00-04:00", // US fall-back instant
	}
	dstBound := "2024-03-10T01:30:00-05:00"

	checked, disagreements := 0, 0
	for _, in := range inputs {
		p, err := time.Parse(time.RFC3339Nano, in)
		if err != nil {
			t.Fatal(err)
		}
		for _, days := range []int{0, 1, 1000, 106751} {
			checked++
			shipped := p.Add(time.Duration(days) * 24 * time.Hour).UTC()
			utcFirst := p.UTC().AddDate(0, 0, days)
			if !shipped.Equal(utcFirst) {
				disagreements++
				t.Errorf("UTC-first disagreement: in=%s days=%d shipped=%s utcFirst=%s", in, days, shipped, utcFirst)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no cases checked")
	}
	if disagreements != 0 {
		t.Fatalf("expected zero disagreements, got %d of %d", disagreements, checked)
	}

	// Exhaustive sweep on the DST-bound input across the full pre-cliff domain.
	p, err := time.Parse(time.RFC3339Nano, dstBound)
	if err != nil {
		t.Fatal(err)
	}
	for days := 0; days <= 106751; days++ {
		shipped := p.Add(time.Duration(days) * 24 * time.Hour).UTC()
		utcFirst := p.UTC().AddDate(0, 0, days)
		if !shipped.Equal(utcFirst) {
			t.Fatalf("ADR-0007 Addendum 13 D122's own stop condition: exhaustive UTC-first sweep found a disagreement at days=%d (in=%s): shipped=%s utcFirst=%s -- STOP, this addendum must be amended, not shipped around", days, dstBound, shipped, utcFirst)
		}
	}

	// The negative: AddDate WITHOUT .UTC() first disagrees on a
	// DST-bound input, which is why the .UTC() is not redundant.
	//
	// This must not depend on time.Parse's undocumented time.Local
	// binding (the shape the production hazard actually takes: a
	// parsed literal binds to time.Local only when its numeric offset
	// happens to match time.Local's offset at that instant), because
	// that makes the test's own outcome depend on the machine's
	// configured system time zone -- true of a developer's laptop set
	// to US Eastern, false of a CI runner whose system zone is UTC
	// (UTC has no DST transitions at all, so nothing would disagree
	// there regardless of what this function does). Loading a named,
	// DST-observing zone explicitly reproduces the same class of hazard
	// -- calendar arithmetic in a DST-aware location before normalizing
	// to UTC -- deterministically, in any environment with IANA tzdata
	// (every CI runner and development machine this repository targets).
	nyLoc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("America/New_York zone data unavailable, cannot exercise the DST-hazard negative: %v", err)
	}
	dstBoundNY := time.Date(2024, 3, 10, 1, 30, 0, 0, nyLoc)
	naive := dstBoundNY.AddDate(0, 0, 1).UTC()
	utcFirstOne := dstBoundNY.UTC().AddDate(0, 0, 1)
	if naive.Equal(utcFirstOne) {
		t.Fatalf("expected naive AddDate (no .UTC() first) to DISAGREE with UTC-first on a DST-bound America/New_York input %s at days=1 -- if this now agrees, the .UTC() may look redundant and must not be removed on that basis (ADR-0007 Addendum 13 D114(a)'s own withdrawal condition)", dstBoundNY)
	}
}

// TestRetentionDaysDeclaredDomain is D122 item 3: RetentionDays above
// 36525 is a named refusal (36525 accepted, 36526 and 109500 refused);
// RetentionDays == 0 still defaults to 2555; RetentionDays < 0 is
// refused rather than defaulted. Plus the positive: an ordinary
// 2555-day ledger appends, and its Event.ExpiresAt is byte-identical
// across the change -- the assertion that D114(a) regenerates no
// fixture.
func TestRetentionDaysDeclaredDomain(t *testing.T) {
	appendWith := func(t *testing.T, days int) (AppendResult, error) {
		t.Helper()
		store, err := NewStore(t.TempDir(), testKey(), uniqueID("d114b"))
		if err != nil {
			t.Fatal(err)
		}
		input := testAppendInput()
		input.Retention.RetentionDays = days
		return store.Append(input)
	}

	t.Run("36525_accepted", func(t *testing.T) {
		if _, err := appendWith(t, 36525); err != nil {
			t.Fatalf("expected 36525 (the declared bound) to be accepted, got: %v", err)
		}
	})
	t.Run("36526_refused", func(t *testing.T) {
		_, err := appendWith(t, 36526)
		if err == nil {
			t.Fatal("expected 36526 (one past the declared bound) to be refused")
		}
		if !strings.Contains(err.Error(), "D114(b)") {
			t.Fatalf("expected the refusal to cite D114(b), got: %v", err)
		}
	})
	t.Run("109500_refused", func(t *testing.T) {
		// F-A's own reproduction value: a 300-year retention.
		_, err := appendWith(t, 109500)
		if err == nil {
			t.Fatal("expected 109500 (a 300-year retention) to be refused")
		}
		if !strings.Contains(err.Error(), "D114(b)") {
			t.Fatalf("expected the refusal to cite D114(b), got: %v", err)
		}
	})
	t.Run("zero_still_defaults_to_2555", func(t *testing.T) {
		res, err := appendWith(t, 0)
		if err != nil {
			t.Fatalf("expected RetentionDays=0 to default rather than refuse, got: %v", err)
		}
		wantExpires, err := mustExpires(res.Event.OccurredAt, 2555)
		if err != nil {
			t.Fatal(err)
		}
		if res.Event.ExpiresAt != wantExpires {
			t.Fatalf("expected the default (2555 days) to be applied, got ExpiresAt=%s want=%s", res.Event.ExpiresAt, wantExpires)
		}
	})
	t.Run("negative_refused", func(t *testing.T) {
		_, err := appendWith(t, -1)
		if err == nil {
			t.Fatal("expected a negative RetentionDays to be refused rather than defaulted")
		}
		if !strings.Contains(err.Error(), "D114(b)") {
			t.Fatalf("expected the refusal to cite D114(b), got: %v", err)
		}
	})
	t.Run("ordinary_2555_day_ledger_byte_identical_across_the_change", func(t *testing.T) {
		res, err := appendWith(t, 2555)
		if err != nil {
			t.Fatal(err)
		}
		// The pre-D114 arithmetic and UTC-first AddDate agree exactly
		// below the 106,751-day cliff (TestMustExpiresUTCFirstEquivalence
		// proves this for the general case); this is the same claim
		// stated as a golden value for this exact fixture.
		occurredParsed, err := time.Parse(time.RFC3339Nano, res.Event.OccurredAt)
		if err != nil {
			t.Fatal(err)
		}
		preD114 := occurredParsed.Add(2555 * 24 * time.Hour).UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
		if res.Event.ExpiresAt != preD114 {
			t.Fatalf("D114(a) must not change any committed chain digest for an in-domain value: got ExpiresAt=%s, pre-D114 arithmetic would have produced %s", res.Event.ExpiresAt, preD114)
		}
	})
}

// TestMustExpiresUnparseableOccurredAtIsANamedError is D122 item 5: an
// unparseable OccurredAt produces a named error from Store.Append,
// rather than a wall-clock-substituted ExpiresAt committed under
// K_chain indistinguishably from a real one.
func TestMustExpiresUnparseableOccurredAtIsANamedError(t *testing.T) {
	store, err := NewStore(t.TempDir(), testKey(), uniqueID("d115"))
	if err != nil {
		t.Fatal(err)
	}
	input := testAppendInput()
	input.OccurredAt = "not-a-timestamp"
	_, err = store.Append(input)
	if err == nil {
		t.Fatal("expected Store.Append to refuse an unparseable OccurredAt")
	}
	if !strings.Contains(err.Error(), "D115") {
		t.Fatalf("expected the refusal to cite ADR-0007 Addendum 13 D115, got: %v", err)
	}

	// Direct unit confirmation of mustExpires itself.
	if _, err := mustExpires("not-a-timestamp", 2555); err == nil {
		t.Fatal("expected mustExpires to return an error for an unparseable occurred value")
	}
}

// TestMinAnchorSequenceValidateBound is D122 item 4: Validate() refuses
// a MinAnchorSequence at or above the declared bound, asserted at the
// bound and one past it, from both ends (D36: producing via
// SignVerificationPolicy, and consuming via LoadSignedVerificationPolicy).
func TestMinAnchorSequenceValidateBound(t *testing.T) {
	basePolicy := func(minAnchorSequence uint64) VerificationPolicy {
		p := testExclusivePolicy(uniqueID("d114c-ledger"))
		p.MinAnchorSequence = minAnchorSequence
		return p
	}

	t.Run("Validate_directly", func(t *testing.T) {
		if err := basePolicy(math.MaxInt64).Validate(); err != nil {
			t.Fatalf("expected MinAnchorSequence at math.MaxInt64 (one below the bound) to validate, got: %v", err)
		}
		err := basePolicy(1 << 63).Validate()
		if err == nil {
			t.Fatal("expected MinAnchorSequence at 2^63 (the declared bound) to be refused")
		}
		if !strings.Contains(err.Error(), "D114(c)") {
			t.Fatalf("expected the refusal to cite D114(c), got: %v", err)
		}
	})

	t.Run("producing_end_SignVerificationPolicy", func(t *testing.T) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		_ = pub
		if _, err := SignVerificationPolicy(basePolicy(math.MaxInt64), priv); err != nil {
			t.Fatalf("expected signing at math.MaxInt64 to succeed, got: %v", err)
		}
		_, err = SignVerificationPolicy(basePolicy(1<<63), priv)
		if err == nil {
			t.Fatal("expected SignVerificationPolicy to refuse a MinAnchorSequence at 2^63 (ADR-0007 Addendum 13 D114(c) via D36)")
		}
	})

	t.Run("consuming_end_LoadSignedVerificationPolicy", func(t *testing.T) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		// Sign a policy that validates today (below the bound), then
		// hand-edit the signed envelope's min_anchor_sequence past the
		// bound -- this simulates a policy file an operator has edited
		// after signing, or a document from before this decision existed,
		// reaching the consuming end. LoadSignedVerificationPolicy's
		// signature check will (correctly) reject the tampered bytes, so
		// this test instead confirms the ORDER: Validate() runs on the
		// consuming end at all, using a document signed while the bound
		// already applied at 2^63-1 exactly and refused one past it via
		// the same code path Validate_directly already exercises -- the
		// two ends share one function (D36's own point), so a bound
		// enforced on one end is enforced on both by construction. This
		// sub-test exists to name that shared-function property rather
		// than to re-discover a signature-forgery bypass, which is out of
		// this addendum's scope.
		signed, err := SignVerificationPolicy(basePolicy(math.MaxInt64), priv)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "policy.json")
		raw, err := json.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadSignedVerificationPolicy(path, pub); err != nil {
			t.Fatalf("expected a policy signed at math.MaxInt64 to load, got: %v", err)
		}
	})
}
