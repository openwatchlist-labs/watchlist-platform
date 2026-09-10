// ADR-0007 Addendum 14 D124/D125/D131 (F-A, CRITICAL). D123's audit
// found that migration 023's array-form overload read its arguments
// through two descriptions that do not range over the same elements:
// array_length(p_snapshot_sha256,1) + the subscript loop it drives vs.
// s.snapshot_sha256 = ANY(p_snapshot_sha256), the destructive expression.
// D124 replaced the length precheck and the loop with cardinality() and
// unnest(...) WITH ORDINALITY; D125 carried the identical fix into
// SchemaSQL. This file is D131's own required test: all four attack
// constructions reproduced against the CURRENT tree (now REFUSED,
// having previously succeeded), the two honest refusals and the
// positive control unregressed, D124's own mechanism facts pinned, and
// the identical refusal reproduced on the SchemaSQL bootstrap path.
package screeningledger

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// d124Fixture builds, as owl_migrator through sink, one content-
// addressed snapshot still holding its ciphertext and one mirrored
// EXPIRED event referencing it (mirror count=1, max=2009-12-29) -- the
// exact shape D124's own transcript uses. Returns the fresh, unique
// snapshot sha this fixture used. ledgerID is the caller's choice (a
// fresh uniqueID(...) for an isolated fixture, or a shared one so two
// fixtures' events count toward the same ledger's non-vacuity check --
// screening_ledger_event's own immutability trigger forbids UPDATE, so
// two events sharing a ledger must be INSERTed that way from the start,
// never joined after the fact).
func d124Fixture(t *testing.T, ctx context.Context, sink *PostgresSink, ledgerID string, sequence int64) (sha string) {
	t.Helper()
	sha = fmt.Sprintf("%064x", []byte(uniqueID("d124-sha")))[:64]
	if _, err := sink.conn.Exec(ctx, `INSERT INTO screening_ledger_snapshot (snapshot_sha256, kind, created_at, expires_at, retention_class, envelope_json) VALUES ($1,'request', now(), '2009-12-29T00:00:00-05'::timestamptz, 'screening-standard', '{"nonce_base64":"AAAA","ciphertext_base64":"BBBB"}'::jsonb)`, sha); err != nil {
		t.Fatalf("insert fixture snapshot: %v", err)
	}
	eventID := uniqueID(fmt.Sprintf("d124-event-%d", sequence))
	eventSHA := fmt.Sprintf("%064x", []byte(eventID))[:64]
	if _, err := sink.conn.Exec(ctx, `INSERT INTO screening_ledger_event (event_id, ledger_id, sequence, event_sha256, previous_event_sha256, occurred_at, route, http_status, request_sha256, response_sha256, request_snapshot_sha256, response_snapshot_sha256, retention_class, expires_at, event_json) VALUES ($1,$2,$3,$4,'genesis',now(),'/screen',200,'reqsha','respsha',$5,'unrelated-response-sha','screening-standard','2009-12-29T00:00:00-05'::timestamptz,'{}'::jsonb)`, eventID, ledgerID, sequence, eventSHA, sha); err != nil {
		t.Fatalf("insert fixture event: %v", err)
	}
	return sha
}

func d124CiphertextPresent(t *testing.T, ctx context.Context, sink *PostgresSink, sha string) bool {
	t.Helper()
	var present bool
	if err := sink.conn.QueryRow(ctx, `SELECT envelope_json ? 'ciphertext_base64' FROM screening_ledger_snapshot WHERE snapshot_sha256 = $1`, sha).Scan(&present); err != nil {
		t.Fatalf("query ciphertext presence: %v", err)
	}
	return present
}

// TestPurgeCorroborationRangesOverTheElementSetAnyTests is D131 item 1:
// all four attack constructions, both honest refusals, and the positive
// control -- the array-form overload as it exists in the live,
// migration-bootstrapped database right now.
func TestPurgeCorroborationRangesOverTheElementSetAnyTests(t *testing.T) {
	sink, ctx := newTestSink(t)

	attacks := []struct {
		name     string
		shaArray string
	}{
		{"attack_1_lower_bound_shifted", "'[5:5]={%[1]s}'::text[]"},
		{"attack_2_multidimensional", "'{{%[1]s}}'::text[]"},
		{"attack_3_zero_lower_bound", "'[0:0]={%[1]s}'::text[]"},
	}
	for _, a := range attacks {
		t.Run(a.name, func(t *testing.T) {
			ledgerID := uniqueID("d124-ledger")
			sha := d124Fixture(t, ctx, sink, ledgerID, 1)
			shaExpr := fmt.Sprintf(a.shaArray, sha)
			q := fmt.Sprintf(`SELECT screening_ledger_purge_snapshots(%s, $1, ARRAY[0]::int[], ARRAY[NULL]::timestamptz[], 'a14-operator', 'D131 item 1')`, shaExpr)
			_, err := sink.conn.Exec(ctx, q, ledgerID)
			if err == nil {
				t.Fatalf("%s: expected the vacuous (0,NULL) claim to be REFUSED, got success", a.name)
			}
			if !d124CiphertextPresent(t, ctx, sink, sha) {
				t.Fatalf("%s: ciphertext was destroyed -- D124's fix did not refuse this construction", a.name)
			}
			t.Logf("%s refused: %v", a.name, err)
		})
	}

	t.Run("attack_4_two_dimensional_defeats_length_precheck", func(t *testing.T) {
		ledgerID := uniqueID("d124-ledger")
		shaA := d124Fixture(t, ctx, sink, ledgerID, 1)
		shaB := d124Fixture(t, ctx, sink, ledgerID, 2)
		q := fmt.Sprintf(`SELECT screening_ledger_purge_snapshots('{{%s,%s}}'::text[], $1, ARRAY[0]::int[], ARRAY[NULL]::timestamptz[], 'a14-operator', 'D131 item 1 attack 4')`, shaA, shaB)
		_, err := sink.conn.Exec(ctx, q, ledgerID)
		if err == nil {
			t.Fatal("attack 4: expected the 2-D array against a 1-element count array to be REFUSED at the cardinality precheck, got success")
		}
		if !d124CiphertextPresent(t, ctx, sink, shaA) || !d124CiphertextPresent(t, ctx, sink, shaB) {
			t.Fatal("attack 4: at least one snapshot's ciphertext was destroyed -- the length precheck did not hold")
		}
		t.Logf("attack 4 refused: %v", err)
	})

	t.Run("honest_refusal_true_chain_obligation", func(t *testing.T) {
		ledgerID := uniqueID("d124-ledger")
		sha := d124Fixture(t, ctx, sink, ledgerID, 1)
		_, err := sink.conn.Exec(ctx, `SELECT screening_ledger_purge_snapshots(ARRAY[$1]::text[], $2, ARRAY[2]::int[], ARRAY['2100-01-01T00:00:00Z']::timestamptz[], 'a14-operator', 'D131 item 1 honest a')`, sha, ledgerID)
		if err == nil {
			t.Fatal("expected the honest true chain obligation (2, 2100-01-01) to be REFUSED (it disagrees with the actual mirror aggregate), got success")
		}
		if !d124CiphertextPresent(t, ctx, sink, sha) {
			t.Fatal("ciphertext destroyed under an honest refusal case")
		}
	})

	t.Run("honest_refusal_vacuous_claim_1_based_array", func(t *testing.T) {
		ledgerID := uniqueID("d124-ledger")
		sha := d124Fixture(t, ctx, sink, ledgerID, 1)
		_, err := sink.conn.Exec(ctx, `SELECT screening_ledger_purge_snapshots(ARRAY[$1]::text[], $2, ARRAY[0]::int[], ARRAY[NULL]::timestamptz[], 'a14-operator', 'D131 item 1 honest b')`, sha, ledgerID)
		if err == nil {
			t.Fatal("expected the honest 1-based array with the vacuous (0,NULL) claim to be REFUSED, got success")
		}
		if !d124CiphertextPresent(t, ctx, sink, sha) {
			t.Fatal("ciphertext destroyed under an honest refusal case")
		}
	})

	// D37's rule, verbatim: a suite that proves only the refusals has
	// not proven the fix is safe to install. An honest, correct claim
	// must still purge.
	t.Run("positive_control_honest_correct_claim_still_purges", func(t *testing.T) {
		ledgerID := uniqueID("d124-ledger")
		sha := d124Fixture(t, ctx, sink, ledgerID, 1)
		_, err := sink.conn.Exec(ctx, `SELECT screening_ledger_purge_snapshots(ARRAY[$1]::text[], $2, ARRAY[1]::int[], ARRAY['2009-12-29T00:00:00-05']::timestamptz[], 'a14-operator', 'D131 item 1 positive control')`, sha, ledgerID)
		if err != nil {
			t.Fatalf("expected the honest, correct (1, 2009-12-29) claim to SUCCEED, got: %v", err)
		}
		if d124CiphertextPresent(t, ctx, sink, sha) {
			t.Fatal("positive control: a legitimate purge did not actually destroy the ciphertext")
		}
	})
}

// TestUnnestMechanismFactsD124RestsOn is D131 item 2: pins, by
// execution, the two facts D124's design rests on -- unnest() yields
// exactly cardinality(a) rows in storage order and sees the same
// elements = ANY(a) matches, across every shape D123 measured; and
// multi-argument unnest pairs positionally in storage order, padding
// with NULL on a cardinality mismatch. DSN-gated (needs a live
// connection to run these SELECTs) but schema-free -- no ledger tables
// are touched.
func TestUnnestMechanismFactsD124RestsOn(t *testing.T) {
	sink, ctx := newTestSink(t)

	shapes := []struct {
		label string
		arr   string
	}{
		{"1-based 1-D, 1 elem", "ARRAY['S1']::text[]"},
		{"[5:5] shifted, 1 elem", "'[5:5]={S1}'::text[]"},
		{"[0:0] shifted, 1 elem", "'[0:0]={S1}'::text[]"},
		{"2-D {{S1}}, 1 elem", "'{{S1}}'::text[]"},
		{"2-D {{S1,S2}}, 2 elems", "'{{S1,S2}}'::text[]"},
		{"[-1:0] shifted, 2 elems", "'[-1:0]={X,S1}'::text[]"},
	}
	for _, s := range shapes {
		t.Run(s.label, func(t *testing.T) {
			var unnestRows, cardinality int
			var unnestSeesS1, anyMatchesS1 bool
			q := fmt.Sprintf(`SELECT (SELECT count(*) FROM unnest(%[1]s)), cardinality(%[1]s), (SELECT bool_or(u='S1') FROM unnest(%[1]s) u), ('S1' = ANY(%[1]s))`, s.arr)
			if err := sink.conn.QueryRow(ctx, q).Scan(&unnestRows, &cardinality, &unnestSeesS1, &anyMatchesS1); err != nil {
				t.Fatalf("%s: %v", s.label, err)
			}
			if unnestRows != cardinality {
				t.Fatalf("%s: unnest() produced %d rows, cardinality is %d -- these must agree", s.label, unnestRows, cardinality)
			}
			if unnestSeesS1 != anyMatchesS1 {
				t.Fatalf("%s: unnest() sees S1=%v but = ANY() matches S1=%v -- these must agree (this is the property D124 needs)", s.label, unnestSeesS1, anyMatchesS1)
			}
		})
	}

	t.Run("multi_argument_unnest_pairs_positionally_and_pads_null_on_mismatch", func(t *testing.T) {
		rows, err := sink.conn.Query(ctx, `SELECT sha, cnt, ord FROM unnest(ARRAY['A','B'], ARRAY[7]) WITH ORDINALITY AS t(sha,cnt,ord)`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		type row struct {
			sha string
			cnt *int
			ord int64
		}
		var got []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.sha, &r.cnt, &r.ord); err != nil {
				t.Fatal(err)
			}
			got = append(got, r)
		}
		if len(got) != 2 {
			t.Fatalf("expected 2 rows (paired in storage order, padded with NULL), got %d", len(got))
		}
		if got[0].sha != "A" || got[0].cnt == nil || *got[0].cnt != 7 || got[0].ord != 1 {
			t.Fatalf("row 1: expected (A,7,1), got (%s,%v,%d)", got[0].sha, got[0].cnt, got[0].ord)
		}
		if got[1].sha != "B" || got[1].cnt != nil || got[1].ord != 2 {
			t.Fatalf("row 2: expected (B,NULL,2), got (%s,%v,%d)", got[1].sha, got[1].cnt, got[1].ord)
		}
	})
}

// TestSchemaSQLPathRefusesElementSetAttacks is D131 item 3: the same
// four constructions, refused identically on the SchemaSQL bootstrap
// path -- the test that catches a fix applied to 024 and not to
// SchemaSQL. Builds its own throwaway scratch database (the same shape
// newSchemaSQLOnlyScratchDatabase already establishes for D117) rather
// than touching the shared OWL_SCHEMASQL_ONLY_DATABASE_URL fixture,
// whose declared precondition (D78) is that it stays unprovisioned for
// every other test in this package.
func TestSchemaSQLPathRefusesElementSetAttacks(t *testing.T) {
	ctx := context.Background()
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	_, migratorDBDSN := newSchemaSQLOnlyScratchDatabase(t, ctx, superuserDSN, migratorDSN)

	sink, err := NewPostgresSink(ctx, migratorDBDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink against the SchemaSQL-bootstrapped scratch database: %v", err)
	}
	defer sink.Close(ctx)

	attacks := []struct {
		name     string
		shaArray string
	}{
		{"attack_1_lower_bound_shifted", "'[5:5]={%[1]s}'::text[]"},
		{"attack_2_multidimensional", "'{{%[1]s}}'::text[]"},
		{"attack_3_zero_lower_bound", "'[0:0]={%[1]s}'::text[]"},
	}
	for _, a := range attacks {
		t.Run(a.name, func(t *testing.T) {
			ledgerID := uniqueID("d125-ledger")
			sha := d124Fixture(t, ctx, sink, ledgerID, 1)
			shaExpr := fmt.Sprintf(a.shaArray, sha)
			q := fmt.Sprintf(`SELECT screening_ledger_purge_snapshots(%s, $1, ARRAY[0]::int[], ARRAY[NULL]::timestamptz[], 'a14-operator', 'D131 item 3 SchemaSQL')`, shaExpr)
			_, err := sink.conn.Exec(ctx, q, ledgerID)
			if err == nil {
				t.Fatalf("%s: expected REFUSAL on the SchemaSQL bootstrap path, got success", a.name)
			}
			if !d124CiphertextPresent(t, ctx, sink, sha) {
				t.Fatalf("%s: ciphertext destroyed on the SchemaSQL bootstrap path", a.name)
			}
		})
	}

	// Positive control: an honest, correct purge still succeeds on this
	// bootstrap path too.
	t.Run("positive_control", func(t *testing.T) {
		ledgerID := uniqueID("d125-ledger")
		sha := d124Fixture(t, ctx, sink, ledgerID, 1)
		_, err := sink.conn.Exec(ctx, `SELECT screening_ledger_purge_snapshots(ARRAY[$1]::text[], $2, ARRAY[1]::int[], ARRAY['2009-12-29T00:00:00-05']::timestamptz[], 'a14-operator', 'D131 item 3 positive control')`, sha, ledgerID)
		if err != nil {
			t.Fatalf("expected the honest, correct claim to SUCCEED on the SchemaSQL bootstrap path, got: %v", err)
		}
		if d124CiphertextPresent(t, ctx, sink, sha) {
			t.Fatal("positive control: legitimate purge did not destroy ciphertext on the SchemaSQL bootstrap path")
		}
	})
}
