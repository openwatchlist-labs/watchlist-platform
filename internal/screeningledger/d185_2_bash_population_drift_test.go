// ADR-0007 Addendum 23 D185(2) (C23-D, Stage X1a): a DSN-free guard
// binding the three bash-side copies of the protected-relation
// population -- provision_test_roles.sh's sec7_protected_relations,
// verify_cross_cluster_dr.sh's D178 loop, and
// tests/test_provisioning_maintain_population.sh's relations -- to
// requiredProtectedRelationStates, in both directions. D179 test 6
// (TestD174D175D176DerivationGuard, in this same package) already binds
// the Go-side derivations to each other; it never reads a bash file, so
// a relation added to requiredProtectedRelationStates without its own
// bash-side row in one of these three files would ship uncaught -- this
// guard is what makes that claim true.
package screeningledger

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// d185ExtractArrayBody isolates the parenthesized body of a bash array
// literal, given the exact declaration text (including its trailing
// open-paren and newline) that precedes it. Returning an error rather
// than calling t.Fatal lets callers report which of the three files
// failed, since a bare regex match count doesn't say which one drifted.
func d185ExtractArrayBody(raw, declPrefix, closeMarker string) (string, error) {
	i := strings.Index(raw, declPrefix)
	if i < 0 {
		return "", os.ErrNotExist
	}
	start := i + len(declPrefix)
	j := strings.Index(raw[start:], closeMarker)
	if j < 0 {
		return "", os.ErrNotExist
	}
	return raw[start : start+j], nil
}

// d185QuotedRows returns every double-quoted string literal inside an
// array body, in file order.
func d185QuotedRows(body string) []string {
	var rows []string
	for _, m := range regexp.MustCompile(`"([^"]*)"`).FindAllStringSubmatch(body, -1) {
		rows = append(rows, m[1])
	}
	return rows
}

func d185SortedJoin(in []string) string {
	s := append([]string(nil), in...)
	sort.Strings(s)
	return strings.Join(s, ",")
}

// TestD185BashRelationPopulationsMatchGo is ADR-0007 Addendum 23
// D185(2). Each of the three files is read, its array literal isolated
// by exact bracketing text (so a matching count of 0 or 2+ is a test
// construction bug, not a silent skip), and every row checked against
// requiredProtectedRelationStates in both directions: every bash row
// must name a relation Go declares (with the fields the file's own
// convention says it must carry), and every relation Go declares must
// have a corresponding bash row in each of the three files.
func TestD185BashRelationPopulationsMatchGo(t *testing.T) {
	want := map[string]requiredProtectedRelationState{}
	for _, s := range requiredProtectedRelationStates {
		want[protectedRelationTableName(s.identity)] = s
	}

	type checkFile struct {
		copyName    string
		path        string
		declPrefix  string
		closeMarker string
		fields      int // table:owner:triggers:indexes = 4; table:owner:pkindex = 3; table:owner = 2
	}
	files := []checkFile{
		{
			copyName:    "provision_test_roles.sh sec7_protected_relations",
			path:        "../../scripts/ci/provision_test_roles.sh",
			declPrefix:  "  sec7_protected_relations=(\n",
			closeMarker: "\n  )\n",
			fields:      4,
		},
		{
			copyName:    "verify_cross_cluster_dr.sh D178 loop",
			path:        "../../scripts/ci/verify_cross_cluster_dr.sh",
			declPrefix:  "for decl_dr_rel in \\\n",
			closeMarker: "\ndo\n",
			fields:      3,
		},
		{
			copyName:    "tests/test_provisioning_maintain_population.sh relations",
			path:        "../../scripts/ci/tests/test_provisioning_maintain_population.sh",
			declPrefix:  "relations=(\n",
			closeMarker: "\n)\n",
			fields:      2,
		},
	}

	for _, cf := range files {
		raw, err := os.ReadFile(cf.path)
		if err != nil {
			t.Fatalf("read %s: %v", cf.path, err)
		}
		body, err := d185ExtractArrayBody(string(raw), cf.declPrefix, cf.closeMarker)
		if err != nil {
			t.Fatalf("test construction bug: %s no longer contains the expected array bracketing (%q ... %q) -- the script's shape changed and this test's markers need updating, not deleting", cf.path, cf.declPrefix, cf.closeMarker)
		}
		rows := d185QuotedRows(body)
		if len(rows) == 0 {
			t.Fatalf("test construction bug: %s: the array body matched but contained no quoted rows", cf.copyName)
		}

		seen := map[string]bool{}
		for _, row := range rows {
			f := strings.SplitN(row, ":", cf.fields)
			if len(f) != cf.fields {
				t.Errorf("%s: row %q has %d field(s), expected %d", cf.copyName, row, len(f), cf.fields)
				continue
			}
			table, owner := f[0], f[1]
			state, ok := want[table]
			if !ok {
				t.Errorf("%s: row names %q, which requiredProtectedRelationStates does not declare", cf.copyName, table)
				continue
			}
			if seen[table] {
				t.Errorf("%s: %q appears more than once", cf.copyName, table)
			}
			seen[table] = true
			if owner != state.relowner {
				t.Errorf("%s: %q declares owner %q, requiredProtectedRelationStates declares %q", cf.copyName, table, owner, state.relowner)
			}

			switch cf.fields {
			case 4: // installer: table:owner:triggers:indexes
				var wantTriggers, wantIndexes []string
				for _, trig := range state.triggers {
					wantTriggers = append(wantTriggers, trig.name)
				}
				for _, idx := range state.indexes {
					wantIndexes = append(wantIndexes, idx.name)
				}
				if got, w := d185SortedJoin(strings.Split(f[2], ",")), d185SortedJoin(wantTriggers); got != w {
					t.Errorf("%s: %q trigger set %q differs from the Go declaration %q", cf.copyName, table, got, w)
				}
				if got, w := d185SortedJoin(strings.Split(f[3], ",")), d185SortedJoin(wantIndexes); got != w {
					t.Errorf("%s: %q index set %q differs from the Go declaration %q", cf.copyName, table, got, w)
				}
			case 3: // DR loop: table:owner:pk_index -- must be that relation's declared PRIMARY KEY index
				pkOK := false
				for _, idx := range state.indexes {
					if idx.name == f[2] && idx.indisprimary {
						pkOK = true
						break
					}
				}
				if !pkOK {
					t.Errorf("%s: %q's probe index %q is not that relation's declared primary-key index in requiredProtectedRelationStates", cf.copyName, table, f[2])
				}
			}
		}
		for table := range want {
			if !seen[table] {
				t.Errorf("%s: no row for protected relation %q -- a relation added to requiredProtectedRelationStates without its own row in this file would ship uncovered", cf.copyName, table)
			}
		}
	}
}
