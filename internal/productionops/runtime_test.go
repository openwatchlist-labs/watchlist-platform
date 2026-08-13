package productionops

import (
	"context"
	"testing"
)

// fakePinger is a test double for the Pinger CheckRuntime now depends on.
// Its whole purpose is to prove CheckRuntime talks to whatever it was
// handed rather than reading os.Getenv and forking psql itself -- the
// property ADR-0005 §11.2 (D12) requires and the pre-fix implementation
// did not have. Before this change CheckRuntime took three arguments and
// had no Pinger parameter at all, so this test could not even compile
// against it; that is the "fails before the fix" state for a signature
// change, the same shape ADR-0005 §4 used for screeningledger's pgx
// cutover.
type fakePinger struct {
	called bool
	err    error
}

func (f *fakePinger) Ping(ctx context.Context) error {
	f.called = true
	return f.err
}

func TestCheckRuntimePostgreSQLUsesPingerNotSubprocess(t *testing.T) {
	// No psql anywhere on PATH: if anything still shelled out to psql,
	// exec would fail with "executable file not found in $PATH" and the
	// postgresql check below would report failed, not ok.
	t.Setenv("PATH", t.TempDir())
	dir := t.TempDir()
	c := RuntimeConfig{
		RuntimeStateDirectory: dir,
		OutboxDirectory:       dir,
		BackupDirectory:       dir,
		Readiness: ReadinessConfig{
			PostgreSQLRequired: true,
			PostgreSQLDSNEnv:   "REL2_STAGE2_UNSET_DSN_ENV",
			PSQLPath:           "psql",
		},
	}
	pg := &fakePinger{}
	r := CheckRuntime(context.Background(), c, QuotaRegistry{}, pg)

	if !pg.called {
		t.Fatal("CheckRuntime did not call Pinger.Ping; readiness probe did not use the supplied connection")
	}
	found := false
	for _, chk := range r.Checks {
		if chk.Name != "postgresql" {
			continue
		}
		found = true
		if chk.Status != "ok" {
			t.Fatalf("postgresql check status = %q, detail = %q; want ok (no subprocess should have run)", chk.Status, chk.Detail)
		}
	}
	if !found {
		t.Fatal("no postgresql check present in readiness report")
	}
	if r.Status != "ok" {
		t.Fatalf("report status = %q, want ok", r.Status)
	}
}

func TestCheckRuntimePostgreSQLPingFailureIsReported(t *testing.T) {
	c := RuntimeConfig{Readiness: ReadinessConfig{PostgreSQLRequired: true, PostgreSQLDSNEnv: "REL2_STAGE2_UNSET_DSN_ENV"}}
	pg := &fakePinger{err: context.DeadlineExceeded}
	r := CheckRuntime(context.Background(), c, QuotaRegistry{}, pg)

	if !pg.called {
		t.Fatal("CheckRuntime did not call Pinger.Ping")
	}
	if r.Status != "not_ready" {
		t.Fatalf("report status = %q, want not_ready when Ping fails", r.Status)
	}
}

func TestCheckRuntimePostgreSQLRequiredWithNilPingerFailsClosed(t *testing.T) {
	c := RuntimeConfig{Readiness: ReadinessConfig{PostgreSQLRequired: true, PostgreSQLDSNEnv: "REL2_STAGE2_UNSET_DSN_ENV"}}
	r := CheckRuntime(context.Background(), c, QuotaRegistry{}, nil)

	if r.Status != "not_ready" {
		t.Fatalf("report status = %q, want not_ready when PostgreSQL is required but no Pinger was supplied", r.Status)
	}
}

func TestCheckRuntimePostgreSQLNotRequiredIgnoresNilPinger(t *testing.T) {
	c := RuntimeConfig{Readiness: ReadinessConfig{PostgreSQLRequired: false}}
	r := CheckRuntime(context.Background(), c, QuotaRegistry{}, nil)

	for _, chk := range r.Checks {
		if chk.Name == "postgresql" {
			t.Fatalf("postgresql check should be absent when not required, got status %q", chk.Status)
		}
	}
}
