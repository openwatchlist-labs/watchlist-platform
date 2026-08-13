package productionops

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// readinessDSN resolves the DSN for the /readyz PostgreSQL probe from the
// environment variable named in the config -- never from argv, and never
// from the check itself (ADR-0005 §11.1/§11.2). Returns "" with no error
// when PostgreSQL readiness is not configured, so callers can skip
// constructing a connection at all rather than branching on it twice.
func readinessDSN(c RuntimeConfig) (string, error) {
	if !c.Readiness.PostgreSQLRequired {
		return "", nil
	}
	dsn := strings.TrimSpace(os.Getenv(c.Readiness.PostgreSQLDSNEnv))
	if dsn == "" {
		return "", fmt.Errorf("%s is empty", c.Readiness.PostgreSQLDSNEnv)
	}
	return dsn, nil
}

// NewReadinessPool is the pool internal/platformapi.Server holds for its
// /readyz probe. platformapi is a separate process from the three
// sink-holding services and never had a pool to reuse (ADR-0005 §11.2),
// so this constructs its own -- deliberately small, since its only job is
// Ping, not request traffic: MaxConns 2, a bounded connect attempt, and
// nothing else. Returns (nil, nil) when PostgreSQL readiness is not
// configured; the result can be passed straight to CheckRuntime as a nil
// Pinger in that case.
func NewReadinessPool(ctx context.Context, c RuntimeConfig) (*pgxpool.Pool, error) {
	dsn, err := readinessDSN(c)
	if err != nil || dsn == "" {
		return nil, err
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 2
	cfg.ConnConfig.ConnectTimeout = 5 * time.Second
	return pgxpool.NewWithConfig(ctx, cfg)
}

// NewReadinessConn is cmd/platform-ops' one-shot equivalent for its
// `readiness` command: a single connection opened for the invocation's
// lifetime, matching D4's CLI/service split rather than standing up a
// pool for a command that runs once and exits. Returns (nil, nil) when
// PostgreSQL readiness is not configured.
func NewReadinessConn(ctx context.Context, c RuntimeConfig) (*pgx.Conn, error) {
	dsn, err := readinessDSN(c)
	if err != nil || dsn == "" {
		return nil, err
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.ConnectTimeout = 5 * time.Second
	return pgx.ConnectConfig(ctx, cfg)
}
