// Package store provides a SQLite-backed persistent store for account
// credentials, token state, and rejected-token digests.
//
// Security invariants:
//   - data/ directory is 0700; the database file is 0600.
//   - Symlinks and non-regular files in the database path cause hard failure.
//   - A corrupt database causes hard failure; no automatic rebuild.
//   - Session tokens and JWTs must never appear in log output or error text.
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

const (
	// CurrentSchemaVersion is the PRAGMA user_version value this binary writes.
	CurrentSchemaVersion = 1

	// MaxRejectedPerAccount is the per-account cap on stored reject digests.
	MaxRejectedPerAccount = 32
)

// DB holds the open SQLite connection. Callers must call Close when done.
type DB struct {
	db   *sql.DB
	path string
}

// Account is a row from the accounts table.
type Account struct {
	ID           int64
	UID          string
	Email        string
	SessionToken string // sensitive – never log
	Enabled      bool
	Label        string
	Source       string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// ProxyPass is a row from the proxy_pass table.
type ProxyPass struct {
	AccountID int64
	JWT       string // sensitive – never log
	Digest    string
	ExpiresAt time.Time
	FetchedAt time.Time
}

// RefreshState mirrors the refresh_state table row.
type RefreshState struct {
	AccountID           int64
	Result              string
	LastAttemptAt       *time.Time
	LastSuccessAt       *time.Time
	NextAttemptAt       *time.Time
	ProxyPassExpiresAt  *time.Time
	ConsecutiveFailures int
	HTTPStatus          *int
	Generation          int
}

// Open opens (or creates) the database at root/data/fxpool.db, enforcing
// owner/mode and symlink restrictions, then runs schema migrations.
func Open(root string) (*DB, error) {
	dir := filepath.Join(root, "data")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: create data dir: %w", err)
	}
	// Enforce 0700 on the data directory itself after creation.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: chmod data dir: %w", err)
	}

	dbPath := filepath.Join(dir, "fxpool.db")
	if err := checkPathSafe(dbPath); err != nil {
		return nil, err
	}
	for _, sidecar := range []string{dbPath + "-wal", dbPath + "-shm"} {
		if err := checkPathSafe(sidecar); err != nil {
			return nil, err
		}
	}

	dsn := "file:" + dbPath + "?_journal_mode=WAL&_foreign_keys=ON&_busy_timeout=5000&_locking=NORMAL"
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite: %w", err)
	}
	raw.SetMaxOpenConns(1)

	db := &DB{db: raw, path: dbPath}
	if err := db.migrate(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	// Ensure the database file is owner-only.  The driver may have created
	// it with umask-derived permissions (often 0644); tighten it now.
	if err := os.Chmod(dbPath, 0o600); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("store: chmod db: %w", err)
	}
	if err := db.checkMode(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return db, nil
}

// checkPathSafe returns an error if path exists and is a symlink or
// non-regular file.  Missing paths are allowed (they will be created).
func checkPathSafe(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: stat %s: %w", filepath.Base(path), err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("store: %s is a symlink – refusing to open", filepath.Base(path))
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("store: %s is not a regular file", filepath.Base(path))
	}
	return nil
}

// checkMode verifies that the database file has owner-only permissions.
func (d *DB) checkMode() error {
	fi, err := os.Lstat(d.path)
	if err != nil {
		return fmt.Errorf("store: stat db: %w", err)
	}
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if ok && sys.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("store: database owned by uid %d, current uid %d", sys.Uid, os.Getuid())
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("store: database permissions are %04o, want 0600", fi.Mode().Perm())
	}
	return nil
}

// Close closes the underlying SQL connection.
func (d *DB) Close() error { return d.db.Close() }

// IntegrityCheck runs PRAGMA integrity_check and returns an error if the
// database is corrupt.
func (d *DB) IntegrityCheck() error {
	rows, err := d.db.QueryContext(context.Background(), "PRAGMA integrity_check")
	if err != nil {
		return fmt.Errorf("store: integrity_check query: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var msg string
		if err := rows.Scan(&msg); err != nil {
			return fmt.Errorf("store: integrity_check scan: %w", err)
		}
		if msg != "ok" {
			return fmt.Errorf("store: integrity_check failed: %s", msg)
		}
	}
	return rows.Err()
}

// migrate runs schema migrations based on PRAGMA user_version.
func (d *DB) migrate() error {
	var ver int
	if err := d.db.QueryRowContext(context.Background(), "PRAGMA user_version").Scan(&ver); err != nil {
		return fmt.Errorf("store: read user_version: %w", err)
	}
	if ver > CurrentSchemaVersion {
		return fmt.Errorf("store: database schema version %d is newer than this binary (max %d)", ver, CurrentSchemaVersion)
	}
	if ver == CurrentSchemaVersion {
		return nil
	}
	// ver == 0: fresh database, apply v1 schema.
	_, err := d.db.ExecContext(context.Background(), schemaV1)
	if err != nil {
		return fmt.Errorf("store: apply schema v1: %w", err)
	}
	return nil
}

const schemaV1 = `
CREATE TABLE IF NOT EXISTS accounts (
  id            INTEGER PRIMARY KEY,
  uid           TEXT NOT NULL UNIQUE,
  email         TEXT NOT NULL,
  session_token TEXT NOT NULL,
  enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  label         TEXT NOT NULL DEFAULT '',
  source        TEXT NOT NULL DEFAULT '',
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS proxy_pass (
  account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  jwt        TEXT NOT NULL,
  digest     TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  fetched_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_state (
  account_id            INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  result                TEXT NOT NULL,
  last_attempt_at       INTEGER,
  last_success_at       INTEGER,
  next_attempt_at       INTEGER,
  proxy_pass_expires_at INTEGER,
  consecutive_failures  INTEGER NOT NULL DEFAULT 0,
  http_status           INTEGER,
  generation            INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rejected_tokens (
  digest     TEXT PRIMARY KEY,
  account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS rejected_tokens_account_created
  ON rejected_tokens(account_id, created_at);

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

PRAGMA user_version = 1;
`

// MetaGet retrieves a value from the meta table.
func (d *DB) MetaGet(ctx context.Context, key string) (string, bool, error) {
	var val string
	err := d.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&val)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store: meta get %q: %w", key, err)
	}
	return val, true, nil
}

// MetaSet sets a value in the meta table (upsert).
func (d *DB) MetaSet(ctx context.Context, tx *sql.Tx, key, value string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	if err != nil {
		return fmt.Errorf("store: meta set %q: %w", key, err)
	}
	return nil
}

// Begin starts a write transaction.
func (d *DB) Begin(ctx context.Context) (*sql.Tx, error) {
	return d.db.BeginTx(ctx, nil)
}

// UpsertAccount inserts or updates an account by uid.
// The session_token must never appear in log output.
func (d *DB) UpsertAccount(ctx context.Context, tx *sql.Tx, a Account) (int64, error) {
	now := a.UpdatedAt.Unix()
	res, err := tx.ExecContext(ctx, `
		INSERT INTO accounts(uid, email, session_token, enabled, label, source, created_at, updated_at)
		VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(uid) DO UPDATE SET
			email         = excluded.email,
			session_token = excluded.session_token,
			enabled       = excluded.enabled,
			label         = excluded.label,
			source        = excluded.source,
			updated_at    = excluded.updated_at
	`, a.UID, a.Email, a.SessionToken, boolToInt(a.Enabled), a.Label, a.Source,
		a.CreatedAt.Unix(), now)
	if err != nil {
		return 0, fmt.Errorf("store: upsert account %q: %w", a.UID, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		// ON CONFLICT path: look it up.
		err2 := tx.QueryRowContext(ctx, `SELECT id FROM accounts WHERE uid = ?`, a.UID).Scan(&id)
		if err2 != nil {
			return 0, fmt.Errorf("store: resolve account id for %q: %w", a.UID, err2)
		}
	}
	return id, nil
}

// GetAccount fetches one account by uid.
func (d *DB) GetAccount(ctx context.Context, uid string) (Account, error) {
	var a Account
	var createdAt, updatedAt int64
	var enabled int
	err := d.db.QueryRowContext(ctx, `
		SELECT id, uid, email, session_token, enabled, label, source, created_at, updated_at
		FROM accounts WHERE uid = ?`, uid).
		Scan(&a.ID, &a.UID, &a.Email, &a.SessionToken, &enabled, &a.Label, &a.Source, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, fmt.Errorf("store: account %q not found", uid)
	}
	if err != nil {
		return Account{}, fmt.Errorf("store: get account %q: %w", uid, err)
	}
	a.Enabled = enabled != 0
	a.CreatedAt = time.Unix(createdAt, 0)
	a.UpdatedAt = time.Unix(updatedAt, 0)
	return a, nil
}

// ListAccounts returns all accounts ordered by id.
func (d *DB) ListAccounts(ctx context.Context) ([]Account, error) {
	rows, err := d.db.QueryContext(ctx, `
		SELECT id, uid, email, session_token, enabled, label, source, created_at, updated_at
		FROM accounts ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: list accounts: %w", err)
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		var a Account
		var createdAt, updatedAt int64
		var enabled int
		if err := rows.Scan(&a.ID, &a.UID, &a.Email, &a.SessionToken, &enabled, &a.Label, &a.Source, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("store: scan account: %w", err)
		}
		a.Enabled = enabled != 0
		a.CreatedAt = time.Unix(createdAt, 0)
		a.UpdatedAt = time.Unix(updatedAt, 0)
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetAccountEnabled sets the enabled flag for a given uid.
func (d *DB) SetAccountEnabled(ctx context.Context, uid string, enabled bool) error {
	res, err := d.db.ExecContext(ctx, `UPDATE accounts SET enabled=?, updated_at=? WHERE uid=?`,
		boolToInt(enabled), time.Now().Unix(), uid)
	if err != nil {
		return fmt.Errorf("store: set enabled %q: %w", uid, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: account %q not found", uid)
	}
	return nil
}

// DeleteAccount deletes an account and cascades to all related rows.
func (d *DB) DeleteAccount(ctx context.Context, tx *sql.Tx, uid string) error {
	res, err := tx.ExecContext(ctx, `DELETE FROM accounts WHERE uid=?`, uid)
	if err != nil {
		return fmt.Errorf("store: delete account %q: %w", uid, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: account %q not found", uid)
	}
	return nil
}

// UpsertProxyPass writes a proxy_pass row for the given account.
// An existing row is replaced atomically.
func (d *DB) UpsertProxyPass(ctx context.Context, tx *sql.Tx, pp ProxyPass) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO proxy_pass(account_id, jwt, digest, expires_at, fetched_at)
		VALUES(?,?,?,?,?)
		ON CONFLICT(account_id) DO UPDATE SET
			jwt        = excluded.jwt,
			digest     = excluded.digest,
			expires_at = excluded.expires_at,
			fetched_at = excluded.fetched_at
	`, pp.AccountID, pp.JWT, pp.Digest, pp.ExpiresAt.Unix(), pp.FetchedAt.Unix())
	if err != nil {
		return fmt.Errorf("store: upsert proxy_pass: %w", err)
	}
	return nil
}

// GetProxyPass retrieves the proxy_pass row for an account.
func (d *DB) GetProxyPass(ctx context.Context, accountID int64) (ProxyPass, error) {
	var pp ProxyPass
	var expiresAt, fetchedAt int64
	err := d.db.QueryRowContext(ctx, `
		SELECT account_id, jwt, digest, expires_at, fetched_at
		FROM proxy_pass WHERE account_id = ?`, accountID).
		Scan(&pp.AccountID, &pp.JWT, &pp.Digest, &expiresAt, &fetchedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ProxyPass{}, fmt.Errorf("store: no proxy_pass for account %d", accountID)
	}
	if err != nil {
		return ProxyPass{}, fmt.Errorf("store: get proxy_pass: %w", err)
	}
	pp.ExpiresAt = time.Unix(expiresAt, 0)
	pp.FetchedAt = time.Unix(fetchedAt, 0)
	return pp, nil
}

// DeleteProxyPass removes the proxy_pass row for an account (used on reimport).
func (d *DB) DeleteProxyPass(ctx context.Context, tx *sql.Tx, accountID int64) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM proxy_pass WHERE account_id=?`, accountID)
	return err
}

// UpsertRefreshState writes a refresh_state row.
func (d *DB) UpsertRefreshState(ctx context.Context, tx *sql.Tx, rs RefreshState) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO refresh_state(
			account_id, result, last_attempt_at, last_success_at, next_attempt_at,
			proxy_pass_expires_at, consecutive_failures, http_status, generation)
		VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(account_id) DO UPDATE SET
			result                = excluded.result,
			last_attempt_at       = excluded.last_attempt_at,
			last_success_at       = excluded.last_success_at,
			next_attempt_at       = excluded.next_attempt_at,
			proxy_pass_expires_at = excluded.proxy_pass_expires_at,
			consecutive_failures  = excluded.consecutive_failures,
			http_status           = excluded.http_status,
			generation            = excluded.generation
	`, rs.AccountID, rs.Result,
		timeToNullInt(rs.LastAttemptAt), timeToNullInt(rs.LastSuccessAt),
		timeToNullInt(rs.NextAttemptAt), timeToNullInt(rs.ProxyPassExpiresAt),
		rs.ConsecutiveFailures, rs.HTTPStatus, rs.Generation)
	if err != nil {
		return fmt.Errorf("store: upsert refresh_state: %w", err)
	}
	return nil
}

// GetRefreshState retrieves the refresh_state row for an account.
func (d *DB) GetRefreshState(ctx context.Context, accountID int64) (RefreshState, error) {
	var rs RefreshState
	var lastAttempt, lastSuccess, nextAttempt, ppExpires sql.NullInt64
	var httpStatus sql.NullInt64
	err := d.db.QueryRowContext(ctx, `
		SELECT account_id, result, last_attempt_at, last_success_at, next_attempt_at,
		       proxy_pass_expires_at, consecutive_failures, http_status, generation
		FROM refresh_state WHERE account_id = ?`, accountID).
		Scan(&rs.AccountID, &rs.Result, &lastAttempt, &lastSuccess, &nextAttempt,
			&ppExpires, &rs.ConsecutiveFailures, &httpStatus, &rs.Generation)
	if errors.Is(err, sql.ErrNoRows) {
		return RefreshState{AccountID: accountID, Result: "never"}, nil
	}
	if err != nil {
		return RefreshState{}, fmt.Errorf("store: get refresh_state: %w", err)
	}
	rs.LastAttemptAt = nullIntToTime(lastAttempt)
	rs.LastSuccessAt = nullIntToTime(lastSuccess)
	rs.NextAttemptAt = nullIntToTime(nextAttempt)
	rs.ProxyPassExpiresAt = nullIntToTime(ppExpires)
	if httpStatus.Valid {
		v := int(httpStatus.Int64)
		rs.HTTPStatus = &v
	}
	return rs, nil
}

// DeleteRefreshState removes the refresh_state row for an account.
func (d *DB) DeleteRefreshState(ctx context.Context, tx *sql.Tx, accountID int64) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM refresh_state WHERE account_id=?`, accountID)
	return err
}

// AddRejectedDigest adds a rejected token digest for an account, pruning old
// entries beyond MaxRejectedPerAccount in the same transaction.
func (d *DB) AddRejectedDigest(ctx context.Context, tx *sql.Tx, accountID int64, digest string) error {
	now := time.Now().Unix()
	_, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO rejected_tokens(digest, account_id, created_at) VALUES(?,?,?)`,
		digest, accountID, now)
	if err != nil {
		return fmt.Errorf("store: add rejected digest: %w", err)
	}
	// Prune oldest beyond cap.
	_, err = tx.ExecContext(ctx, `
		DELETE FROM rejected_tokens
		WHERE account_id = ? AND digest NOT IN (
			SELECT digest FROM rejected_tokens
			WHERE account_id = ?
			ORDER BY created_at DESC LIMIT ?
		)`, accountID, accountID, MaxRejectedPerAccount)
	if err != nil {
		return fmt.Errorf("store: prune rejected digests: %w", err)
	}
	return nil
}

// IsRejected returns true if the given digest is in the rejected_tokens table.
func (d *DB) IsRejected(ctx context.Context, digest string) (bool, error) {
	var count int
	err := d.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM rejected_tokens WHERE digest=?`, digest).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("store: is_rejected: %w", err)
	}
	return count > 0, nil
}

// AccountIDForDigest returns the account_id that owns a proxy_pass digest.
// This is used to route a Reject call to the right account.
func (d *DB) AccountIDForDigest(ctx context.Context, digest string) (int64, error) {
	var id int64
	err := d.db.QueryRowContext(ctx, `SELECT account_id FROM proxy_pass WHERE digest=?`, digest).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("store: no account for digest")
	}
	if err != nil {
		return 0, fmt.Errorf("store: account_id_for_digest: %w", err)
	}
	return id, nil
}

// DigestFor computes the SHA-256 hex digest of a raw token string.
func DigestFor(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func timeToNullInt(t *time.Time) sql.NullInt64 {
	if t == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Valid: true, Int64: t.Unix()}
}

func nullIntToTime(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := time.Unix(n.Int64, 0)
	return &t
}
