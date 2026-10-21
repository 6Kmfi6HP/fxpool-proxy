package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fxpool-proxy/internal/securefile"
	"fxpool-proxy/internal/token"
)

// LegacyImportKey is the meta key that marks the one-time legacy file import.
const LegacyImportKey = "legacy_import_v1"

// LegacyImportResult summarizes a single legacy import run.
type LegacyImportResult struct {
	Skipped          bool   // true if the import was already done
	AccountImported  bool   // true if a renewal_credentials.json was imported
	UID              string // uid of the imported account (empty if none)
	TokenImported    bool   // true if a proxy_pass.jwt was imported
	StateImported    bool   // true if a refresh_state.json was imported
	RejectedImported int    // number of rejected digests imported
	Diagnostics      string // human-readable notes; never contains secrets
}

// LegacyImport performs the one-time, offline, idempotent import of legacy
// files from root/tokens/ into the database. Everything runs inside a single
// write transaction together with the legacy_import_v1 meta marker so that
// account data and the completion flag are atomically visible.
//
// Rules (plan §5):
//   - If legacy_import_v1 is already set, skip and return immediately.
//   - If the marker is absent but the accounts table is non-empty, fail
//     closed: the operator must resolve the split state explicitly.
//   - Invalid credentials never create a half account; diagnostics are
//     recorded but secrets never leak into them.
//   - proxy_pass and refresh_state are only migrated when the account was
//     imported and ownership is unambiguous.
//   - Legacy files are left in place; no rename, no delete.
func (d *DB) LegacyImport(ctx context.Context, root string) (LegacyImportResult, error) {
	res := LegacyImportResult{}

	// Fast-path: already done.
	if v, ok, err := d.MetaGet(ctx, LegacyImportKey); err != nil {
		return res, err
	} else if ok && v != "" {
		res.Skipped = true
		return res, nil
	}

	tx, err := d.Begin(ctx)
	if err != nil {
		return res, fmt.Errorf("store: legacy import begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Marker absent: check whether accounts already exist (conflict guard).
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM accounts`).Scan(&n); err != nil {
		return res, fmt.Errorf("store: legacy import count accounts: %w", err)
	}
	if n > 0 {
		return res, errors.New(
			"store: database has accounts but no legacy_import_v1 marker; " +
				"refusing to auto-merge — back up the database and legacy files, " +
				"then run the documented recovery procedure",
		)
	}

	tokensDir := filepath.Join(root, "tokens")
	credPath := filepath.Join(tokensDir, "renewal_credentials.json")

	cred, credErr := readLegacyCredentials(credPath)
	if credErr != nil {
		// No valid credentials: record diagnostics and mark done so we don't
		// retry every startup.  This is an expected terminal state for a
		// fresh install with no prior credentials.
		res.Diagnostics = fmt.Sprintf("no legacy credentials imported: %s", credErr)
		if err := d.MetaSet(ctx, tx, LegacyImportKey, "skipped:"+res.Diagnostics); err != nil {
			return res, err
		}
		if err := tx.Commit(); err != nil {
			return res, fmt.Errorf("store: legacy import commit (skip): %w", err)
		}
		committed = true
		res.Skipped = true
		return res, nil
	}

	// Import the account row.
	now := time.Now()
	acc := Account{
		UID:          cred.UID,
		Email:        cred.Email,
		SessionToken: cred.SessionToken,
		Enabled:      true,
		Source:       "migrated",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	accID, err := d.UpsertAccount(ctx, tx, acc)
	if err != nil {
		return res, err
	}
	res.AccountImported = true
	res.UID = cred.UID

	// Migrate proxy_pass.jwt only if valid.
	pp, ppOK, ppErr := readLegacyProxyPass(tokensDir, accID, now)
	if ppErr != nil {
		return res, fmt.Errorf("store: legacy proxy_pass: %w", ppErr)
	}
	if ppOK {
		if err := d.UpsertProxyPass(ctx, tx, pp); err != nil {
			return res, err
		}
		res.TokenImported = true
	}

	// Migrate refresh_state.json if present.
	rs, rsOK, rsErr := readLegacyRefreshState(tokensDir, accID)
	if rsErr != nil {
		return res, fmt.Errorf("store: legacy refresh_state: %w", rsErr)
	}
	if rsOK {
		if err := d.UpsertRefreshState(ctx, tx, rs); err != nil {
			return res, err
		}
		res.StateImported = true
	}

	// Migrate rejected_proxy_pass.sha256.
	cnt, err := importLegacyRejectedTx(ctx, tx, tokensDir, accID, now)
	if err != nil {
		return res, err
	}
	res.RejectedImported = cnt

	if err := d.MetaSet(ctx, tx, LegacyImportKey, "done"); err != nil {
		return res, err
	}
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("store: legacy import commit: %w", err)
	}
	committed = true
	return res, nil
}

// readLegacyCredentials reads and validates tokens/renewal_credentials.json
// using the same validation rules as token.Manager.LoadCredentials.
func readLegacyCredentials(path string) (token.Credentials, error) {
	b, err := securefile.ReadRegular(path, 16<<10, true)
	if err != nil {
		return token.Credentials{}, err
	}
	var c token.Credentials
	if json.Unmarshal(b, &c) != nil || c.Schema != 1 || !strings.Contains(c.Email, "@") ||
		len(c.UID) != 32 || len(c.SessionToken) != 64 {
		return token.Credentials{}, errors.New("unsupported or invalid renewal credentials")
	}
	if _, e := hex.DecodeString(c.UID); e != nil {
		return token.Credentials{}, errors.New("invalid uid")
	}
	if _, e := hex.DecodeString(c.SessionToken); e != nil {
		return token.Credentials{}, errors.New("invalid session token")
	}
	c.UID = strings.ToLower(c.UID)
	c.SessionToken = strings.ToLower(c.SessionToken)
	return c, nil
}

// readLegacyProxyPass reads tokens/proxy_pass.jwt.
// Returns ok=false if the file is absent or the token cannot be parsed.
func readLegacyProxyPass(tokensDir string, accID int64, now time.Time) (ProxyPass, bool, error) {
	path := filepath.Join(tokensDir, "proxy_pass.jwt")
	b, err := securefile.ReadRegular(path, 64<<10, true)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ProxyPass{}, false, nil
		}
		return ProxyPass{}, false, err
	}
	raw := strings.TrimSpace(string(b))
	if raw == "" {
		return ProxyPass{}, false, nil
	}
	// Parse claims to obtain expiry.  Empty guardian disables audience
	// validation; we just need the exp field for storage.
	claims, e := token.DecodeAndValidateJWT(raw, "", time.Now(), 0)
	if e != nil {
		// Unparseable token: skip silently rather than failing the whole import.
		return ProxyPass{}, false, nil
	}
	dig := DigestFor(raw)
	return ProxyPass{
		AccountID: accID,
		JWT:       raw,
		Digest:    dig,
		ExpiresAt: time.Unix(int64(claims.Expires), 0),
		FetchedAt: now,
	}, true, nil
}

// readLegacyRefreshState maps tokens/refresh_state.json into a RefreshState row.
func readLegacyRefreshState(tokensDir string, accID int64) (RefreshState, bool, error) {
	path := filepath.Join(tokensDir, "refresh_state.json")
	s := token.LoadState(path)
	if s.Result == "never" {
		return RefreshState{}, false, nil
	}
	rs := RefreshState{
		AccountID:           accID,
		Result:              s.Result,
		ConsecutiveFailures: s.ConsecutiveFailures,
		Generation:          s.Generation,
	}
	if s.LastAttemptAt != nil {
		t := time.Unix(int64(*s.LastAttemptAt), 0)
		rs.LastAttemptAt = &t
	}
	if s.LastSuccessAt != nil {
		t := time.Unix(int64(*s.LastSuccessAt), 0)
		rs.LastSuccessAt = &t
	}
	if s.NextAttemptAt != nil {
		t := time.Unix(int64(*s.NextAttemptAt), 0)
		rs.NextAttemptAt = &t
	}
	if s.ProxyPassExpiresAt != nil {
		t := time.Unix(int64(*s.ProxyPassExpiresAt), 0)
		rs.ProxyPassExpiresAt = &t
	}
	if s.HTTPStatus != nil {
		v := *s.HTTPStatus
		rs.HTTPStatus = &v
	}
	return rs, true, nil
}

// importLegacyRejectedTx reads tokens/rejected_proxy_pass.sha256 and inserts
// valid hex digests for accID within the given transaction.
func importLegacyRejectedTx(ctx context.Context, tx *sql.Tx, tokensDir string, accID int64, now time.Time) (int, error) {
	path := filepath.Join(tokensDir, "rejected_proxy_pass.sha256")
	b, err := securefile.ReadRegular(path, 4096, false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	lines := strings.Fields(string(b))
	// Keep at most MaxRejectedPerAccount newest lines.
	if len(lines) > MaxRejectedPerAccount {
		lines = lines[len(lines)-MaxRejectedPerAccount:]
	}
	count := 0
	ts := now.Unix()
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) != 64 {
			continue // not a SHA-256 hex digest
		}
		if _, e := hex.DecodeString(line); e != nil {
			continue
		}
		_, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO rejected_tokens(digest, account_id, created_at) VALUES(?,?,?)`,
			line, accID, ts)
		if err != nil {
			return count, fmt.Errorf("store: import rejected digest: %w", err)
		}
		count++
		ts++ // ensure distinct created_at for ordering
	}
	return count, nil
}
