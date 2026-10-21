package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"fxpool-proxy/internal/token"
)

// ManagerBackend wraps a *DB to satisfy token.StoreBackend.
// The account ID is passed per-call by the Manager (via Manager.AccountID),
// not stored here. Storing it here alongside Manager.AccountID would create
// two independent copies that could silently diverge; all methods receive it
// as a parameter through the StoreBackend interface instead.
type ManagerBackend struct {
	DB *DB
}

// Compile-time check that ManagerBackend satisfies token.StoreBackend.
var _ token.StoreBackend = (*ManagerBackend)(nil)

// LoadCredentials returns the renewal credentials for the account.
func (b *ManagerBackend) LoadCredentials(accountID int64) (token.Credentials, error) {
	ctx := context.Background()
	acc, err := b.DB.getAccountByID(ctx, accountID)
	if err != nil {
		return token.Credentials{}, err
	}
	return token.Credentials{
		Schema:       1,
		Email:        acc.Email,
		UID:          acc.UID,
		SessionToken: acc.SessionToken,
	}, nil
}

// ReadToken returns the stored raw ProxyPass JWT for the account.
func (b *ManagerBackend) ReadToken(accountID int64) (string, error) {
	ctx := context.Background()
	pp, err := b.DB.GetProxyPass(ctx, accountID)
	if err != nil {
		// No token stored yet.
		return "", nil
	}
	return pp.JWT, nil
}

// SaveToken persists a raw JWT with its expiry and fetch timestamps.
func (b *ManagerBackend) SaveToken(accountID int64, jwt string, expiresAt, fetchedAt time.Time) error {
	ctx := context.Background()
	tx, err := b.DB.Begin(ctx)
	if err != nil {
		return err
	}
	pp := ProxyPass{
		AccountID: accountID,
		JWT:       jwt,
		Digest:    DigestFor(jwt),
		ExpiresAt: expiresAt,
		FetchedAt: fetchedAt,
	}
	if err := b.DB.UpsertProxyPass(ctx, tx, pp); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// LoadState returns the current refresh state for the account.
func (b *ManagerBackend) LoadState(accountID int64) (token.RefreshState, error) {
	ctx := context.Background()
	rs, err := b.DB.GetRefreshState(ctx, accountID)
	if err != nil {
		return token.EmptyState(), err
	}
	return dbStateToToken(rs), nil
}

// SaveState persists a refresh state row for the account.
func (b *ManagerBackend) SaveState(accountID int64, rs token.RefreshState) error {
	ctx := context.Background()
	tx, err := b.DB.Begin(ctx)
	if err != nil {
		return err
	}
	dbRS := tokenStateToDBState(accountID, rs)
	if err := b.DB.UpsertRefreshState(ctx, tx, dbRS); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// IsRejected reports whether the digest is in the rejected list.
func (b *ManagerBackend) IsRejected(digest string) (bool, error) {
	return b.DB.IsRejected(context.Background(), digest)
}

// Reject adds a digest to the rejected list for the account.
func (b *ManagerBackend) Reject(accountID int64, digest string) error {
	ctx := context.Background()
	tx, err := b.DB.Begin(ctx)
	if err != nil {
		return err
	}
	if err := b.DB.AddRejectedDigest(ctx, tx, accountID, digest); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// PublishCredentials upserts the account by UID and resets its token and state
// in a single transaction.
func (b *ManagerBackend) PublishCredentials(c token.Credentials) (int64, error) {
	ctx := context.Background()
	tx, err := b.DB.Begin(ctx)
	if err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	now := time.Now()
	acc := Account{
		UID:          c.UID,
		Email:        c.Email,
		SessionToken: c.SessionToken,
		Enabled:      true,
		Source:       "import",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	accID, err := b.DB.UpsertAccount(ctx, tx, acc)
	if err != nil {
		return 0, err
	}

	// Delete existing proxy_pass and rejected_tokens for this account.
	if err := b.DB.DeleteProxyPass(ctx, tx, accID); err != nil {
		return 0, err
	}
	// Delete rejected digests so a reimport starts fresh.
	if _, err := tx.ExecContext(ctx, `DELETE FROM rejected_tokens WHERE account_id=?`, accID); err != nil {
		return 0, fmt.Errorf("store: clear rejected on reimport: %w", err)
	}
	// Reset refresh state to credentials_imported.
	rs := RefreshState{
		AccountID:           accID,
		Result:              "credentials_imported",
		ConsecutiveFailures: 0,
		Generation:          0,
	}
	// Preserve generation if state existed.
	if existing, err := b.DB.GetRefreshState(ctx, accID); err == nil {
		rs.Generation = existing.Generation
	}
	if err := b.DB.UpsertRefreshState(ctx, tx, rs); err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: publish credentials commit: %w", err)
	}
	committed = true
	return accID, nil
}

// getAccountByID is a helper to look up an account by its integer ID.
func (d *DB) getAccountByID(ctx context.Context, id int64) (Account, error) {
	var a Account
	var createdAt, updatedAt int64
	var enabled int
	err := d.db.QueryRowContext(ctx, `
		SELECT id, uid, email, session_token, enabled, label, source, created_at, updated_at
		FROM accounts WHERE id = ?`, id).
		Scan(&a.ID, &a.UID, &a.Email, &a.SessionToken, &enabled, &a.Label, &a.Source, &createdAt, &updatedAt)
	if errors.Is(err, os.ErrNotExist) {
		return Account{}, fmt.Errorf("store: account %d not found", id)
	}
	if err != nil {
		return Account{}, fmt.Errorf("store: get account by id %d: %w", id, err)
	}
	a.Enabled = enabled != 0
	a.CreatedAt = time.Unix(createdAt, 0)
	a.UpdatedAt = time.Unix(updatedAt, 0)
	return a, nil
}

// dbStateToToken converts a store.RefreshState to token.RefreshState.
func dbStateToToken(rs RefreshState) token.RefreshState {
	s := token.RefreshState{
		Schema:              1,
		Result:              rs.Result,
		ConsecutiveFailures: rs.ConsecutiveFailures,
		Generation:          rs.Generation,
	}
	if rs.LastAttemptAt != nil {
		v := float64(rs.LastAttemptAt.Unix())
		s.LastAttemptAt = &v
	}
	if rs.LastSuccessAt != nil {
		v := float64(rs.LastSuccessAt.Unix())
		s.LastSuccessAt = &v
	}
	if rs.NextAttemptAt != nil {
		v := float64(rs.NextAttemptAt.Unix())
		s.NextAttemptAt = &v
	}
	if rs.ProxyPassExpiresAt != nil {
		v := float64(rs.ProxyPassExpiresAt.Unix())
		s.ProxyPassExpiresAt = &v
	}
	if rs.HTTPStatus != nil {
		v := *rs.HTTPStatus
		s.HTTPStatus = &v
	}
	return s
}

// tokenStateToDBState converts a token.RefreshState to store.RefreshState.
func tokenStateToDBState(accountID int64, ts token.RefreshState) RefreshState {
	rs := RefreshState{
		AccountID:           accountID,
		Result:              ts.Result,
		ConsecutiveFailures: ts.ConsecutiveFailures,
		Generation:          ts.Generation,
	}
	if ts.LastAttemptAt != nil {
		t := time.Unix(int64(*ts.LastAttemptAt), 0)
		rs.LastAttemptAt = &t
	}
	if ts.LastSuccessAt != nil {
		t := time.Unix(int64(*ts.LastSuccessAt), 0)
		rs.LastSuccessAt = &t
	}
	if ts.NextAttemptAt != nil {
		t := time.Unix(int64(*ts.NextAttemptAt), 0)
		rs.NextAttemptAt = &t
	}
	if ts.ProxyPassExpiresAt != nil {
		t := time.Unix(int64(*ts.ProxyPassExpiresAt), 0)
		rs.ProxyPassExpiresAt = &t
	}
	if ts.HTTPStatus != nil {
		v := *ts.HTTPStatus
		rs.HTTPStatus = &v
	}
	return rs
}
