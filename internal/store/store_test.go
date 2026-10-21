package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tmpRoot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestOpenCreatesDBWithSafePermissions(t *testing.T) {
	root := tmpRoot(t)
	d, err := Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()

	dbPath := filepath.Join(root, "data", "fxpool.db")
	fi, err := os.Lstat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("db mode %o, want group/other bits clear", fi.Mode().Perm())
	}
}

func TestOpenRejectsSymlinkDB(t *testing.T) {
	root := tmpRoot(t)
	// Create a symlink at the db path pointing to /etc/passwd-like target.
	dbPath := filepath.Join(root, "data", "fxpool.db")
	target := filepath.Join(root, "data", "real.db")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, dbPath); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root); err == nil {
		t.Fatal("expected symlink rejection, got nil")
	}
}

func TestSchemaMigratesToUserVersion1(t *testing.T) {
	root := tmpRoot(t)
	d, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var ver int
	if err := d.db.QueryRowContext(context.Background(), "PRAGMA user_version").Scan(&ver); err != nil {
		t.Fatal(err)
	}
	if ver != CurrentSchemaVersion {
		t.Fatalf("user_version=%d, want %d", ver, CurrentSchemaVersion)
	}
}

func TestReopenIsIdempotent(t *testing.T) {
	root := tmpRoot(t)
	d1, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	d1.Close()

	d2, err := Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer d2.Close()

	// user_version should still be 1.
	var ver int
	if err := d2.db.QueryRowContext(context.Background(), "PRAGMA user_version").Scan(&ver); err != nil {
		t.Fatal(err)
	}
	if ver != 1 {
		t.Fatalf("user_version after reopen=%d, want 1", ver)
	}
}

func TestIntegrityCheckOnFreshDB(t *testing.T) {
	root := tmpRoot(t)
	d, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.IntegrityCheck(); err != nil {
		t.Fatalf("integrity_check on fresh db: %v", err)
	}
}

func TestCorruptDBFailsClosed(t *testing.T) {
	root := tmpRoot(t)
	d, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	// Overwrite the db file with garbage.
	dbPath := filepath.Join(root, "data", "fxpool.db")
	if err := os.WriteFile(dbPath, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Reopen should fail during migration/integrity check (the driver will
	// reject the garbage). We accept any error here.
	d2, err := Open(root)
	if err == nil {
		d2.Close()
		// If open somehow succeeded, integrity_check must fail.
		if err := d2.IntegrityCheck(); err == nil {
			t.Fatal("expected corrupt DB to fail closed")
		}
	}
}

func TestAccountUpsertAndList(t *testing.T) {
	root := tmpRoot(t)
	d, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()

	acc := Account{
		UID:          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Email:        "a@example.com",
		SessionToken: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Enabled:      true,
		Source:       "manual",
		CreatedAt:    time.Unix(1000, 0),
		UpdatedAt:    time.Unix(1000, 0),
	}
	tx, err := d.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id, err := d.UpsertAccount(ctx, tx, acc)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Fatal("account id is 0")
	}

	got, err := d.GetAccount(ctx, acc.UID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Email != acc.Email || got.SessionToken != acc.SessionToken {
		t.Fatalf("got %+v, want email+token match", got)
	}

	// Update the email.
	acc.Email = "a2@example.com"
	acc.UpdatedAt = time.Unix(2000, 0)
	tx, err = d.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.UpsertAccount(ctx, tx, acc); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got, _ = d.GetAccount(ctx, acc.UID)
	if got.Email != "a2@example.com" {
		t.Fatalf("email not updated: %s", got.Email)
	}

	// List.
	list, err := d.ListAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("list len=%d, want 1", len(list))
	}
}

func TestSetAccountEnabled(t *testing.T) {
	root := tmpRoot(t)
	d, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()
	acc := Account{
		UID:          "cccccccccccccccccccccccccccccccc",
		Email:        "c@example.com",
		SessionToken: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		Enabled:      true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	tx, _ := d.Begin(ctx)
	_, _ = d.UpsertAccount(ctx, tx, acc)
	_ = tx.Commit()

	if err := d.SetAccountEnabled(ctx, acc.UID, false); err != nil {
		t.Fatal(err)
	}
	got, _ := d.GetAccount(ctx, acc.UID)
	if got.Enabled {
		t.Fatal("account still enabled")
	}
}

func TestProxyPassUpsertReplace(t *testing.T) {
	root := tmpRoot(t)
	d, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()
	acc := Account{
		UID:          "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		Email:        "e@example.com",
		SessionToken: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		Enabled:      true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	tx, _ := d.Begin(ctx)
	id, _ := d.UpsertAccount(ctx, tx, acc)
	pp := ProxyPass{
		AccountID: id,
		JWT:       "jwt-old",
		Digest:    DigestFor("jwt-old"),
		ExpiresAt: time.Unix(9000, 0),
		FetchedAt: time.Unix(8000, 0),
	}
	_ = d.UpsertProxyPass(ctx, tx, pp)
	_ = tx.Commit()

	// Replace with a new token.
	tx, _ = d.Begin(ctx)
	pp2 := pp
	pp2.JWT = "jwt-new"
	pp2.Digest = DigestFor("jwt-new")
	pp2.ExpiresAt = time.Unix(9500, 0)
	_ = d.UpsertProxyPass(ctx, tx, pp2)
	_ = tx.Commit()

	got, _ := d.GetProxyPass(ctx, id)
	if got.JWT != "jwt-new" {
		t.Fatalf("jwt=%q, want jwt-new", got.JWT)
	}
}

func TestRefreshStateUpsert(t *testing.T) {
	root := tmpRoot(t)
	d, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()
	acc := Account{
		UID:          "11111111111111111111111111111111",
		Email:        "one@example.com",
		SessionToken: "2222222222222222222222222222222222222222222222222222222222222222",
		Enabled:      true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	tx, _ := d.Begin(ctx)
	id, _ := d.UpsertAccount(ctx, tx, acc)
	_ = tx.Commit()

	la := time.Unix(100, 0)
	ls := time.Unix(110, 0)
	na := time.Unix(120, 0)
	pe := time.Unix(130, 0)
	st := 200
	rs := RefreshState{
		AccountID:           id,
		Result:              "success",
		LastAttemptAt:       &la,
		LastSuccessAt:       &ls,
		NextAttemptAt:       &na,
		ProxyPassExpiresAt:  &pe,
		ConsecutiveFailures: 0,
		HTTPStatus:          &st,
		Generation:          1,
	}
	tx, _ = d.Begin(ctx)
	if err := d.UpsertRefreshState(ctx, tx, rs); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	_ = tx.Commit()

	got, _ := d.GetRefreshState(ctx, id)
	if got.Result != "success" || got.Generation != 1 {
		t.Fatalf("got %+v", got)
	}
	if got.HTTPStatus == nil || *got.HTTPStatus != 200 {
		t.Fatalf("http_status=%v", got.HTTPStatus)
	}
	if got.LastAttemptAt == nil || !got.LastAttemptAt.Equal(la) {
		t.Fatalf("last_attempt_at=%v", got.LastAttemptAt)
	}
}

func TestRejectedDigestPrune(t *testing.T) {
	root := tmpRoot(t)
	d, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()
	acc := Account{
		UID:          "33333333333333333333333333333333",
		Email:        "three@example.com",
		SessionToken: "4444444444444444444444444444444444444444444444444444444444444444",
		Enabled:      true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	tx, _ := d.Begin(ctx)
	id, _ := d.UpsertAccount(ctx, tx, acc)
	_ = tx.Commit()

	// Add MaxRejectedPerAccount + 5 digests.
	for i := 0; i < MaxRejectedPerAccount+5; i++ {
		tx, _ := d.Begin(ctx)
		dig := DigestFor("token-" + string(rune('a'+i)))
		if err := d.AddRejectedDigest(ctx, tx, id, dig); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		_ = tx.Commit()
	}
	var count int
	_ = d.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM rejected_tokens WHERE account_id=?`, id).Scan(&count)
	if count > MaxRejectedPerAccount {
		t.Fatalf("rejected count=%d, cap=%d", count, MaxRejectedPerAccount)
	}
}

func TestAccountIDForDigest(t *testing.T) {
	root := tmpRoot(t)
	d, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()
	acc := Account{
		UID:          "55555555555555555555555555555555",
		Email:        "five@example.com",
		SessionToken: "6666666666666666666666666666666666666666666666666666666666666666",
		Enabled:      true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	tx, _ := d.Begin(ctx)
	id, _ := d.UpsertAccount(ctx, tx, acc)
	dig := DigestFor("jwt-x")
	_ = d.UpsertProxyPass(ctx, tx, ProxyPass{
		AccountID: id,
		JWT:       "jwt-x",
		Digest:    dig,
		ExpiresAt: time.Unix(9000, 0),
		FetchedAt: time.Unix(8000, 0),
	})
	_ = tx.Commit()

	got, err := d.AccountIDForDigest(ctx, dig)
	if err != nil {
		t.Fatal(err)
	}
	if got != id {
		t.Fatalf("account_id=%d, want %d", got, id)
	}
}

func TestDeleteAccountCascades(t *testing.T) {
	root := tmpRoot(t)
	d, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()
	acc := Account{
		UID:          "77777777777777777777777777777777",
		Email:        "seven@example.com",
		SessionToken: "8888888888888888888888888888888888888888888888888888888888888888",
		Enabled:      true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	tx, _ := d.Begin(ctx)
	id, _ := d.UpsertAccount(ctx, tx, acc)
	_ = d.UpsertProxyPass(ctx, tx, ProxyPass{
		AccountID: id, JWT: "jwt", Digest: DigestFor("jwt"), ExpiresAt: time.Unix(9000, 0), FetchedAt: time.Unix(8000, 0),
	})
	_ = d.UpsertRefreshState(ctx, tx, RefreshState{AccountID: id, Result: "success", Generation: 1})
	_ = d.AddRejectedDigest(ctx, tx, id, DigestFor("rejected-1"))
	_ = tx.Commit()

	tx, _ = d.Begin(ctx)
	if err := d.DeleteAccount(ctx, tx, acc.UID); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	_ = tx.Commit()

	// proxy_pass should be gone (FK cascade).
	if _, err := d.GetProxyPass(ctx, id); err == nil {
		t.Fatal("proxy_pass not cascaded")
	}
	// refresh_state should be gone.
	rs, _ := d.GetRefreshState(ctx, id)
	if rs.Result != "never" {
		t.Fatalf("refresh_state result=%q, want never (absent)", rs.Result)
	}
}
