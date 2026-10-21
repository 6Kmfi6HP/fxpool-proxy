package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fxpool-proxy/internal/securefile"
)

func writeLegacyCreds(t *testing.T, root, uid, email, sessionToken string) {
	t.Helper()
	cred := struct {
		Schema       int    `json:"schema"`
		Email        string `json:"email"`
		UID          string `json:"uid"`
		SessionToken string `json:"session_token"`
	}{1, email, uid, sessionToken}
	b, _ := json.Marshal(cred)
	if err := os.MkdirAll(filepath.Join(root, "tokens"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := securefile.AtomicWrite(filepath.Join(root, "tokens", "renewal_credentials.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeLegacyRejected(t *testing.T, root string, digests ...string) {
	t.Helper()
	var lines string
	for _, d := range digests {
		lines += d + "\n"
	}
	if err := securefile.AtomicWrite(filepath.Join(root, "tokens", "rejected_proxy_pass.sha256"), []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyImportSkippedWhenMarkerSet(t *testing.T) {
	root := tmpRoot(t)
	d, _ := Open(root)
	defer d.Close()
	ctx := context.Background()

	// Pre-set the marker.
	tx, _ := d.Begin(ctx)
	_ = d.MetaSet(ctx, tx, LegacyImportKey, "done")
	_ = tx.Commit()

	res, err := d.LegacyImport(ctx, root)
	if err != nil {
		t.Fatalf("LegacyImport: %v", err)
	}
	if !res.Skipped {
		t.Fatal("expected Skipped=true")
	}
}

func TestLegacyImportNoCredentialsMarksDone(t *testing.T) {
	root := tmpRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "tokens"), 0o700); err != nil {
		t.Fatal(err)
	}
	d, _ := Open(root)
	defer d.Close()
	ctx := context.Background()

	res, err := d.LegacyImport(ctx, root)
	if err != nil {
		t.Fatalf("LegacyImport no creds: %v", err)
	}
	if !res.Skipped || res.AccountImported {
		t.Fatalf("expected Skipped with no account, got %+v", res)
	}

	// Re-running must skip (marker set).
	res2, err := d.LegacyImport(ctx, root)
	if err != nil {
		t.Fatalf("LegacyImport rerun: %v", err)
	}
	if !res2.Skipped {
		t.Fatal("expected Skipped on rerun")
	}
}

func TestLegacyImportIdempotent(t *testing.T) {
	uid := "abcdefabcdefabcdefabcdefabcdefab"
	email := "test@example.com"
	session := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	root := tmpRoot(t)
	writeLegacyCreds(t, root, uid, email, session)

	d, _ := Open(root)
	defer d.Close()
	ctx := context.Background()

	res, err := d.LegacyImport(ctx, root)
	if err != nil {
		t.Fatalf("first import: %v", err)
	}
	if !res.AccountImported {
		t.Fatal("expected AccountImported=true")
	}

	// Second run must skip.
	res2, _ := d.LegacyImport(ctx, root)
	if !res2.Skipped {
		t.Fatal("expected Skipped on second run")
	}

	// Account must exist exactly once.
	accounts, _ := d.ListAccounts(ctx)
	if len(accounts) != 1 {
		t.Fatalf("expected 1 account, got %d", len(accounts))
	}
	if accounts[0].UID != uid {
		t.Fatalf("uid mismatch: got %s", accounts[0].UID)
	}
}

func TestLegacyImportExistingAccountsBlocksMarkerless(t *testing.T) {
	root := tmpRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "tokens"), 0o700); err != nil {
		t.Fatal(err)
	}
	d, _ := Open(root)
	defer d.Close()
	ctx := context.Background()

	// Insert an account directly without setting the marker.
	acc := Account{
		UID:          "deadbeefdeadbeefdeadbeefdeadbeef",
		Email:        "x@x.com",
		SessionToken: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Enabled:      true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	tx, _ := d.Begin(ctx)
	_, _ = d.UpsertAccount(ctx, tx, acc)
	_ = tx.Commit()

	// LegacyImport must fail closed.
	_, err := d.LegacyImport(ctx, root)
	if err == nil {
		t.Fatal("expected error when accounts exist without marker")
	}
}

func TestLegacyImportRejectedDigests(t *testing.T) {
	uid := "fedcba9876543210fedcba9876543210"
	email := "rej@example.com"
	session := "0000000000000000000000000000000000000000000000000000000000000000"
	root := tmpRoot(t)
	writeLegacyCreds(t, root, uid, email, session)

	// Write 5 valid SHA-256 hex digests.
	digests := make([]string, 5)
	for i := range digests {
		digests[i] = DigestFor("token-" + string(rune('a'+i)))
	}
	writeLegacyRejected(t, root, digests...)

	d, _ := Open(root)
	defer d.Close()
	ctx := context.Background()

	res, err := d.LegacyImport(ctx, root)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if res.RejectedImported != 5 {
		t.Fatalf("RejectedImported=%d, want 5", res.RejectedImported)
	}
	for _, dg := range digests {
		ok, err := d.IsRejected(ctx, dg)
		if err != nil || !ok {
			t.Fatalf("digest %s not rejected: err=%v", dg, err)
		}
	}
}
