package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeGuardianJWT builds a structurally valid JWT that DecodeAndValidateJWT
// accepts with the given guardian URL as issuer/audience.
// The signature is a valid base64url string (no cryptographic check is done).
// nonce is embedded in the subject so each call yields a distinct token
// (and therefore a distinct digest), avoiding proxy_pass UNIQUE collisions.
func fakeGuardianJWT(guardianURL string, ttl time.Duration, nonce int) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	now := float64(time.Now().Unix())
	exp := float64(time.Now().Add(ttl).Unix())
	// Use the full guardianURL as issuer so url.Parse returns a valid URL
	// with a proper hostname; a bare host:port is misread by url.Parse as
	// scheme:path, causing Hostname() to return "" and the issuer check to fail.
	claims := fmt.Sprintf(`{"sub":"test-%d","iss":%q,"aud":%q,"iat":%g,"nbf":%g,"exp":%g}`,
		nonce, guardianURL, guardianURL, now, now, exp)
	payload := base64.RawURLEncoding.EncodeToString([]byte(claims))
	sig := base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
	return header + "." + payload + "." + sig
}

// fakeServer builds a combined fake FxA auth + Guardian server for one account.
// uid and sessionToken identify the account; the server counts how many times
// the Guardian /token endpoint is called so tests can assert refresh counts.
type fakeServer struct {
	srv          *httptest.Server
	uid          string
	sessionToken string
	tokenCalls   atomic.Int32
}

func newFakeServer(uid, sessionToken string) *fakeServer {
	fs := &fakeServer{uid: uid, sessionToken: sessionToken}
	mux := http.NewServeMux()

	// FxA auth: credentials/status → v1 stretch
	mux.HandleFunc("/account/credentials/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"email":"user-%s@example.test","verifierVersion":1}`, uid[:8])
	})
	// FxA auth: login accepts any authPW for simplicity
	mux.HandleFunc("/account/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"uid":%q,"sessionToken":%q,"verified":true}`, uid, sessionToken)
	})
	// FxA OAuth: authorization (PKCE step 1)
	mux.HandleFunc("/oauth/authorization", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		state, _ := body["state"].(string)
		redirect := fs.srv.URL + "/?code=testcode123&state=" + state
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"redirect":%q}`, redirect)
	})
	// FxA OAuth: token exchange (PKCE step 2).
	// authorize() calls FxAOAuth+"/token"; since tests set --fxa-base to the
	// fake server root (no "/v1" suffix), FxAOAuth becomes srvURL, so the path
	// that arrives is "/token", not "/v1/token".
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"acc-%s-fake","token_type":"bearer"}`, uid[:8])
	})
	// FxA OAuth: destroy
	mux.HandleFunc("/destroy", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// Guardian: GET /api/v1/fpn/token  (ProxyPass JWT)
	mux.HandleFunc("/api/v1/fpn/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			// Usage endpoint
			w.Header().Set("X-Quota-Unlimited", "true")
			return
		}
		fs.tokenCalls.Add(1)
		jwt := fakeGuardianJWT(fs.srv.URL, 2*time.Hour, int(fs.tokenCalls.Load()))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token":%q}`, jwt)
	})

	fs.srv = httptest.NewServer(mux)
	return fs
}

func (fs *fakeServer) URL() string  { return fs.srv.URL }
func (fs *fakeServer) Close()        { fs.srv.Close() }

// writeBundle writes a credential bundle file for import-credentials.
func writeBundle(t *testing.T, dir, uid, sessionToken string) string {
	t.Helper()
	bundle := map[string]string{
		"schema":        "firefox-ip-protection-renewal-credentials-v1",
		"email":         fmt.Sprintf("user-%s@example.test", uid[:8]),
		"uid":           uid,
		"session_token": sessionToken,
	}
	b, _ := json.Marshal(bundle)
	path := filepath.Join(dir, "bundle-"+uid[:8]+".json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// ---- helpers to capture stdout from run() ----

func captureRun(args []string) (int, string) {
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	code := run(args)
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return code, buf.String()
}

// ---- tests ----

// TestMultiAccountImportAndList imports two accounts in account mode,
// then verifies accounts list shows both.
func TestMultiAccountImportAndList(t *testing.T) {
	uidA := "aaaa000000000000aaaa000000000000"
	uidB := "bbbb000000000000bbbb000000000000"
	sessA := "aa00000000000000aa00000000000000aa00000000000000aa00000000000000"
	sessB := "bb00000000000000bb00000000000000bb00000000000000bb00000000000000"

	srvA := newFakeServer(uidA, sessA)
	defer srvA.Close()
	srvB := newFakeServer(uidB, sessB)
	defer srvB.Close()

	root := t.TempDir()
	bundleA := writeBundle(t, root, uidA, sessA)
	bundleB := writeBundle(t, root, uidB, sessB)

	// Import account A with --no-verify (no network Guardian call).
	if code := run([]string{
		"import-credentials", bundleA,
		"--root", root,
		"--account-mode", "rr",
		"--guardian", srvA.URL(),
		"--no-verify",
	}); code != 0 {
		t.Fatalf("import A: exit %d", code)
	}

	// Import account B.
	if code := run([]string{
		"import-credentials", bundleB,
		"--root", root,
		"--account-mode", "rr",
		"--guardian", srvB.URL(),
		"--no-verify",
	}); code != 0 {
		t.Fatalf("import B: exit %d", code)
	}

	// accounts list --json should show both accounts.
	code, out := captureRun([]string{
		"accounts", "list", "--json",
		"--root", root,
		"--account-mode", "rr",
	})
	if code != 0 {
		t.Fatalf("accounts list: exit %d\noutput: %s", code, out)
	}
	var rows []struct {
		UID    string `json:"uid"`
		Email  string `json:"email"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rows); err != nil {
		t.Fatalf("json decode: %v\noutput: %s", err, out)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 accounts, got %d: %s", len(rows), out)
	}
	uids := map[string]bool{rows[0].UID: true, rows[1].UID: true}
	if !uids[uidA] || !uids[uidB] {
		t.Fatalf("missing uid in list: %v", rows)
	}
}

// TestMultiAccountRefreshAll imports two accounts, runs token-refresh --all,
// and verifies both Guardian endpoints were called.
func TestMultiAccountRefreshAll(t *testing.T) {
	uidA := "cccc000000000000cccc000000000000"
	uidB := "dddd000000000000dddd000000000000"
	sessA := "cc00000000000000cc00000000000000cc00000000000000cc00000000000000"
	sessB := "dd00000000000000dd00000000000000dd00000000000000dd00000000000000"

	srvA := newFakeServer(uidA, sessA)
	defer srvA.Close()
	srvB := newFakeServer(uidB, sessB)
	defer srvB.Close()

	root := t.TempDir()
	// Import both accounts, sharing the same guardian URL for simplicity
	// (the fake server identifies accounts by session token via FxA).
	// We use srvA's URL as the shared guardian for both; both get tokens.
	guardian := srvA.URL()

	for _, pair := range []struct{ uid, sess, bundle string }{
		{uidA, sessA, writeBundle(t, root, uidA, sessA)},
		{uidB, sessB, writeBundle(t, root, uidB, sessB)},
	} {
		if code := run([]string{
			"import-credentials", pair.bundle,
			"--root", root,
			"--account-mode", "rr",
			"--guardian", guardian,
			"--no-verify",
		}); code != 0 {
			t.Fatalf("import %s: exit %d", pair.uid[:8], code)
		}
	}

	before := srvA.tokenCalls.Load()

	// token-refresh --all should call the Guardian for each account.
	code, out := captureRun([]string{
		"token-refresh", "--all",
		"--root", root,
		"--account-mode", "rr",
		"--guardian", guardian,
		"--fxa-base", srvA.URL(),
	})
	if code != 0 {
		t.Fatalf("token-refresh --all: exit %d\noutput: %s", code, out)
	}

	after := srvA.tokenCalls.Load()
	if after-before < 2 {
		t.Fatalf("expected ≥2 Guardian token calls, got %d→%d", before, after)
	}
	if !strings.Contains(out, "seconds_left") {
		t.Fatalf("expected seconds_left in output: %s", out)
	}
}

// TestMultiAccountTokenStatus verifies token-status outputs compatible JSON
// when exactly one account exists (legacy-compatible schema).
func TestMultiAccountTokenStatusSingleAccount(t *testing.T) {
	uid := "eeee000000000000eeee000000000000"
	sess := "ee00000000000000ee00000000000000ee00000000000000ee00000000000000"

	srv := newFakeServer(uid, sess)
	defer srv.Close()

	root := t.TempDir()
	bundle := writeBundle(t, root, uid, sess)

	if code := run([]string{
		"import-credentials", bundle,
		"--root", root, "--account-mode", "rr",
		"--guardian", srv.URL(), "--no-verify",
	}); code != 0 {
		t.Fatalf("import: exit %d", code)
	}

	// Refresh to get a token stored.
	run([]string{
		"token-refresh",
		"--root", root, "--account-mode", "rr",
		"--guardian", srv.URL(), "--fxa-base", srv.URL(),
	})

	code, out := captureRun([]string{
		"token-status",
		"--root", root, "--account-mode", "rr",
		"--guardian", srv.URL(),
	})
	if code != 0 {
		t.Fatalf("token-status: exit %d\noutput: %s", code, out)
	}

	var status map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &status); err != nil {
		t.Fatalf("json decode: %v\noutput: %s", err, out)
	}
	// Must have these keys from the legacy-compatible schema.
	for _, key := range []string{"automatic_renewal_ready", "has_proxy_pass", "guardian", "refresh_state"} {
		if _, ok := status[key]; !ok {
			t.Errorf("missing key %q in token-status output: %s", key, out)
		}
	}
}

// TestMultiAccountEnableDisable imports two accounts, disables one, and
// verifies accounts list only shows the enabled one as enabled.
func TestMultiAccountEnableDisable(t *testing.T) {
	uidA := "ffff000000000000ffff000000000000"
	uidB := "0000ffff000000000000ffff00000000"
	sessA := "ff00000000000000ff00000000000000ff00000000000000ff00000000000000"
	sessB := "0f000000000000000f000000000000000f000000000000000f00000000000000"

	srvA := newFakeServer(uidA, sessA)
	defer srvA.Close()

	root := t.TempDir()
	for _, pair := range []struct{ uid, sess string }{{uidA, sessA}, {uidB, sessB}} {
		bundle := writeBundle(t, root, pair.uid, pair.sess)
		if code := run([]string{
			"import-credentials", bundle,
			"--root", root, "--account-mode", "rr",
			"--guardian", srvA.URL(), "--no-verify",
		}); code != 0 {
			t.Fatalf("import %s: exit %d", pair.uid[:8], code)
		}
	}

	// Disable account B.
	if code := run([]string{
		"accounts", "disable", uidB,
		"--root", root, "--account-mode", "rr",
	}); code != 0 {
		t.Fatalf("disable: exit %d", code)
	}

	code, out := captureRun([]string{
		"accounts", "list", "--json",
		"--root", root, "--account-mode", "rr",
	})
	if code != 0 {
		t.Fatalf("list: exit %d\noutput: %s", code, out)
	}
	var rows []struct {
		UID     string `json:"uid"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rows); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	for _, r := range rows {
		if r.UID == uidB && r.Enabled {
			t.Errorf("account B should be disabled but enabled=true")
		}
		if r.UID == uidA && !r.Enabled {
			t.Errorf("account A should be enabled but enabled=false")
		}
	}

	// Re-enable and check.
	if code := run([]string{
		"accounts", "enable", uidB,
		"--root", root, "--account-mode", "rr",
	}); code != 0 {
		t.Fatalf("enable: exit %d", code)
	}
	_, out2 := captureRun([]string{
		"accounts", "list", "--json",
		"--root", root, "--account-mode", "rr",
	})
	var rows2 []struct {
		UID     string `json:"uid"`
		Enabled bool   `json:"enabled"`
	}
	_ = json.Unmarshal([]byte(strings.TrimSpace(out2)), &rows2)
	for _, r := range rows2 {
		if r.UID == uidB && !r.Enabled {
			t.Errorf("account B should be re-enabled")
		}
	}
}

// TestMultiAccountRemove imports one account and removes it.
func TestMultiAccountRemove(t *testing.T) {
	uid := "1111000000000000111100000000000a"
	sess := "1100000000000000110000000000000011000000000000001100000000000000"
	srv := newFakeServer(uid, sess)
	defer srv.Close()

	root := t.TempDir()
	bundle := writeBundle(t, root, uid, sess)
	run([]string{"import-credentials", bundle, "--root", root, "--account-mode", "rr", "--guardian", srv.URL(), "--no-verify"})

	if code := run([]string{"accounts", "remove", "--yes", uid, "--root", root, "--account-mode", "rr"}); code != 0 {
		t.Fatalf("remove: exit %d", code)
	}

	_, out := captureRun([]string{"accounts", "list", "--json", "--root", root, "--account-mode", "rr"})
	var rows []map[string]any
	_ = json.Unmarshal([]byte(strings.TrimSpace(out)), &rows)
	for _, r := range rows {
		if r["uid"] == uid {
			t.Fatalf("removed account still in list: %s", out)
		}
	}
}

// TestLegacyMigrationOnAccountModeStart verifies that starting in account-mode
// with a legacy renewal_credentials.json performs the one-time migration and
// makes the account available in accounts list.
func TestLegacyMigrationOnAccountModeStart(t *testing.T) {
	uid := "2222000000000000222200000000000b"
	sess := "2200000000000000220000000000000022000000000000002200000000000000"

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "tokens"), 0o700); err != nil {
		t.Fatal(err)
	}

	// Write a legacy renewal_credentials.json.
	cred := map[string]any{
		"schema":        1,
		"email":         fmt.Sprintf("user-%s@example.test", uid[:8]),
		"uid":           uid,
		"session_token": sess,
	}
	b, _ := json.Marshal(cred)
	if err := os.WriteFile(filepath.Join(root, "tokens", "renewal_credentials.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}

	// token-status in account-mode should trigger migration and succeed.
	code, out := captureRun([]string{
		"token-status",
		"--root", root, "--account-mode", "rr",
		"--guardian", "https://vpn.mozilla.org",
	})
	// Exit 0: migration happened, account exists, no proxy_pass yet (has_proxy_pass=false is OK).
	if code != 0 {
		t.Fatalf("token-status after migration: exit %d\noutput: %s", code, out)
	}

	// The migrated account should appear in accounts list.
	_, listOut := captureRun([]string{
		"accounts", "list", "--json",
		"--root", root, "--account-mode", "rr",
	})
	var rows []struct{ UID string `json:"uid"` }
	_ = json.Unmarshal([]byte(strings.TrimSpace(listOut)), &rows)
	found := false
	for _, r := range rows {
		if r.UID == uid {
			found = true
		}
	}
	if !found {
		t.Fatalf("migrated uid %s not in accounts list: %s", uid[:8], listOut)
	}
}
