package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestVersion(t *testing.T) {
	want := "v9.8.7-test"
	oldVersion := version
	oldStdout := os.Stdout
	version = want
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	t.Cleanup(func() {
		version = oldVersion
		os.Stdout = oldStdout
	})

	if got := run([]string{"version"}); got != 0 {
		t.Fatalf("exit %d", got)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := out.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != want+"\n" {
		t.Fatalf("version output %q, want %q", got, want+"\n")
	}
}

func TestRunValidationBeforeIO(t *testing.T) {
	for _, args := range [][]string{{"run", "--limit=-1"}, {"run", "--no-socks", "--no-http"}, {"run", "--countries=US", "--recommended"}, {"run", "--bind=0.0.0.0"}} {
		if got := run(args); got != 2 {
			t.Fatalf("%v returned %d", args, got)
		}
	}
}
func TestCredentialImportNoVerify(t *testing.T) {
	root := t.TempDir()
	bundle := filepath.Join(root, "bundle.json")
	raw := []byte(`{"schema":"firefox-ip-protection-renewal-credentials-v1","email":"x@example.invalid","uid":"00112233445566778899aabbccddeeff","session_token":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}`)
	if e := os.WriteFile(bundle, raw, 0o600); e != nil {
		t.Fatal(e)
	}
	if got := run([]string{"import-credentials", bundle, "--no-verify", "--root", root}); got != 0 {
		t.Fatalf("exit %d", got)
	}
	info, e := os.Stat(filepath.Join(root, "tokens", "renewal_credentials.json"))
	if e != nil {
		t.Fatal(e)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
}

func TestLoginCommandPublishNoVerify(t *testing.T) {
	// A fake FxA auth server accepting the v1 vector.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/account/credentials/status":
			w.Write([]byte(`{"email":"andré@example.org","verifierVersion":1}`))
		case "/account/login":
			var body struct {
				AuthPW string `json:"authPW"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.AuthPW != "247b675ffb4c46310bc87e26d712153abe5e1c90ef00a4784594f97ef54f2375" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"code":400,"errno":103,"error":"Incorrect password"}`))
				return
			}
			w.Write([]byte(`{"uid":"0123456789abcdef0123456789abcdef","sessionToken":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","verified":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	root := t.TempDir()
	// Feed just the password over stdin (non-terminal read path); email via flag.
	stdin := "pässwörd\n"
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	_, _ = w.WriteString(stdin)
	_ = w.Close()
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = oldStdin })

	if got := run([]string{"login", "--email", "andré@example.org", "--root", root, "--fxa-base", srv.URL, "--no-verify"}); got != 0 {
		t.Fatalf("exit %d", got)
	}
	b, e := os.ReadFile(filepath.Join(root, "tokens", "renewal_credentials.json"))
	if e != nil {
		t.Fatal(e)
	}
	var cred struct {
		Email        string `json:"email"`
		SessionToken string `json:"session_token"`
	}
	if e := json.Unmarshal(b, &cred); e != nil {
		t.Fatal(e)
	}
	if cred.Email != "andré@example.org" || cred.SessionToken != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("credential mismatch: %+v", cred)
	}
	info, e := os.Stat(filepath.Join(root, "tokens", "renewal_credentials.json"))
	if e != nil {
		t.Fatal(e)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
}

func TestExportCredentialsFromFirefoxDir(t *testing.T) {
	fx := t.TempDir()
	prof := filepath.Join(fx, "Profiles", "abcd1234.default-release")
	if e := os.MkdirAll(prof, 0o700); e != nil {
		t.Fatal(e)
	}
	ini := "[Profile0]\nName=default-release\nIsRelative=1\nPath=Profiles/abcd1234.default-release\nDefault=1\n"
	if e := os.WriteFile(filepath.Join(fx, "profiles.ini"), []byte(ini), 0o644); e != nil {
		t.Fatal(e)
	}
	signed := `{"version":1,"accountData":{"email":"user@example.invalid","uid":"00112233445566778899aabbccddeeff","sessionToken":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","verified":true,"device":{"id":"aabbccddeeff00112233445566778899"}}}`
	if e := os.WriteFile(filepath.Join(prof, "signedInUser.json"), []byte(signed), 0o644); e != nil {
		t.Fatal(e)
	}
	out := filepath.Join(t.TempDir(), "out.json")
	if got := run([]string{"export-credentials", "--firefox-dir", fx, "-o", out}); got != 0 {
		t.Fatalf("exit %d", got)
	}
	info, e := os.Stat(out)
	if e != nil {
		t.Fatal(e)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	root := t.TempDir()
	if got := run([]string{"export-credentials", "--firefox-dir", fx, "--import", "--no-verify", "--root", root, "-o", filepath.Join(root, "bundle.json")}); got != 0 {
		t.Fatalf("import exit %d", got)
	}
	if _, e := os.Stat(filepath.Join(root, "tokens", "renewal_credentials.json")); e != nil {
		t.Fatal(e)
	}
}

// TestCredentialImportStdinFlagOrdering is a regression test for the documented
// `import-credentials - --root DIR --no-verify` invocation. A bare "-" is a
// non-flag argument, so a single flag.FlagSet.Parse would stop there and leave
// every following flag unparsed.
func TestCredentialImportStdinFlagOrdering(t *testing.T) {
	raw := `{"schema":"firefox-ip-protection-renewal-credentials-v1","email":"x@example.invalid","uid":"00112233445566778899aabbccddeeff","session_token":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}`
	for _, tc := range []struct {
		name string
		args func(root string) []string
	}{
		{
			name: "bundle first",
			args: func(root string) []string {
				return []string{"import-credentials", "-", "--no-verify", "--root", root}
			},
		},
		{
			name: "bundle between flags",
			args: func(root string) []string {
				return []string{"import-credentials", "--no-verify", "-", "--root", root}
			},
		},
		{
			name: "bundle last",
			args: func(root string) []string {
				return []string{"import-credentials", "--root", root, "--no-verify", "-"}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			oldStdin := os.Stdin
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.WriteString(raw); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			os.Stdin = r
			t.Cleanup(func() {
				os.Stdin = oldStdin
				_ = r.Close()
			})

			if got := run(tc.args(root)); got != 0 {
				t.Fatalf("exit %d", got)
			}
			info, err := os.Stat(filepath.Join(root, "tokens", "renewal_credentials.json"))
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("mode %o", info.Mode().Perm())
			}
		})
	}
}
