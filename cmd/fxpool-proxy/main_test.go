package main

import (
	"os"
	"path/filepath"
	"testing"
)

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
