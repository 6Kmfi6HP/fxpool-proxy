package fxaexport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSignedInUser(t *testing.T) {
	raw := []byte(`{
  "version": 1,
  "accountData": {
    "email": "user@example.invalid",
    "uid": "00112233445566778899AABBCCDDEEFF",
    "sessionToken": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    "verified": true,
    "device": {"id": "aabbccddeeff00112233445566778899"}
  }
}`)
	b, err := ParseSignedInUser(raw)
	if err != nil {
		t.Fatal(err)
	}
	if b.Schema != BundleSchema || b.Email != "user@example.invalid" {
		t.Fatalf("%+v", b)
	}
	if b.UID != "00112233445566778899aabbccddeeff" {
		t.Fatalf("uid %q", b.UID)
	}
	if b.SessionToken != strings.ToLower("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff") {
		t.Fatalf("token case")
	}
}

func TestParseSignedInUserRejects(t *testing.T) {
	cases := []string{
		`{"version":2,"accountData":{"email":"a@b.c","uid":"00112233445566778899aabbccddeeff","sessionToken":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","verified":true,"device":{"id":"aabbccddeeff00112233445566778899"}}}`,
		`{"version":1,"accountData":{"email":"a@b.c","uid":"00112233445566778899aabbccddeeff","sessionToken":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","verified":false,"device":{"id":"aabbccddeeff00112233445566778899"}}}`,
		`{"version":1,"accountData":{"email":"not-an-email","uid":"00112233445566778899aabbccddeeff","sessionToken":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","verified":true,"device":{"id":"aabbccddeeff00112233445566778899"}}}`,
		`{"version":1,"accountData":{"email":"a@b.c","uid":"00112233445566778899aabbccddeeff","sessionToken":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","verified":true}}`,
	}
	for _, raw := range cases {
		if _, err := ParseSignedInUser([]byte(raw)); err == nil {
			t.Fatalf("expected error for %s", raw[:40])
		}
	}
}

func TestListProfilesAndSelect(t *testing.T) {
	root := t.TempDir()
	prof := filepath.Join(root, "Profiles", "abcd1234.default-release")
	if err := os.MkdirAll(prof, 0o700); err != nil {
		t.Fatal(err)
	}
	ini := `[Profile0]
Name=default-release
IsRelative=1
Path=Profiles/abcd1234.default-release
Default=1

[General]
StartWithLastProfile=1
Version=2
`
	if err := os.WriteFile(filepath.Join(root, "profiles.ini"), []byte(ini), 0o644); err != nil {
		t.Fatal(err)
	}
	signed := `{
  "version": 1,
  "accountData": {
    "email": "user@example.invalid",
    "uid": "00112233445566778899aabbccddeeff",
    "sessionToken": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    "verified": true,
    "device": {"id": "aabbccddeeff00112233445566778899"}
  }
}`
	if err := os.WriteFile(filepath.Join(prof, "signedInUser.json"), []byte(signed), 0o644); err != nil {
		t.Fatal(err)
	}
	profiles, err := ListProfiles(root)
	if err != nil || len(profiles) != 1 || !profiles[0].IsDefault {
		t.Fatalf("profiles=%v err=%v", profiles, err)
	}
	c := InspectProfile(profiles[0])
	if c.Error != nil || c.Bundle == nil {
		t.Fatalf("%+v", c)
	}
	got, err := Select([]Candidate{c}, "")
	if err != nil || got.Bundle.Email != "user@example.invalid" {
		t.Fatalf("select: %+v %v", got, err)
	}
	got, err = Select([]Candidate{c}, "default-release")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Select([]Candidate{c}, "missing"); err == nil {
		t.Fatal("expected miss")
	}
}

func TestSelectAmbiguous(t *testing.T) {
	mk := func(name string) Candidate {
		return Candidate{
			Profile: Profile{Name: name, Path: "/tmp/" + name},
			Bundle:  &Bundle{Schema: BundleSchema, Email: name + "@ex.invalid", UID: "00112233445566778899aabbccddeeff", SessionToken: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"},
		}
	}
	_, err := Select([]Candidate{mk("a"), mk("b")}, "")
	if err == nil || !strings.Contains(err.Error(), "--profile") {
		t.Fatalf("err=%v", err)
	}
	def := mk("def")
	def.Profile.IsDefault = true
	got, err := Select([]Candidate{mk("a"), def}, "")
	if err != nil || got.Profile.Name != "def" {
		t.Fatalf("%+v %v", got, err)
	}
}
