package fxa

import (
	"encoding/hex"
	"testing"
)

// Test vectors from mozilla/fxa fxa-auth-client test/crypto.ts.
func TestDeriveAuthPWV1(t *testing.T) {
	// email "andré@example.org", password "pässwörd"
	salt := quickStretchSalt(1, "andré@example.org")
	got, err := DeriveAuthPW("pässwörd", salt, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := "247b675ffb4c46310bc87e26d712153abe5e1c90ef00a4784594f97ef54f2375"
	if hex.EncodeToString(got) != want {
		t.Fatalf("v1 authPW mismatch\n got: %s\nwant: %s", hex.EncodeToString(got), want)
	}
}

func TestDeriveAuthPWV2(t *testing.T) {
	// password "pässwörd", clientSalt 0123456789abcdef0123456789abcdef
	salt := quickStretchSalt(2, "0123456789abcdef0123456789abcdef")
	got, err := DeriveAuthPW("pässwörd", salt, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := "d278c764bd1852a14bfc4e9d8c1682b4f1a57edb9a9372bf8c370cc41592155b"
	if hex.EncodeToString(got) != want {
		t.Fatalf("v2 authPW mismatch\n got: %s\nwant: %s", hex.EncodeToString(got), want)
	}
}

func TestDeriveAuthPWInvalidVersion(t *testing.T) {
	if _, err := DeriveAuthPW("pw", quickStretchSalt(3, "x@y.z"), 3); err == nil {
		t.Fatal("expected error for unsupported verifierVersion")
	}
}
