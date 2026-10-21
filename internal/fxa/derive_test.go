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

// Live v2 values observed from /account/credentials/status on 2026-10-20. The
// clientSalt already carries the quickStretchV2 namespace prefix.
const (
	liveV2Salt   = "identity.mozilla.com/picl/v1/quickStretchV2:011b427efba7a4928d8fb541d58439f3"
	liveV2AuthPW = "a95438248feae90229990fe8c5b2fbd4cd3971eef3c1ab8b8db0eb6728e20bcd"

	// doublePrefixedV2Salt is what a second application of the namespace would
	// produce; its authPW must never be sent for the live account.
	doublePrefixedV2Salt = "identity.mozilla.com/picl/v1/quickStretchV2:identity.mozilla.com/picl/v1/quickStretchV2:011b427efba7a4928d8fb541d58439f3"
	doublePrefixedAuthPW = "2d71b9f8abc3527f4df1fa9b201630b752ef55edebe2f8f7aa1840cf0812b897"
)

func TestDeriveAuthPWLiveV2SaltVerbatim(t *testing.T) {
	// The server-provided salt must be used exactly as returned, not re-prefixed.
	salt := quickStretchSalt(2, liveV2Salt)
	if salt != liveV2Salt {
		t.Fatalf("live v2 salt was modified\n got: %s\nwant: %s", salt, liveV2Salt)
	}
	got, err := DeriveAuthPW("pässwörd", salt, 2)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != liveV2AuthPW {
		t.Fatalf("live v2 authPW mismatch\n got: %s\nwant: %s", hex.EncodeToString(got), liveV2AuthPW)
	}
}

func TestDeriveAuthPWDoublePrefixAntiVector(t *testing.T) {
	// Regression guard: a double-prefixed salt derives a different authPW. The
	// status resolver must never hand this salt to the derivation.
	got, err := DeriveAuthPW("pässwörd", doublePrefixedV2Salt, 2)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != doublePrefixedAuthPW {
		t.Fatalf("double-prefix anti-vector mismatch\n got: %s\nwant: %s", hex.EncodeToString(got), doublePrefixedAuthPW)
	}
	if liveV2AuthPW == doublePrefixedAuthPW {
		t.Fatal("test vectors are not distinct; the regression guard is meaningless")
	}
}
