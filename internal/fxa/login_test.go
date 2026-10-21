package fxa

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// liveV2StatusBody is the byte-exact /account/credentials/status body observed
// live on 2026-10-20 for a v2 account: no verifierVersion field, and a
// clientSalt that already carries the quickStretchV2 namespace.
const liveV2StatusBody = `{"currentVersion":"v2","clientSalt":"identity.mozilla.com/picl/v1/quickStretchV2:011b427efba7a4928d8fb541d58439f3","upgradeNeeded":false}`

// newTestClient starts an httptest server whose handler routes the FxA
// endpoints the client calls. It returns the client and the handler closure.
func newTestClient(t *testing.T, fn func(w http.ResponseWriter, r *http.Request)) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(fn))
	t.Cleanup(srv.Close)
	return &Client{Base: srv.URL, HTTP: srv.Client()}
}

// testLoginServer serves /account/credentials/status and /account/login with a
// scripted authPW check.
func testLoginServer(t *testing.T, statusResp string, loginAuthPW string, loginResp string) *Client {
	t.Helper()
	return newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/account/credentials/status":
			w.Write([]byte(statusResp))
		case "/account/login":
			var body struct {
				AuthPW string `json:"authPW"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if loginAuthPW != "" && body.AuthPW != loginAuthPW {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"code":400,"errno":103,"error":"Incorrect password"}`))
				return
			}
			w.Write([]byte(loginResp))
		default:
			http.NotFound(w, r)
		}
	})
}

func TestLoginV1Success(t *testing.T) {
	// email "andré@example.org" v1; authPW from the Mozilla vector.
	authPW := "247b675ffb4c46310bc87e26d712153abe5e1c90ef00a4784594f97ef54f2375"
	c := testLoginServer(t,
		`{"email":"andré@example.org","verifierVersion":1}`,
		authPW,
		`{"uid":"0123456789abcdef0123456789abcdef","sessionToken":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","verified":true}`,
	)
	s, err := c.Login(context.Background(), "andré@example.org", "pässwörd")
	if err != nil {
		t.Fatal(err)
	}
	if s.UID != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("uid mismatch: %s", s.UID)
	}
	if s.SessionToken != strings.Repeat("a", 64) {
		t.Fatalf("session token mismatch: %s", s.SessionToken)
	}
}

func TestLoginV2Success(t *testing.T) {
	// v2 uses clientSalt for PBKDF2; authPW from the Mozilla vector.
	authPW := "d278c764bd1852a14bfc4e9d8c1682b4f1a57edb9a9372bf8c370cc41592155b"
	c := testLoginServer(t,
		`{"email":"u@example.org","verifierVersion":2,"clientSalt":"0123456789abcdef0123456789abcdef"}`,
		authPW,
		`{"uid":"0123456789abcdef0123456789abcdef","sessionToken":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","verified":true}`,
	)
	s, err := c.Login(context.Background(), "u@example.org", "pässwörd")
	if err != nil {
		t.Fatal(err)
	}
	if s.SessionToken != strings.Repeat("a", 64) {
		t.Fatalf("session token mismatch: %s", s.SessionToken)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	c := testLoginServer(t,
		`{"email":"u@example.org","verifierVersion":1}`,
		"wrongauthpw",
		``, // never reached
	)
	_, err := c.Login(context.Background(), "u@example.org", "wrongpass")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
	if !strings.Contains(err.Error(), "incorrect") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoginUnknownAccount(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/account/credentials/status":
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"code":400,"errno":102,"error":"Unknown account"}`))
		default:
			http.NotFound(w, r)
		}
	})
	_, err := c.Login(context.Background(), "nobody@example.org", "x")
	if err == nil {
		t.Fatal("expected error for unknown account")
	}
	if !strings.Contains(err.Error(), "no Firefox Account") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoginEmailCaseCorrection(t *testing.T) {
	// First attempt with wrong case → errno 120 with canonical email;
	// second attempt with corrected email succeeds.
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/account/credentials/status":
			w.Write([]byte(`{"email":"U@Example.org","verifierVersion":1}`))
		case "/account/login":
			var body struct {
				Email  string `json:"email"`
				AuthPW string `json:"authPW"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Email == "U@Example.org" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"code":400,"errno":120,"error":"Incorrect email case","email":"u@example.org"}`))
				return
			}
			// Second attempt uses corrected email → success.
			w.Write([]byte(`{"uid":"0123456789abcdef0123456789abcdef","sessionToken":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","verified":true}`))
		default:
			http.NotFound(w, r)
		}
	})
	s, err := c.Login(context.Background(), "U@Example.org", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if s.Email != "u@example.org" {
		t.Fatalf("expected corrected email, got %s", s.Email)
	}
}

func TestLoginTOTPRequired(t *testing.T) {
	promptCalled := false
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/account/credentials/status":
			w.Write([]byte(`{"email":"u@example.org","verifierVersion":1}`))
		case "/account/login":
			w.Write([]byte(`{"uid":"0123456789abcdef0123456789abcdef","sessionToken":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","verified":false,"verificationMethod":"totp-2fa"}`))
		case "/session/verify/totp":
			var body struct {
				Code string `json:"code"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Code != "123456" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"code":400,"errno":106,"error":"Invalid verification code"}`))
				return
			}
			w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	})
	c.TOTPPrompt = func() (string, error) {
		promptCalled = true
		return "123456", nil
	}
	s, err := c.Login(context.Background(), "u@example.org", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if !promptCalled {
		t.Fatal("TOTPPrompt was not called")
	}
	if s.SessionToken != strings.Repeat("a", 64) {
		t.Fatalf("session token mismatch: %s", s.SessionToken)
	}
}

func TestResolveAuthMetaLiveV2(t *testing.T) {
	var resp accountStatusResponse
	if err := json.Unmarshal([]byte(liveV2StatusBody), &resp); err != nil {
		t.Fatal(err)
	}
	meta, err := resolveAuthMeta(resp, "u@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if meta.VerifierVersion != 2 {
		t.Fatalf("verifier version: got %d, want 2", meta.VerifierVersion)
	}
	// The derived salt must equal the server-provided string verbatim.
	if meta.Salt != resp.ClientSalt {
		t.Fatalf("salt was not used verbatim\n got: %s\nwant: %s", meta.Salt, resp.ClientSalt)
	}
	if meta.Salt != liveV2Salt {
		t.Fatalf("salt mismatch\n got: %s\nwant: %s", meta.Salt, liveV2Salt)
	}
	if n := strings.Count(meta.Salt, "quickStretchV2:"); n != 1 {
		t.Fatalf("quickStretchV2 prefix applied %d times, want 1: %s", n, meta.Salt)
	}
}

func TestLoginLiveV2(t *testing.T) {
	// This fails both on the missing-version bug (v1 + email salt is derived)
	// and on the double-prefix bug (a different authPW reaches the server).
	c := testLoginServer(t,
		liveV2StatusBody,
		liveV2AuthPW,
		`{"uid":"0123456789abcdef0123456789abcdef","sessionToken":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","verified":true}`,
	)
	s, err := c.Login(context.Background(), "u@example.org", "pässwörd")
	if err != nil {
		t.Fatal(err)
	}
	if s.UID != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("uid mismatch: %s", s.UID)
	}
	if s.SessionToken != strings.Repeat("a", 64) {
		t.Fatalf("session token mismatch: %s", s.SessionToken)
	}
}

func TestResolveAuthMetaLegacyVerifierVersion(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantVersion int
		wantSalt    string
		wantErr     bool
	}{
		{
			name:        "v2 bare clientSalt is prefixed once",
			body:        `{"verifierVersion":2,"clientSalt":"0123456789abcdef0123456789abcdef"}`,
			wantVersion: 2,
			wantSalt:    "identity.mozilla.com/picl/v1/quickStretchV2:0123456789abcdef0123456789abcdef",
		},
		{
			name:        "v1 uses the email as salt",
			body:        `{"verifierVersion":1}`,
			wantVersion: 1,
			wantSalt:    "identity.mozilla.com/picl/v1/quickStretch:u@example.org",
		},
		{
			name:        "currentVersion v1 uses the email as salt",
			body:        `{"currentVersion":"v1"}`,
			wantVersion: 1,
			wantSalt:    "identity.mozilla.com/picl/v1/quickStretch:u@example.org",
		},
		{
			name:        "missing version falls back to v1",
			body:        `{}`,
			wantVersion: 1,
			wantSalt:    "identity.mozilla.com/picl/v1/quickStretch:u@example.org",
		},
		{
			name:        "explicit verifierVersion wins over currentVersion",
			body:        `{"currentVersion":"v2","verifierVersion":1}`,
			wantVersion: 1,
			wantSalt:    "identity.mozilla.com/picl/v1/quickStretch:u@example.org",
		},
		{
			name:        "currentVersion is case and space insensitive",
			body:        `{"currentVersion":" V2 ","clientSalt":"0123456789abcdef0123456789abcdef"}`,
			wantVersion: 2,
			wantSalt:    "identity.mozilla.com/picl/v1/quickStretchV2:0123456789abcdef0123456789abcdef",
		},
		{
			name:    "unsupported currentVersion is an error",
			body:    `{"currentVersion":"v9"}`,
			wantErr: true,
		},
		{
			name:    "unsupported verifierVersion is an error",
			body:    `{"verifierVersion":3}`,
			wantErr: true,
		},
		{
			name:    "v2 without any salt is an error",
			body:    `{"currentVersion":"v2"}`,
			wantErr: true,
		},
		{
			name:    "v2 with a v1 prefix is an error",
			body:    `{"currentVersion":"v2","clientSalt":"identity.mozilla.com/picl/v1/quickStretch:u@example.org"}`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp accountStatusResponse
			if err := json.Unmarshal([]byte(tt.body), &resp); err != nil {
				t.Fatal(err)
			}
			meta, err := resolveAuthMeta(resp, "u@example.org")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got meta %+v", meta)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if meta.VerifierVersion != tt.wantVersion {
				t.Fatalf("verifier version: got %d, want %d", meta.VerifierVersion, tt.wantVersion)
			}
			if meta.Salt != tt.wantSalt {
				t.Fatalf("salt\n got: %s\nwant: %s", meta.Salt, tt.wantSalt)
			}
		})
	}
}

func TestResolveAuthMetaCurrentClientSalt(t *testing.T) {
	// currentClientSalt wins over clientSalt and is used verbatim.
	body := `{"currentVersion":"v2","clientSalt":"0123456789abcdef0123456789abcdef","currentClientSalt":"` + liveV2Salt + `"}`
	var resp accountStatusResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	meta, err := resolveAuthMeta(resp, "u@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if meta.VerifierVersion != 2 {
		t.Fatalf("verifier version: got %d, want 2", meta.VerifierVersion)
	}
	if meta.Salt != liveV2Salt {
		t.Fatalf("salt\n got: %s\nwant: %s", meta.Salt, liveV2Salt)
	}
}

func TestResolveAuthMetaPrefixedClientSaltNoDoublePrefix(t *testing.T) {
	// Regression: the live server returns clientSalt already namespaced. The
	// resolver must not prepend the namespace a second time.
	for _, body := range []string{
		liveV2StatusBody,
		`{"currentVersion":"v2","clientSalt":"` + liveV2Salt + `"}`,
		`{"currentVersion":"v2","currentClientSalt":"` + liveV2Salt + `"}`,
		`{"verifierVersion":2,"clientSalt":"` + liveV2Salt + `"}`,
	} {
		var resp accountStatusResponse
		if err := json.Unmarshal([]byte(body), &resp); err != nil {
			t.Fatal(err)
		}
		meta, err := resolveAuthMeta(resp, "u@example.org")
		if err != nil {
			t.Fatal(err)
		}
		if meta.Salt != liveV2Salt {
			t.Fatalf("salt not verbatim for %s\n got: %s\nwant: %s", body, meta.Salt, liveV2Salt)
		}
		if meta.Salt == doublePrefixedV2Salt {
			t.Fatalf("salt was double-prefixed for %s: %s", body, meta.Salt)
		}
		got, err := DeriveAuthPW("pässwörd", meta.Salt, meta.VerifierVersion)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != liveV2AuthPW {
			t.Fatalf("authPW for %s\n got: %s\nwant: %s", body, hex.EncodeToString(got), liveV2AuthPW)
		}
	}
}

func TestLoginWAFBlocked(t *testing.T) {
	// The live WAF answers POST /account/login with 406 and an empty body.
	// The status must be distinguishable even though there is no errno.
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/account/credentials/status":
			w.Write([]byte(liveV2StatusBody))
		case "/account/login":
			w.WriteHeader(http.StatusNotAcceptable)
		default:
			http.NotFound(w, r)
		}
	})
	_, err := c.Login(context.Background(), "u@example.org", "pässwörd")
	if err == nil {
		t.Fatal("expected a WAF error")
	}
	if !errors.Is(err, ErrWAFBlocked) {
		t.Fatalf("errors.Is(err, ErrWAFBlocked) = false: %v", err)
	}
	if !strings.Contains(err.Error(), "import-credentials") {
		t.Fatalf("error does not point at import-credentials: %v", err)
	}
}

func TestErrnoErrorAccessors(t *testing.T) {
	waf, ok := newErrnoError(http.StatusNotAcceptable, "", nil).(*errnoError)
	if !ok {
		t.Fatal("newErrnoError did not return *errnoError")
	}
	if waf.Status() != http.StatusNotAcceptable {
		t.Fatalf("Status() = %d, want 406", waf.Status())
	}
	if waf.Errno() != 0 {
		t.Fatalf("Errno() = %d, want 0 for an empty body", waf.Errno())
	}

	incorrect, ok := newErrnoError(http.StatusBadRequest, "",
		[]byte(`{"code":400,"errno":103,"error":"Incorrect password"}`)).(*errnoError)
	if !ok {
		t.Fatal("newErrnoError did not return *errnoError")
	}
	if incorrect.Status() != http.StatusBadRequest {
		t.Fatalf("Status() = %d, want 400", incorrect.Status())
	}
	if incorrect.Errno() != errnoIncorrectPass {
		t.Fatalf("Errno() = %d, want %d", incorrect.Errno(), errnoIncorrectPass)
	}
}
