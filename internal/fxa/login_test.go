package fxa

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
