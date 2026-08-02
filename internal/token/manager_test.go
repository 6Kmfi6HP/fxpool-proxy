package token

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"fxpool-proxy/internal/fxa"
)

func TestHKDFMatchesPyFxA082(t *testing.T) {
	got := hex.EncodeToString(hkdf(make([]byte, 32), "sessionToken", 96))
	want := "cb339b3ae38e8ca7ce73414765fcf866ec6fd00faa48932575b407d1836c6e0106b3bea873cc43aac3506d36baf945399d76539493a48607047f8d210e4aae4029340093ac49debdc559ecaf404674529be06b5106294023aedc1b2362aeb4a6"
	if got != want {
		t.Fatalf("HKDF mismatch\n%s", got)
	}
}

func TestManagerLogin(t *testing.T) {
	// A fake FxA auth server that accepts the v1 vector credentials.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/account/credentials/status":
			w.Write([]byte(`{"email":"andré@example.org","verifierVersion":1}`))
		case "/account/login":
			var body struct {
				AuthPW string `json:"authPW"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			// v1 vector authPW for andré@example.org / pässwörd.
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
	m := NewManager(root, "https://vpn.mozilla.org")
	m.FxAAuth = srv.URL
	m.Client = srv.Client()

	s, err := m.Login(context.Background(), "andré@example.org", "pässwörd",
		func(fc *fxa.Client) { fc.Base = srv.URL })
	if err != nil {
		t.Fatal(err)
	}
	if s.UID != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("uid mismatch: %s", s.UID)
	}

	// The renewal credentials file must exist with 0600 permissions.
	credPath := filepath.Join(root, "tokens", "renewal_credentials.json")
	b, err := os.ReadFile(credPath)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(credPath)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600, got %o", st.Mode().Perm())
	}
	var cred Credentials
	if err := json.Unmarshal(b, &cred); err != nil {
		t.Fatal(err)
	}
	if cred.Email != "andré@example.org" || cred.SessionToken != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("credential mismatch: %+v", cred)
	}
}
