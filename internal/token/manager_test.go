package token

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

func TestClassifyStatuses(t *testing.T) {
	tests := []struct {
		status int
		want   string
	}{
		{http.StatusUnavailableForLegalReasons, "unavailable_in_region"},
		{http.StatusTooManyRequests, "rate_limited"},
		{http.StatusUnauthorized, "reauth_required"},
		{http.StatusForbidden, "no_entitlement"},
		{http.StatusInternalServerError, "transient_error"},
		{http.StatusBadRequest, "protocol_error"},
	}
	for _, tt := range tests {
		if got := classify(&httpError{status: tt.status}); got != tt.want {
			t.Fatalf("classify(%d) = %q, want %q", tt.status, got, tt.want)
		}
	}
}

func TestUnavailableInRegionState(t *testing.T) {
	root := t.TempDir()
	if err := EnsureDirs(root); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "tokens", "refresh_state.json")
	s, err := RecordState(path, "unavailable_in_region", time.Now(), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.ConsecutiveFailures != 1 {
		t.Fatalf("consecutive failures = %d, want 1", s.ConsecutiveFailures)
	}
	loaded := LoadState(path)
	if loaded.Result != "unavailable_in_region" {
		t.Fatalf("result = %q", loaded.Result)
	}
}

func TestRefresh451PersistsRegionState(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusUnavailableForLegalReasons)
	}))
	defer srv.Close()

	m := NewManager(t.TempDir(), srv.URL)
	m.Client = srv.Client()
	m.AccessToken = "access" // skip the FxA authorization leg
	_, err := m.Ensure(context.Background(), false)
	if err == nil {
		t.Fatal("expected an error from HTTP 451")
	}
	if !IsUnavailableInRegion(err) {
		t.Fatalf("error is not a region block: %v", err)
	}
	if !strings.Contains(err.Error(), "unavailable_in_region") {
		t.Fatalf("error lacks the state name: %v", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("Guardian requests = %d, want 1", got)
	}
	if st := m.loadState(); st.Result != "unavailable_in_region" {
		t.Fatalf("persisted result = %q", st.Result)
	}
}

type failTransport struct{ calls atomic.Int64 }

func (f *failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	f.calls.Add(1)
	return nil, errors.New("transport must not be used")
}

func TestLoginUsesFxAClient(t *testing.T) {
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/account/credentials/status":
			w.Write([]byte(`{"verifierVersion":1}`))
		case "/account/login":
			w.Write([]byte(`{"sessionToken":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","uid":"0123456789abcdef0123456789abcdef","verified":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer auth.Close()
	guardian := &failTransport{}
	m := NewManager(t.TempDir(), "https://guardian.invalid")
	m.FxAAuth = auth.URL
	m.FxAClient = auth.Client()
	m.Client = &http.Client{Transport: guardian}
	if _, e := m.Login(context.Background(), "u@example.org", "pw"); e != nil {
		t.Fatalf("Login: %v", e)
	}
	if guardian.calls.Load() != 0 {
		t.Fatalf("Login used the Guardian transport %d times", guardian.calls.Load())
	}
}

func TestGuardianTransportIsolatedFromFxA(t *testing.T) {
	guardian := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	}))
	defer guardian.Close()
	fxaFail := &failTransport{}
	m := NewManager(t.TempDir(), guardian.URL)
	m.FxAAuth = "https://api.accounts.firefox.com/v1"
	m.FxAOAuth = "https://oauth.accounts.firefox.com/v1"
	m.Client = guardian.Client()
	m.FxAClient = &http.Client{Transport: fxaFail}
	if _, _, e := m.jsonRequestWithHeader(context.Background(), http.MethodGet, guardian.URL+"/api/v1/fpn/token", nil, ""); e != nil {
		t.Fatalf("Guardian request: %v", e)
	}
	if fxaFail.calls.Load() != 0 {
		t.Fatalf("Guardian request used the FxA transport %d times", fxaFail.calls.Load())
	}
	if _, _, e := m.jsonRequestWithHeader(context.Background(), http.MethodGet, m.FxAAuth+"/account/credentials/status", nil, ""); e == nil {
		t.Fatal("FxA request unexpectedly succeeded")
	}
	if fxaFail.calls.Load() != 1 {
		t.Fatalf("FxA request used FxA transport %d times, want 1", fxaFail.calls.Load())
	}
}
