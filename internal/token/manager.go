package token

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"fxpool-proxy/internal/securefile"
)

const ClientID = "5882386c6d801776"
const Scopes = "profile https://identity.mozilla.com/apps/vpn"

type Credentials struct {
	Schema       int    `json:"schema"`
	Email        string `json:"email"`
	UID          string `json:"uid"`
	SessionToken string `json:"session_token"`
}
type Manager struct {
	Root, Guardian, FxAAuth, FxAOAuth string
	Client                            *http.Client
	ExplicitProxyPass, AccessToken    string
	mu                                sync.Mutex
	refreshing                        bool
}
type Usage struct {
	Unlimited  *bool  `json:"unlimited"`
	Limit      *int   `json:"limit"`
	Remaining  *int   `json:"remaining"`
	Reset      string `json:"reset,omitempty"`
	RetryAfter int    `json:"retry_after,omitempty"`
}

func (m *Manager) Usage(ctx context.Context) (Usage, error) {
	access := m.AccessToken
	if access == "" {
		c, e := m.LoadCredentials()
		if e != nil {
			return Usage{}, e
		}
		access, e = m.authorize(ctx, c.SessionToken)
		if e != nil {
			return Usage{}, e
		}
		defer m.destroy(context.WithoutCancel(ctx), access)
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodHead, m.Guardian+"/api/v1/fpn/token", nil)
	if e != nil {
		return Usage{}, e
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	resp, e := m.Client.Do(req)
	if e != nil {
		return Usage{}, e
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Usage{}, &httpError{status: resp.StatusCode, msg: fmt.Sprintf("Guardian HTTP %d", resp.StatusCode)}
	}
	u := Usage{}
	if v := resp.Header.Get("X-Quota-Unlimited"); v != "" {
		b, e := strconv.ParseBool(v)
		if e != nil {
			return u, errors.New("invalid Guardian quota header")
		}
		u.Unlimited = &b
		if b {
			return u, nil
		}
	}
	limit, e := strconv.Atoi(resp.Header.Get("X-Quota-Limit"))
	if e != nil || limit < 0 {
		return u, errors.New("missing Guardian quota limit")
	}
	remaining, e := strconv.Atoi(resp.Header.Get("X-Quota-Remaining"))
	if e != nil || remaining < 0 || remaining > limit {
		return u, errors.New("invalid Guardian quota remaining")
	}
	if resp.Header.Get("X-Quota-Reset") == "" {
		return u, errors.New("missing Guardian quota reset")
	}
	u.Limit = &limit
	u.Remaining = &remaining
	u.Reset = resp.Header.Get("X-Quota-Reset")
	return u, nil
}

func NewManager(root, guardian string) *Manager {
	if guardian == "" {
		guardian = "https://vpn.mozilla.org"
	}
	return &Manager{Root: root, Guardian: strings.TrimRight(guardian, "/"), FxAAuth: "https://api.accounts.firefox.com/v1", FxAOAuth: "https://oauth.accounts.firefox.com/v1", Client: &http.Client{Timeout: 15 * time.Second}}
}
func (m *Manager) tokenPath() string { return filepath.Join(m.Root, "tokens", "proxy_pass.jwt") }
func (m *Manager) statePath() string { return filepath.Join(m.Root, "tokens", "refresh_state.json") }
func (m *Manager) LoadCredentials() (Credentials, error) {
	path := filepath.Join(m.Root, "tokens", "renewal_credentials.json")
	b, e := securefile.ReadRegular(path, 16<<10, true)
	if e != nil {
		return Credentials{}, e
	}
	var c Credentials
	if json.Unmarshal(b, &c) != nil || c.Schema != 1 || !strings.Contains(c.Email, "@") || len(c.UID) != 32 || len(c.SessionToken) != 64 {
		return Credentials{}, errors.New("unsupported or invalid renewal credentials")
	}
	if _, e = hex.DecodeString(c.UID); e != nil {
		return Credentials{}, errors.New("invalid uid")
	}
	if _, e = hex.DecodeString(c.SessionToken); e != nil {
		return Credentials{}, errors.New("invalid session token")
	}
	c.UID = strings.ToLower(c.UID)
	c.SessionToken = strings.ToLower(c.SessionToken)
	return c, nil
}
func (m *Manager) Current(minTTL time.Duration) (string, error) {
	state := LoadState(m.statePath())
	switch state.Result {
	case "credentials_imported", "rate_limited", "reauth_required", "no_entitlement":
		return "", fmt.Errorf("new tunnels blocked by refresh state %s", state.Result)
	}
	b, e := securefile.ReadRegular(m.tokenPath(), 64<<10, true)
	if e != nil {
		if m.ExplicitProxyPass == "" {
			return "", e
		}
		b = []byte(m.ExplicitProxyPass)
	}
	raw := strings.TrimSpace(string(b))
	if _, e = DecodeAndValidateJWT(raw, m.Guardian, time.Now(), minTTL); e != nil {
		return "", e
	}
	dig := sha256.Sum256([]byte(raw))
	if rejected, _ := securefile.ReadRegular(filepath.Join(m.Root, "tokens", "rejected_proxy_pass.sha256"), 4096, false); bytes.Contains(rejected, []byte(hex.EncodeToString(dig[:]))) {
		return "", errors.New("ProxyPass was rejected")
	}
	return raw, nil
}
func (m *Manager) Ensure(ctx context.Context, force bool) (string, error) {
	if !force {
		if t, e := m.Current(120 * time.Second); e == nil {
			return t, nil
		}
	}
	return m.Refresh(ctx, force)
}
func (m *Manager) Refresh(ctx context.Context, force bool) (string, error) {
	m.mu.Lock()
	if m.refreshing {
		m.mu.Unlock()
		return "", errors.New("refresh already in progress")
	}
	m.refreshing = true
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.refreshing = false; m.mu.Unlock() }()
	lock, e := m.lock(false)
	if e != nil {
		return "", e
	}
	defer unlock(lock)
	state := LoadState(m.statePath())
	now := time.Now()
	if state.NextAttemptAt != nil && *state.NextAttemptAt > float64(now.Unix()) {
		return "", errors.New("refresh deferred by persisted cooldown")
	}
	if !force {
		if t, e := m.Current(120 * time.Second); e == nil {
			_, _ = RecordState(m.statePath(), "fresh", now, nil, nil, nil)
			return t, nil
		}
	}
	_, _ = RecordState(m.statePath(), "in_progress", now, nil, nil, nil)
	access := m.AccessToken
	if access == "" {
		c, e := m.LoadCredentials()
		if e != nil {
			return "", m.fail("missing_credentials", nil, e)
		}
		access, e = m.authorize(ctx, c.SessionToken)
		if e != nil {
			return "", m.fail(classify(e), httpStatus(e), e)
		}
		defer m.destroy(context.WithoutCancel(ctx), access)
	}
	token, e := m.guardianToken(ctx, access)
	if e != nil {
		return "", m.fail(classify(e), httpStatus(e), e)
	}
	claims, e := DecodeAndValidateJWT(token, m.Guardian, time.Now(), 120*time.Second)
	if e != nil {
		return "", m.fail("protocol_error", nil, e)
	}
	if e = securefile.AtomicWrite(m.tokenPath(), []byte(token+"\n"), 0o600); e != nil {
		return "", m.fail("transient_error", nil, e)
	}
	expiry := time.Unix(int64(claims.Expires), 0)
	status := 200
	_, e = RecordState(m.statePath(), "success", time.Now(), &status, nil, &expiry)
	return token, e
}
func (m *Manager) fail(result string, status *int, cause error) error {
	s := LoadState(m.statePath())
	delay := Backoff(s.ConsecutiveFailures)
	var he *httpError
	if errors.As(cause, &he) && he.retry > 0 {
		delay = he.retry
	}
	if result == "reauth_required" || result == "no_entitlement" || result == "protocol_error" {
		delay = 5 * time.Minute
	}
	next := time.Now().Add(delay)
	_, _ = RecordState(m.statePath(), result, time.Now(), status, &next, nil)
	return fmt.Errorf("%s: %w", result, cause)
}
func (m *Manager) lock(block bool) (*os.File, error) {
	p := filepath.Join(m.Root, "tokens", ".refresh.lock")
	if e := os.MkdirAll(filepath.Dir(p), 0o700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	if e != nil {
		return nil, e
	}
	if e = lockFile(f, block); e != nil {
		f.Close()
		return nil, errors.New("another refresh is in progress")
	}
	return f, nil
}
func unlock(f *os.File) { _ = unlockFile(f); _ = f.Close() }

type httpError struct {
	status int
	retry  time.Duration
	msg    string
}

func (e *httpError) Error() string { return e.msg }
func httpStatus(e error) *int {
	var h *httpError
	if errors.As(e, &h) {
		return &h.status
	}
	return nil
}
func classify(e error) string {
	var h *httpError
	if errors.As(e, &h) {
		if h.status == 429 {
			return "rate_limited"
		}
		if h.status == 401 {
			return "reauth_required"
		}
		if h.status == 403 {
			return "no_entitlement"
		}
		if h.status >= 500 {
			return "transient_error"
		}
		return "protocol_error"
	}
	return "transient_error"
}

func hkdf(secret []byte, info string, n int) []byte {
	extract := hmac.New(sha256.New, []byte{})
	extract.Write(secret)
	prk := extract.Sum(nil)
	var out, prev []byte
	for i := byte(1); len(out) < n; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(prev)
		h.Write([]byte("identity.mozilla.com/picl/v1/" + info))
		h.Write([]byte{i})
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}
func randomURL(n int) (string, error) {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func hawkHeader(method string, u *url.URL, body []byte, session string) (string, error) {
	secret, e := hex.DecodeString(session)
	if e != nil {
		return "", e
	}
	km := hkdf(secret, "sessionToken", 96)
	id := hex.EncodeToString(km[:32])
	key := km[32:64]
	nonce, e := randomURL(6)
	if e != nil {
		return "", e
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	payloadHash := ""
	if len(body) > 0 {
		h := sha256.Sum256(append(append([]byte("hawk.1.payload\napplication/json\n"), body...), '\n'))
		payloadHash = base64.StdEncoding.EncodeToString(h[:])
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	normalized := strings.Join([]string{"hawk.1.header", ts, nonce, method, u.RequestURI(), u.Hostname(), port, payloadHash, "", "", ""}, "\n") + "\n"
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(normalized))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	h := fmt.Sprintf(`Hawk id="%s", ts="%s", nonce="%s"`, id, ts, nonce)
	if payloadHash != "" {
		h += fmt.Sprintf(`, hash="%s"`, payloadHash)
	}
	return h + fmt.Sprintf(`, mac="%s"`, signature), nil
}
func (m *Manager) jsonRequest(ctx context.Context, method, endpoint string, body any, auth string) (map[string]any, error) {
	var raw []byte
	var e error
	if body != nil {
		raw, e = json.Marshal(body)
		if e != nil {
			return nil, e
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(raw))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "firefox-ip-protection-pool/3.0")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, e := m.Client.Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if e != nil {
		return nil, e
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &httpError{resp.StatusCode, retryAfter(resp.Header.Get("Retry-After")), fmt.Sprintf("upstream HTTP %d", resp.StatusCode)}
	}
	var v map[string]any
	if json.Unmarshal(b, &v) != nil {
		return nil, errors.New("upstream returned invalid JSON")
	}
	return v, nil
}
func retryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if n, e := strconv.Atoi(strings.TrimSpace(v)); e == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	if at, e := http.ParseTime(v); e == nil && at.After(time.Now()) {
		return time.Until(at)
	}
	return 0
}

func (m *Manager) PublishCredentials(c Credentials) error {
	if _, e := hex.DecodeString(c.UID); e != nil || len(c.UID) != 32 {
		return errors.New("invalid uid")
	}
	if _, e := hex.DecodeString(c.SessionToken); e != nil || len(c.SessionToken) != 64 {
		return errors.New("invalid session token")
	}
	if !strings.Contains(c.Email, "@") {
		return errors.New("invalid email")
	}
	lock, e := m.lock(true)
	if e != nil {
		return e
	}
	defer unlock(lock)
	c.Schema = 1
	c.UID = strings.ToLower(c.UID)
	c.SessionToken = strings.ToLower(c.SessionToken)
	if e = securefile.AtomicJSON(filepath.Join(m.Root, "tokens", "renewal_credentials.json"), c, 0o600); e != nil {
		return e
	}
	if _, e = RecordState(m.statePath(), "credentials_imported", time.Now(), nil, nil, nil); e != nil {
		return e
	}
	for _, name := range []string{"session_token.txt", "account_meta.json", "rejected_proxy_pass.sha256"} {
		if e = os.Remove(filepath.Join(m.Root, "tokens", name)); e != nil && !errors.Is(e, os.ErrNotExist) {
			return errors.New("could not remove legacy credential file")
		}
	}
	return nil
}
func (m *Manager) authorize(ctx context.Context, session string) (string, error) {
	verifier, e := randomURL(32)
	if e != nil {
		return "", e
	}
	challengeBytes := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes[:])
	state, e := randomURL(24)
	if e != nil {
		return "", e
	}
	endpoint := strings.TrimRight(m.FxAAuth, "/") + "/oauth/authorization"
	u, _ := url.Parse(endpoint)
	body := map[string]any{"client_id": ClientID, "state": state, "scope": Scopes, "code_challenge": challenge, "code_challenge_method": "S256"}
	raw, _ := json.Marshal(body)
	hawk, e := hawkHeader("POST", u, raw, session)
	if e != nil {
		return "", e
	}
	v, e := m.jsonRequest(ctx, "POST", endpoint, body, hawk)
	if e != nil {
		return "", e
	}
	redirect, ok := v["redirect"].(string)
	if !ok {
		return "", errors.New("redirect missing in OAuth response")
	}
	ru, e := url.Parse(redirect)
	if e != nil {
		return "", e
	}
	if ru.Query().Get("state") != state || ru.Query().Get("code") == "" {
		return "", errors.New("invalid OAuth redirect")
	}
	v, e = m.jsonRequest(ctx, "POST", strings.TrimRight(m.FxAOAuth, "/")+"/token", map[string]any{"code": ru.Query().Get("code"), "client_id": ClientID, "code_verifier": verifier}, "")
	if e != nil {
		return "", e
	}
	access, ok := v["access_token"].(string)
	if !ok || access == "" {
		return "", errors.New("access_token missing in OAuth response")
	}
	return access, nil
}
func (m *Manager) guardianToken(ctx context.Context, access string) (string, error) {
	v, e := m.jsonRequest(ctx, "GET", m.Guardian+"/api/v1/fpn/token", nil, "Bearer "+access)
	if e != nil {
		return "", e
	}
	t, ok := v["token"].(string)
	if !ok || t == "" {
		return "", errors.New("token missing in Guardian response")
	}
	return t, nil
}
func (m *Manager) destroy(ctx context.Context, access string) {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, _ = m.jsonRequest(c, "POST", strings.TrimRight(m.FxAOAuth, "/")+"/destroy", map[string]any{"token": access}, "")
}
func (m *Manager) Reject(raw string) error {
	sum := sha256.Sum256([]byte(raw))
	path := filepath.Join(m.Root, "tokens", "rejected_proxy_pass.sha256")
	old, _ := securefile.ReadRegular(path, 4096, false)
	lines := strings.Fields(string(old))
	digest := hex.EncodeToString(sum[:])
	for _, l := range lines {
		if hmac.Equal([]byte(l), []byte(digest)) {
			return nil
		}
	}
	lines = append(lines, digest)
	if len(lines) > 32 {
		lines = lines[len(lines)-32:]
	}
	return securefile.AtomicWrite(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}
