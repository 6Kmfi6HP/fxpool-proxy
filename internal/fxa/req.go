package fxa

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Client is a minimal Firefox Accounts auth-server client.
type Client struct {
	// Base is the FxA auth-server base URL, e.g. https://api.accounts.firefox.com/v1.
	Base string
	// HTTP is the underlying HTTP client (timeout 15s recommended).
	HTTP *http.Client
	// TOTPPrompt, when set, is called to collect a one-time code when the
	// account requires 2FA. When nil, a TOTP requirement is an error.
	TOTPPrompt func() (string, error)
	// UserAgent is sent on every request.
	UserAgent string
}

// DefaultBase is the production FxA auth-server base URL.
const DefaultBase = "https://api.accounts.firefox.com/v1"

func (c *Client) base() string {
	if c.Base == "" {
		return DefaultBase
	}
	return strings.TrimRight(c.Base, "/")
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// errnoError is a non-2xx FxA response carrying the server errno.
type errnoError struct {
	status int
	errno  int
	msg    string
	retry  time.Duration
	body   []byte // raw response body for extracting fields (e.g. canonical email)
}

func (e *errnoError) Error() string { return e.msg }

// canonicalEmail returns the corrected email the server suggests on an
// email-case mismatch (errno 120), or "" if absent.
func (e *errnoError) canonicalEmail() string {
	var v struct {
		Email string `json:"email"`
	}
	if e.body != nil && json.Unmarshal(e.body, &v) == nil {
		return v.Email
	}
	return ""
}

// postJSON sends a JSON body to Base+path and decodes the response into out
// (if non-nil). Non-2xx responses are wrapped in *errnoError with the server
// errno and any Retry-After.
func (c *Client) postJSON(ctx context.Context, path string, body, out any) error {
	var raw []byte
	var err error
	if body != nil {
		raw, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	u := c.base() + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	ua := c.UserAgent
	if ua == "" {
		ua = "firefox-ip-protection-pool/3.0"
	}
	req.Header.Set("User-Agent", ua)
	resp, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return newErrnoError(resp.StatusCode, resp.Header.Get("Retry-After"), b)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("invalid JSON from FxA: %w", err)
	}
	return nil
}

func newErrnoError(status int, retryAfter string, body []byte) error {
	msg := fmt.Sprintf("FxA HTTP %d", status)
	var v struct {
		Code  int    `json:"code"`
		Errno int    `json:"errno"`
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &v) == nil && v.Errno != 0 {
		msg = fmt.Sprintf("FxA HTTP %d errno %d: %s", status, v.Errno, v.Error)
	}
	return &errnoError{status: status, errno: v.Errno, msg: msg, retry: retryAfterDuration(retryAfter), body: append([]byte(nil), body...)}
}

// errnoOf returns the FxA errno from an error, or 0 when not an FxA error.
func errnoOf(err error) int {
	var e *errnoError
	if errors.As(err, &e) {
		return e.errno
	}
	return 0
}

func retryAfterDuration(v string) time.Duration {
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	if at, err := http.ParseTime(v); err == nil && at.After(time.Now()) {
		return time.Until(at)
	}
	return 0
}
