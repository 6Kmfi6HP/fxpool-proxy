package token

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"fxpool-proxy/internal/securefile"
)

type RefreshState struct {
	Schema              int      `json:"schema"`
	Result              string   `json:"result"`
	LastAttemptAt       *float64 `json:"last_attempt_at"`
	LastSuccessAt       *float64 `json:"last_success_at"`
	ProxyPassExpiresAt  *float64 `json:"proxy_pass_expires_at"`
	NextAttemptAt       *float64 `json:"next_attempt_at"`
	ConsecutiveFailures int      `json:"consecutive_failures"`
	HTTPStatus          *int     `json:"http_status"`
	Generation          int      `json:"generation"`
}

func EmptyState() RefreshState { return RefreshState{Schema: 1, Result: "never"} }
func LoadState(path string) RefreshState {
	b, err := securefile.ReadRegular(path, 64<<10, false)
	if err != nil {
		return EmptyState()
	}
	var s RefreshState
	if json.Unmarshal(b, &s) != nil || s.Schema != 1 || !validResult(s.Result) {
		return EmptyState()
	}
	return s
}
func validResult(s string) bool {
	switch s {
	case "never", "credentials_imported", "in_progress", "fresh", "success", "busy", "backoff", "rate_limited", "oauth_rate_limited", "reauth_required", "no_entitlement", "missing_credentials", "transient_error", "protocol_error":
		return true
	}
	return false
}
func failure(s string) bool {
	switch s {
	case "rate_limited", "oauth_rate_limited", "reauth_required", "no_entitlement", "missing_credentials", "transient_error", "protocol_error":
		return true
	}
	return false
}
func RecordState(path, result string, now time.Time, status *int, next, expiry *time.Time) (RefreshState, error) {
	if !validResult(result) {
		return RefreshState{}, os.ErrInvalid
	}
	s := LoadState(path)
	n := float64(now.Unix())
	s.Result = result
	if result != "never" {
		s.LastAttemptAt = &n
	}
	s.HTTPStatus = status
	if next != nil {
		v := float64(next.Unix())
		s.NextAttemptAt = &v
	} else {
		s.NextAttemptAt = nil
	}
	if expiry != nil {
		v := float64(expiry.Unix())
		s.ProxyPassExpiresAt = &v
	}
	if result == "success" {
		s.LastSuccessAt = &n
		s.ConsecutiveFailures = 0
		s.Generation++
	} else if result == "fresh" || result == "credentials_imported" {
		s.ConsecutiveFailures = 0
	} else if failure(result) {
		s.ConsecutiveFailures++
	}
	err := securefile.AtomicJSON(path, s, 0o600)
	return s, err
}
func Backoff(failures int) time.Duration {
	if failures < 0 {
		failures = 0
	}
	if failures > 6 {
		failures = 6
	}
	d := 5 * time.Second * time.Duration(1<<failures)
	if d > 5*time.Minute {
		return 5 * time.Minute
	}
	return d
}
func EnsureDirs(root string) error {
	for _, d := range []string{"tokens", "data", "export", "logs"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			return err
		}
	}
	return nil
}
