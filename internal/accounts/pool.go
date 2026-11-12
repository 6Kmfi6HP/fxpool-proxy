// Package accounts provides the multi-account pool that selects a token
// source via round-robin and handles per-account authentication failures.
package accounts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"fxpool-proxy/internal/store"
	"fxpool-proxy/internal/token"
	"fxpool-proxy/internal/upstream"
)

// Pool holds N per-account Managers and implements upstream.TokenSource.
// It selects accounts via round-robin and retries with the next account on
// authentication failures.
type Pool struct {
	managers []*entry
	mu       sync.Mutex
	rrIndex  int
	db       *store.DB
	quota    *QuotaPolicy
}

// QuotaPolicy enables opt-in quota-aware account selection. When disabled
// (the default), selection is plain round-robin. Unknown or stale quota
// snapshots always count as eligible so the pool never dead-ends.
type QuotaPolicy struct {
	// MaxAge is how long a quota snapshot is trusted. Older snapshots are
	// treated as unknown.
	MaxAge time.Duration
	// MarginBytes is the minimum remaining bytes required to use an account.
	MarginBytes int64
	// Cooldown is how long a known-exhausted account is skipped when the
	// snapshot has no parseable reset time.
	Cooldown time.Duration
	// Now is a test seam; defaults to time.Now.
	Now func() time.Time
}

// EnableQuotaPolicy turns on quota-aware selection with the given policy.
func (p *Pool) EnableQuotaPolicy(q QuotaPolicy) {
	if q.MaxAge <= 0 {
		q.MaxAge = 15 * time.Minute
	}
	if q.Now == nil {
		q.Now = time.Now
	}
	p.mu.Lock()
	p.quota = &q
	p.mu.Unlock()
}

func (p *Pool) quotaPolicy() *QuotaPolicy {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.quota
}

// quotaEligible reports whether the account may be used under the quota
// policy. Anything unknown, unlimited, or stale is eligible.
func (p *Pool) quotaEligible(ctx context.Context, accountID int64, now time.Time) bool {
	pol := p.quotaPolicy()
	if pol == nil {
		return true
	}
	q, ok, err := p.db.GetQuota(ctx, accountID)
	if err != nil || !ok {
		return true
	}
	if q.Unlimited || q.LimitBytes == nil || q.RemainingBytes == nil {
		return true
	}
	if now.Sub(q.UpdatedAt) > pol.MaxAge {
		return true // stale snapshot: treat as unknown
	}
	if int64(*q.RemainingBytes) > pol.MarginBytes {
		return true
	}
	if t, ok := parseQuotaReset(q.ResetTime); ok {
		return !now.Before(t)
	}
	if pol.Cooldown <= 0 {
		return true
	}
	return !now.Before(q.UpdatedAt.Add(pol.Cooldown))
}

// parseQuotaReset accepts the reset formats Guardian has used: RFC3339, HTTP
// date, and Unix seconds or milliseconds.
func parseQuotaReset(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339, http.TimeFormat} {
		if t, err := time.Parse(layout, v); err == nil {
			return t, true
		}
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n > 1e12 {
			return time.UnixMilli(n), true
		}
		return time.Unix(n, 0), true
	}
	return time.Time{}, false
}

// RefreshQuotas fetches and persists a quota snapshot for every account.
// Errors are ignored: a failed refresh leaves the previous snapshot in place.
func (p *Pool) RefreshQuotas(ctx context.Context) {
	p.mu.Lock()
	mgrs := make([]*token.Manager, len(p.managers))
	for i, e := range p.managers {
		mgrs[i] = e.mgr
	}
	p.mu.Unlock()
	for _, m := range mgrs {
		_, _ = m.Usage(ctx)
	}
}

// Compile-time check that Pool satisfies the TokenSource interface used by
// upstream.Dialer.
var _ upstream.TokenSource = (*Pool)(nil)

type entry struct {
	accountID int64
	uid       string
	mgr       *token.Manager
}

// NewPool creates a Pool from the given database. It loads all enabled accounts
// and wires up per-account Manager instances sharing the same HTTP client and
// Guardian endpoint.
func NewPool(ctx context.Context, db *store.DB, root, guardian, fxaBase string, client *http.Client) (*Pool, error) {
	accounts, err := db.ListAccounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("accounts: list: %w", err)
	}
	p := &Pool{db: db}
	for _, acc := range accounts {
		if !acc.Enabled {
			continue
		}
		mgr := token.NewManager(root, guardian)
		if fxaBase != "" {
			mgr.FxAAuth = strings.TrimRight(fxaBase, "/")
		}
		if client != nil {
			mgr.Client = client
		}
		mgr.Store = &store.ManagerBackend{DB: db}
		mgr.AccountID = acc.ID
		p.managers = append(p.managers, &entry{
			accountID: acc.ID,
			uid:       acc.UID,
			mgr:       mgr,
		})
	}
	return p, nil
}

// Len returns the number of enabled accounts in the pool.
func (p *Pool) Len() int { return len(p.managers) }

// Ensure returns a valid ProxyPass token. It tries accounts in round-robin
// order, refreshing each if needed.
//   - force=false: return a cached valid token from the chosen account if one
//     exists; otherwise try to refresh it before moving to the next account.
//   - force=true: force-refresh the currently selected account.
func (p *Pool) Ensure(ctx context.Context, force bool) (string, error) {
	p.mu.Lock()
	n := len(p.managers)
	p.mu.Unlock()
	if n == 0 {
		return "", errors.New("accounts: no enabled accounts in pool")
	}
	// Try each account in round-robin order.  The cursor advances on every
	// selection including the force (auth-fallback) path, so successful
	// tunnels alternate across accounts per plan §7 acceptance criterion.
	p.mu.Lock()
	start := 0
	if n > 0 {
		start = p.rrIndex % n
	}
	pol := p.quota
	p.mu.Unlock()

	// Split the round-robin order into eligible and ineligible (quota
	// exhausted). Ineligible accounts are only tried when nothing else is
	// available, so the pool falls back to plain round-robin instead of
	// failing outright.
	var eligible, ineligible []*entry
	now := time.Now()
	if pol != nil {
		now = pol.Now()
	}
	for i := 0; i < n; i++ {
		e := p.managers[(start+i)%n]
		if pol == nil || p.quotaEligible(ctx, e.accountID, now) {
			eligible = append(eligible, e)
		} else {
			ineligible = append(ineligible, e)
		}
	}
	errs := make([]string, 0, n)
	var regionErr error
	try := func(order []*entry) (string, bool) {
		for _, e := range order {
			p.mu.Lock()
			p.rrIndex = (p.rrIndex + 1) % n
			p.mu.Unlock()
			tok, err := e.mgr.Ensure(ctx, force)
			if err == nil {
				return tok, true
			}
			// A region block (Guardian HTTP 451) is a property of the network
			// path, not of this credential. Retrying another account would be an
			// implicit relay switch, so stop immediately with the real cause.
			if token.IsUnavailableInRegion(err) {
				regionErr = fmt.Errorf("account %s: %w", e.uid, err)
				return "", false
			}
			errs = append(errs, fmt.Sprintf("account %s: %v", e.uid, err))
		}
		return "", false
	}
	if tok, ok := try(eligible); ok {
		return tok, nil
	}
	if regionErr != nil {
		return "", regionErr
	}
	if len(eligible) == 0 {
		if tok, ok := try(ineligible); ok {
			return tok, nil
		}
		if regionErr != nil {
			return "", regionErr
		}
	}
	return "", fmt.Errorf("accounts: all accounts unavailable: %s", strings.Join(errs, "; "))
}

// Reject marks the raw token as rejected in the owning account's rejected list.
// It looks up the account by the token's SHA-256 digest in the proxy_pass table.
// If the digest is not found in the proxy_pass table the token is no longer the
// current token for any account (it was already superseded by a refresh), so
// there is nothing to reject and the call succeeds silently.  Writing the
// digest to every account's rejected list in that case would incorrectly poison
// accounts that never used the token.
func (p *Pool) Reject(raw string) error {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	digest := hex.EncodeToString(sum[:])
	ctx := context.Background()
	accID, err := p.db.AccountIDForDigest(ctx, digest)
	if err != nil {
		// Token not in proxy_pass: already superseded by a refresh.
		// No action needed; return success rather than polluting all accounts.
		return nil
	}
	// Found the owning account: reject only there.
	p.mu.Lock()
	var mgr *token.Manager
	for _, e := range p.managers {
		if e.accountID == accID {
			mgr = e.mgr
			break
		}
	}
	p.mu.Unlock()
	if mgr == nil {
		return fmt.Errorf("accounts: account %d for token not in pool", accID)
	}
	return mgr.Reject(raw)
}

// RefreshAll calls Ensure(ctx, false) on each account in the pool. Errors are
// collected but not returned; this is intended for the background refresh loop.
func (p *Pool) RefreshAll(ctx context.Context) {
	p.mu.Lock()
	mgrs := make([]*entry, len(p.managers))
	copy(mgrs, p.managers)
	p.mu.Unlock()
	for _, e := range mgrs {
		_, _ = e.mgr.Ensure(ctx, false)
	}
}

// ManagerForUID returns the Manager for the account with the given UID, or nil
// if not found.
func (p *Pool) ManagerForUID(uid string) *token.Manager {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.managers {
		if e.uid == uid {
			return e.mgr
		}
	}
	return nil
}

// StatusForUID returns a snapshot of the token status for one account.
type AccountStatus struct {
	UID              string
	Email            string
	Enabled          bool
	RefreshResult    string
	HasProxyPass     bool
	SecondsLeft      int64
	ConsecutiveFails int
	Generation       int
}

// ListStatuses returns a status snapshot for all accounts in the pool.
func (p *Pool) ListStatuses(ctx context.Context) ([]AccountStatus, error) {
	p.mu.Lock()
	mgrs := make([]*entry, len(p.managers))
	copy(mgrs, p.managers)
	p.mu.Unlock()

	var out []AccountStatus
	for _, e := range mgrs {
		acc, err := p.db.GetAccount(ctx, e.uid)
		if err != nil {
			continue
		}
		rs, _ := p.db.GetRefreshState(ctx, e.accountID)
		st := AccountStatus{
			UID:              e.uid,
			Email:            acc.Email,
			Enabled:          acc.Enabled,
			RefreshResult:    rs.Result,
			ConsecutiveFails: rs.ConsecutiveFailures,
			Generation:       rs.Generation,
		}
		pp, err := p.db.GetProxyPass(ctx, e.accountID)
		if err == nil {
			st.HasProxyPass = true
			st.SecondsLeft = time.Until(pp.ExpiresAt).Milliseconds() / 1000
		}
		out = append(out, st)
	}
	return out, nil
}
