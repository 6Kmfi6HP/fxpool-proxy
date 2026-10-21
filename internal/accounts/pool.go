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
	// Try each account in round-robin order.
	errs := make([]string, 0, n)
	for tried := 0; tried < n; tried++ {
		p.mu.Lock()
		idx := p.rrIndex % n
		e := p.managers[idx]
		if !force {
			p.rrIndex = (p.rrIndex + 1) % n
		}
		p.mu.Unlock()

		tok, err := e.mgr.Ensure(ctx, force)
		if err == nil {
			return tok, nil
		}
		errs = append(errs, fmt.Sprintf("account %s: %v", e.uid, err))
		// On force, don't cycle; the caller already targeted a specific account.
		if force {
			break
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
