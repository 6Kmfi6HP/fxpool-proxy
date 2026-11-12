package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"fxpool-proxy/internal/accounts"
	"fxpool-proxy/internal/fxa"
	"fxpool-proxy/internal/fxaexport"
	"fxpool-proxy/internal/pool"
	"fxpool-proxy/internal/securefile"
	"fxpool-proxy/internal/serverlist"
	storepkg "fxpool-proxy/internal/store"
	"fxpool-proxy/internal/token"
	"fxpool-proxy/internal/upstream"

	"golang.org/x/term"
)

// version is replaced from the release tag at build time with -ldflags.
var version = "dev"

type config struct {
	root, guardian, serverURL, proxyPass, fxaToken, bind, advertise, rotator, httpRotator, rotateMode, countries, country, authUser, authPass, firefoxVersion, clientCountry, masqueURI string
	fxaBase                                                                                                                                                                             string
	accountMode                                                                                                                                                                         string
	clockURL, probeTarget, probePorts                                                                                                                                                   string
	socksBase, httpBase, udpBase, limit                                                                                                                                                 int
	maxConns, udpMaxTunnelsClient                                                                                                                                                       int
	idleTimeout, udpIdleTimeout, probeTimeout                                                                                                                                           time.Duration
	quotaMaxAge, quotaCooldown, quotaRefreshInterval                                                                                                                                    time.Duration
	quotaMargin                                                                                                                                                                         int64
	forceSync, allowNoToken, noSocks, noHTTP, requireAuth, allowOpen, includeLocked, recommended, quotaAware                                                                            bool
}

type endpoint struct {
	node        serverlist.Node
	socks, http string
}

// env reads FXPOOL_<suffix>, then falls back to deprecated IPP_<suffix>.
func env(suffix, def string) string {
	if v := os.Getenv("FXPOOL_" + suffix); v != "" {
		return v
	}
	if v := os.Getenv("IPP_" + suffix); v != "" {
		return v
	}
	return def
}
func flagsFor(name string) (*flag.FlagSet, *config) {
	c := &config{}
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	wd, _ := os.Getwd()
	f.StringVar(&c.root, "root", wd, "project runtime root")
	f.StringVar(&c.guardian, "guardian", env("GUARDIAN", "https://vpn.mozilla.org"), "Guardian base URL")
	f.StringVar(&c.serverURL, "serverlist-url", serverlist.DefaultURL, "Remote Settings URL")
	f.StringVar(&c.fxaBase, "fxa-base", "", "FxA auth-server base URL (default https://api.accounts.firefox.com/v1)")
	f.StringVar(&c.proxyPass, "proxy-pass-jwt", env("PROXY_PASS_JWT", ""), "explicit ProxyPass JWT")
	f.StringVar(&c.fxaToken, "fxa-token", env("FXA_TOKEN", ""), "temporary FxA OAuth access token")
	f.StringVar(&c.bind, "bind", env("BIND", "127.0.0.1"), "listen address")
	f.StringVar(&c.advertise, "advertise-host", env("ADVERTISE_HOST", ""), "exported host")
	f.IntVar(&c.socksBase, "socks-base", 21000, "first per-node SOCKS port")
	f.IntVar(&c.httpBase, "http-base", 31000, "first per-node HTTP port")
	f.IntVar(&c.udpBase, "udp-base", 41000, "first per-node UDP relay port (SOCKS5 UDP ASSOCIATE via MASQUE)")
	f.DurationVar(&c.udpIdleTimeout, "udp-idle-timeout", 2*time.Minute, "idle timeout for SOCKS5 UDP tunnels (0 disables)")
	f.IntVar(&c.udpMaxTunnelsClient, "udp-max-tunnels-client", 64, "maximum concurrent UDP tunnels per client (0 = unlimited)")
	f.IntVar(&c.limit, "limit", 0, "maximum node count")
	f.DurationVar(&c.idleTimeout, "idle-timeout", 10*time.Minute, "idle timeout for relayed TCP connections (0 disables)")
	f.IntVar(&c.maxConns, "max-conns", 512, "maximum concurrent client connections per server (0 = unlimited)")
	f.StringVar(&c.countries, "countries", env("COUNTRIES", ""), "comma-separated countries")
	f.BoolVar(&c.noSocks, "no-socks", false, "disable SOCKS listeners")
	f.BoolVar(&c.noHTTP, "no-http", false, "disable HTTP listeners")
	f.StringVar(&c.rotator, "rotator", env("ROTATOR", ""), "aggregate SOCKS authority or off")
	f.StringVar(&c.httpRotator, "http-rotator", env("HTTP_ROTATOR", ""), "aggregate HTTP authority or off")
	f.StringVar(&c.rotateMode, "rotate-mode", env("ROTATE_MODE", "random"), "random or rr")
	f.BoolVar(&c.forceSync, "force-sync", false, "force Remote Settings request")
	f.BoolVar(&c.allowNoToken, "allow-no-token", false, "start without a currently valid token")
	f.StringVar(&c.country, "country", "", "probe country")
	f.StringVar(&c.authUser, "auth-user", env("LISTEN_USER", ""), "local proxy user")
	f.StringVar(&c.authPass, "auth-pass", env("LISTEN_PASS", ""), "local proxy password")
	f.BoolVar(&c.requireAuth, "require-auth", false, "require configured local authentication")
	f.BoolVar(&c.allowOpen, "allow-open-proxy", false, "permit an unauthenticated non-loopback listener")
	f.StringVar(&c.firefoxVersion, "firefox-version", env("FIREFOX_VERSION", serverlist.DefaultFirefoxVersion), "Firefox version")
	f.StringVar(&c.clientCountry, "client-country", env("CLIENT_COUNTRY", ""), "client country for filters")
	f.StringVar(&c.masqueURI, "masque-uri", env("MASQUE_URI", ""), "MASQUE proxy URI template, e.g. https://host:443/.well-known/masque/udp/{target_host}/{target_port}/")
	f.BoolVar(&c.includeLocked, "include-locked", false, "include locked records diagnostically")
	f.BoolVar(&c.recommended, "recommended", false, "use REC records only")
	f.StringVar(&c.accountMode, "account-mode", env("ACCOUNT_MODE", ""), "multi-account token selection mode (rr)")
	f.StringVar(&c.clockURL, "clock-url", "https://vpn.mozilla.org", "trusted HTTPS URL for clock-check")
	f.BoolVar(&c.quotaAware, "quota-aware", false, "opt-in: prefer accounts with known remaining quota (default round-robin)")
	f.DurationVar(&c.quotaMaxAge, "quota-max-age", 15*time.Minute, "trust window for a quota snapshot (must be > 0 with --quota-aware)")
	f.Int64Var(&c.quotaMargin, "quota-margin-bytes", 0, "minimum remaining bytes required to select an account")
	f.DurationVar(&c.quotaCooldown, "quota-cooldown", 15*time.Minute, "skip duration for exhausted accounts without a reset time")
	f.DurationVar(&c.quotaRefreshInterval, "quota-refresh-interval", 15*time.Minute, "background quota refresh interval when --quota-aware is set")
	f.StringVar(&c.probeTarget, "probe-target", "1.1.1.1", "UDP probe target host")
	f.StringVar(&c.probePorts, "probe-ports", "53,80,443,3478,8080,8443,123", "comma-separated UDP ports for udp-probe")
	f.DurationVar(&c.probeTimeout, "probe-timeout", 3*time.Second, "per-port timeout for probe/udp-probe")
	return f, c
}
func main() { os.Exit(run(os.Args[1:])) }
func run(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: fxpool-proxy <sync|token-status|token-refresh|usage|how-to-token|probe|udp-probe|clock-check|run|login|export-credentials|import-credentials|accounts>")
		return 2
	}
	cmd := argv[0]
	// "accounts" is a sub-command family with its own argument parsing.
	if cmd == "accounts" {
		f, c := flagsFor(cmd)
		// Global flags (--root, --account-mode, --guardian, --fxa-base, …) may
		// appear anywhere — before the sub-command name, between positionals, or
		// after them. Pull them out by name so they reach flagsFor's config; the
		// rest (sub-command name + sub-command-specific flags) go to cmdAccounts.
		globalFlagNames := map[string]bool{
			"root": true, "account-mode": true, "guardian": true,
			"fxa-base": true, "fxa-token": true,
		}
		var globalArgv, subArgs []string
		rest := argv[1:]
		for i := 0; i < len(rest); i++ {
			arg := rest[i]
			// Flags are --name or --name=value.
			if strings.HasPrefix(arg, "--") {
				name := strings.TrimPrefix(arg, "--")
				val := ""
				if eq := strings.IndexByte(name, '='); eq >= 0 {
					val = name[eq+1:]
					name = name[:eq]
					_ = val
				}
				if globalFlagNames[name] {
					globalArgv = append(globalArgv, arg)
					// If --name value (no =), consume the next token too.
					if !strings.Contains(arg, "=") && i+1 < len(rest) && !strings.HasPrefix(rest[i+1], "-") {
						i++
						globalArgv = append(globalArgv, rest[i])
					}
					continue
				}
			}
			subArgs = append(subArgs, arg)
		}
		if err := f.Parse(globalArgv); err != nil {
			return 2
		}
		if err := token.EnsureDirs(c.root); err != nil {
			safeError(err)
			return 1
		}
		return cmdAccounts(c, subArgs)
	}
	f, c := flagsFor(cmd)
	force := false
	deleteSource, noVerify := false, false
	loginEmail, loginTOTP := "", ""
	bundle := ""
	exportOut, exportProfile, exportFirefoxDir := "fxa-renewal-credentials.json", "", ""
	exportList, exportImport, exportStdout := false, false, false
	if cmd == "token-refresh" {
		f.BoolVar(&force, "force", false, "force refresh")
	}
	refreshUID, refreshAll := "", false
	if cmd == "token-refresh" {
		f.StringVar(&refreshUID, "uid", "", "account uid (multi-account mode)")
		f.BoolVar(&refreshAll, "all", false, "refresh all accounts (multi-account mode)")
	}
	usageUID, usageAll, usageRefresh, usageJSON := "", false, false, false
	if cmd == "usage" {
		f.StringVar(&usageUID, "uid", "", "account uid (multi-account mode)")
		f.BoolVar(&usageAll, "all", false, "query all accounts (multi-account mode)")
		f.BoolVar(&usageRefresh, "refresh", false, "force live query to Guardian instead of cached quota")
		f.BoolVar(&usageJSON, "json", false, "output JSON")
	}
	if cmd == "login" {
		f.StringVar(&loginEmail, "email", "", "Firefox Account email")
		f.BoolVar(&noVerify, "no-verify", false, "publish without Guardian refresh")
		f.StringVar(&loginTOTP, "totp", "", "two-factor code (skip interactive prompt)")
	}
	if cmd == "import-credentials" {
		f.BoolVar(&deleteSource, "delete-source", false, "delete bundle after verification")
		f.BoolVar(&noVerify, "no-verify", false, "publish without refresh")
	}
	if cmd == "export-credentials" {
		f.StringVar(&exportOut, "output", "fxa-renewal-credentials.json", "output path (use - for stdout)")
		f.StringVar(&exportOut, "o", "fxa-renewal-credentials.json", "output path (shorthand)")
		f.StringVar(&exportProfile, "profile", "", "profile name or path when multiple are signed in")
		f.StringVar(&exportFirefoxDir, "firefox-dir", "", "Firefox configuration root override")
		f.BoolVar(&exportList, "list", false, "list discovered profiles without writing credentials")
		f.BoolVar(&exportImport, "import", false, "also import into tokens/ and verify renewal")
		f.BoolVar(&noVerify, "no-verify", false, "with --import, publish without Guardian refresh")
		f.BoolVar(&exportStdout, "stdout", false, "write credential JSON to stdout (same as -o -)")
	}
	args := argv[1:]
	if cmd == "import-credentials" {
		// The bundle is positional and may be a bare "-" (stdin). Go's
		// flag.FlagSet.Parse stops at the first non-flag argument, so consume
		// positionals one at a time and re-parse the remainder: this keeps
		// `import-credentials - --no-verify --root DIR` working as documented
		// instead of silently leaving every flag after "-" unparsed.
		for {
			if e := f.Parse(args); e != nil {
				return 2
			}
			rest := f.Args()
			if len(rest) == 0 {
				break
			}
			if bundle == "" {
				bundle = rest[0]
			} else {
				fmt.Fprintln(os.Stderr, "unexpected argument:", rest[0])
				return 2
			}
			args = rest[1:]
		}
	} else if e := f.Parse(args); e != nil {
		return 2
	}
	if cmd != "export-credentials" || exportImport {
		if e := token.EnsureDirs(c.root); e != nil {
			safeError(e)
			return 1
		}
	}
	switch cmd {
	case "sync":
		return cmdSync(c)
	case "token-status":
		return cmdStatus(c)
	case "token-refresh":
		return cmdRefresh(c, force, refreshUID, refreshAll)
	case "usage":
		return cmdUsage(c, usageUID, usageAll, usageRefresh, usageJSON)
	case "how-to-token":
		guide()
		return 0
	case "probe":
		return cmdProbe(c)
	case "udp-probe":
		return cmdUDPProbe(c)
	case "clock-check":
		return cmdClockCheck(c)
	case "login":
		return cmdLogin(c, loginEmail, noVerify, loginTOTP)
	case "run":
		return cmdRun(c)
	case "export-credentials":
		if exportStdout {
			exportOut = "-"
		}
		return cmdExport(c, exportOut, exportProfile, exportFirefoxDir, exportList, exportImport, noVerify)
	case "import-credentials":
		if bundle == "" && f.NArg() > 0 {
			bundle = f.Arg(0)
		}
		return cmdImport(c, bundle, deleteSource, noVerify)
	case "version", "--version":
		fmt.Println(version)
		return 0
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", cmd)
		return 2
	}
}
func manager(c *config) *token.Manager {
	m := token.NewManager(c.root, c.guardian)
	if c.fxaBase != "" {
		m.FxAAuth = strings.TrimRight(c.fxaBase, "/")
	}
	m.ExplicitProxyPass = strings.TrimSpace(c.proxyPass)
	m.AccessToken = strings.TrimSpace(c.fxaToken)
	return m
}

// openAccountDB opens the account database, runs schema migration, and
// performs the one-time legacy import.  Returns the open DB; caller must
// Close() it.  On any error the function prints a diagnostic and the caller
// should return 1.
func openAccountDB(c *config) (*storepkg.DB, error) {
	db, err := storepkg.Open(c.root)
	if err != nil {
		return nil, fmt.Errorf("open account database: %w", err)
	}
	ctx := context.Background()
	res, err := db.LegacyImport(ctx, c.root)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("legacy credential import: %w", err)
	}
	if res.AccountImported {
		fmt.Fprintf(os.Stderr, "[+] migrated legacy credentials uid=%s\n", res.UID)
	} else if !res.Skipped && res.Diagnostics != "" {
		fmt.Fprintf(os.Stderr, "[*] legacy import: %s\n", res.Diagnostics)
	}
	return db, nil
}

// managerWithDB creates a DB-backed Manager for the given account UID.
// When uid is empty and exactly one account exists, that account is used.
func managerWithDB(c *config, db *storepkg.DB, uid string) (*token.Manager, int64, error) {
	ctx := context.Background()
	accounts, err := db.ListAccounts(ctx)
	if err != nil {
		return nil, 0, err
	}
	var acc storepkg.Account
	switch {
	case uid != "":
		found := false
		for _, a := range accounts {
			if a.UID == uid {
				acc = a
				found = true
				break
			}
		}
		if !found {
			return nil, 0, fmt.Errorf("account %q not found", uid)
		}
	case len(accounts) == 1:
		acc = accounts[0]
	case len(accounts) == 0:
		return nil, 0, errors.New("no accounts in database; import credentials first")
	default:
		return nil, 0, errors.New("multiple accounts present; specify --uid")
	}
	m := token.NewManager(c.root, c.guardian)
	if c.fxaBase != "" {
		base := strings.TrimRight(c.fxaBase, "/")
		m.FxAAuth = base
		// When tests point fxa-base at a fake server the OAuth token endpoint
		// lives on the same origin; keep them in sync so PKCE works end-to-end.
		m.FxAOAuth = base
	}
	m.ExplicitProxyPass = strings.TrimSpace(c.proxyPass)
	m.AccessToken = strings.TrimSpace(c.fxaToken)
	m.Store = &storepkg.ManagerBackend{DB: db}
	m.AccountID = acc.ID
	return m, acc.ID, nil
}
func store(c *config) serverlist.Store { return serverlist.DefaultStore(c.root, c.serverURL) }
func cmdSync(c *config) int {
	nodes, e := store(c).Fetch(context.Background(), true, c.firefoxVersion, c.clientCountry, c.includeLocked)
	if e != nil {
		safeError(e)
		return 1
	}
	by := map[string]int{}
	active := 0
	for _, n := range nodes {
		if n.Supported && !n.Locked {
			active++
			by[n.Country]++
		}
	}
	fmt.Printf("[*] serverlist: %d total, %d active\n", len(nodes), active)
	keys := make([]string, 0, len(by))
	for k := range by {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("    %s: %d\n", k, by[k])
	}
	if e = securefile.AtomicJSON(filepath.Join(c.root, "export", "exits.json"), nodes, 0o644); e != nil {
		safeError(e)
		return 1
	}
	return 0
}
func cmdStatus(c *config) int {
	// Explicit JWT mode: bypass the account DB; report the configured source.
	if strings.TrimSpace(c.proxyPass) != "" {
		m := manager(c)
		raw, e := m.Current(0)
		out := map[string]any{
			"automatic_renewal_ready": false,
			"has_proxy_pass":          e == nil,
			"guardian":                c.guardian,
			"refresh_state":           token.EmptyState(),
			"explicit_proxy_pass":     true,
		}
		if e == nil {
			claims, _ := token.DecodeAndValidateJWT(raw, c.guardian, time.Now(), 0)
			out["proxy_pass"] = map[string]any{"valid": true, "seconds_left": int64(claims.Expires) - time.Now().Unix(), "algorithm_verified": false, "signature_verified": false}
		}
		printJSON(out)
		return 0
	}
	if c.accountMode != "" {
		db, err := openAccountDB(c)
		if err != nil {
			safeError(err)
			return 1
		}
		defer db.Close()
		ctx := context.Background()
		accs, err := db.ListAccounts(ctx)
		if err != nil {
			safeError(err)
			return 1
		}
		// Single account: emit the legacy-compatible JSON schema.
		if len(accs) == 1 {
			acc := accs[0]
			rs, _ := db.GetRefreshState(ctx, acc.ID)
			state := token.RefreshState{
				Schema:              1,
				Result:              rs.Result,
				ConsecutiveFailures: rs.ConsecutiveFailures,
				Generation:          rs.Generation,
			}
			if rs.LastAttemptAt != nil {
				v := float64(rs.LastAttemptAt.Unix())
				state.LastAttemptAt = &v
			}
			if rs.LastSuccessAt != nil {
				v := float64(rs.LastSuccessAt.Unix())
				state.LastSuccessAt = &v
			}
			if rs.NextAttemptAt != nil {
				v := float64(rs.NextAttemptAt.Unix())
				state.NextAttemptAt = &v
			}
			if rs.ProxyPassExpiresAt != nil {
				v := float64(rs.ProxyPassExpiresAt.Unix())
				state.ProxyPassExpiresAt = &v
			}
			if rs.HTTPStatus != nil {
				v := *rs.HTTPStatus
				state.HTTPStatus = &v
			}
			pp, ppErr := db.GetProxyPass(ctx, acc.ID)
			out := map[string]any{
				"automatic_renewal_ready": acc.Enabled,
				"has_proxy_pass":          ppErr == nil,
				"guardian":                c.guardian,
				"refresh_state":           state,
			}
			if ppErr == nil {
				claims, _ := token.DecodeAndValidateJWT(pp.JWT, c.guardian, time.Now(), 0)
				out["proxy_pass"] = map[string]any{
					"valid": true, "seconds_left": int64(claims.Expires) - time.Now().Unix(),
					"algorithm_verified": false, "signature_verified": false,
				}
			}
			printJSON(out)
			return 0
		}
		// Multiple accounts: use accounts list format.
		p, err := accounts.NewPool(ctx, db, c.root, c.guardian, c.fxaBase, nil)
		if err != nil {
			safeError(err)
			return 1
		}
		statuses, _ := p.ListStatuses(ctx)
		printJSON(statuses)
		return 0
	}
	m := manager(c)
	state := token.LoadState(filepath.Join(c.root, "tokens", "refresh_state.json"))
	_, credErr := m.LoadCredentials()
	raw, e := m.Current(0)
	out := map[string]any{"automatic_renewal_ready": credErr == nil, "has_proxy_pass": e == nil, "guardian": c.guardian, "refresh_state": state}
	if e == nil {
		claims, _ := token.DecodeAndValidateJWT(raw, c.guardian, time.Now(), 0)
		out["proxy_pass"] = map[string]any{"valid": true, "seconds_left": int64(claims.Expires) - time.Now().Unix(), "algorithm_verified": false, "signature_verified": false}
	}
	printJSON(out)
	return 0
}
func cmdRefresh(c *config, force bool, uid string, all bool) int {
	// Explicit JWT mode: refresh is not applicable.
	if strings.TrimSpace(c.proxyPass) != "" {
		safeError(errors.New("token-refresh is not applicable in explicit JWT mode (FXPOOL_PROXY_PASS_JWT)"))
		return 2
	}
	if c.accountMode != "" {
		// Explicit JWT check above already handled; open DB path.
		db, err := openAccountDB(c)
		if err != nil {
			safeError(err)
			return 1
		}
		defer db.Close()
		ctx := context.Background()
		if all {
			// Refresh all accounts, collect errors.
			accs, err := db.ListAccounts(ctx)
			if err != nil {
				safeError(err)
				return 1
			}
			anyErr := false
			for _, acc := range accs {
				if !acc.Enabled {
					continue
				}
				m, _, err := managerWithDB(c, db, acc.UID)
				if err != nil {
					safeError(fmt.Errorf("account %s: %w", acc.UID, err))
					anyErr = true
					continue
				}
				t, e := m.Refresh(ctx, force)
				if e != nil {
					safeError(fmt.Errorf("account %s: %w", acc.UID, e))
					anyErr = true
					continue
				}
				claims, _ := token.DecodeAndValidateJWT(t, c.guardian, time.Now(), 0)
				fmt.Printf("[+] uid=%s seconds_left=%d\n", acc.UID, int64(claims.Expires)-time.Now().Unix())
			}
			if anyErr {
				return 1
			}
			return 0
		}
		m, _, err := managerWithDB(c, db, uid)
		if err != nil {
			safeError(err)
			return 1
		}
		t, e := m.Refresh(ctx, force)
		if e != nil {
			safeError(e)
			return 1
		}
		claims, _ := token.DecodeAndValidateJWT(t, c.guardian, time.Now(), 0)
		fmt.Printf("[+] refreshed; seconds_left=%d\n", int64(claims.Expires)-time.Now().Unix())
		return 0
	}
	t, e := manager(c).Refresh(context.Background(), force)
	if e != nil {
		safeError(e)
		var he interface{ Temporary() bool }
		if errors.As(e, &he) {
			return 75
		}
		return 1
	}
	claims, _ := token.DecodeAndValidateJWT(t, c.guardian, time.Now(), 0)
	fmt.Printf("[+] refreshed; seconds_left=%d\n", int64(claims.Expires)-time.Now().Unix())
	return 0
}

type usageRow struct {
	UID            string `json:"uid"`
	Email          string `json:"email"`
	Enabled        bool   `json:"enabled"`
	Unlimited      bool   `json:"unlimited"`
	LimitBytes     *int   `json:"limit_bytes,omitempty"`
	RemainingBytes *int   `json:"remaining_bytes,omitempty"`
	ResetTime      string `json:"reset_time,omitempty"`
	Cached         bool   `json:"cached"`
	Error          string `json:"error,omitempty"`
}

func formatBytes(b int) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func cmdUsage(c *config, uid string, all, refresh, asJSON bool) int {
	// Explicit JWT mode: bypass the account DB.
	if strings.TrimSpace(c.proxyPass) != "" {
		u, e := manager(c).Usage(context.Background())
		if e != nil {
			safeError(e)
			return 1
		}
		printJSON(u)
		return 0
	}
	if c.accountMode != "" {
		db, err := openAccountDB(c)
		if err != nil {
			safeError(err)
			return 1
		}
		defer db.Close()
		ctx := context.Background()
		accs, err := db.ListAccounts(ctx)
		if err != nil {
			safeError(err)
			return 1
		}
		if len(accs) == 0 {
			safeError(errors.New("no accounts in database; import credentials first"))
			return 1
		}

		if all {
			quotas, _ := db.ListQuotas(ctx)
			var rows []usageRow

			for _, a := range accs {
				row := usageRow{UID: a.UID, Email: a.Email, Enabled: a.Enabled}
				q, hasQuota := quotas[a.ID]
				needLive := refresh || !hasQuota

				if needLive {
					if !a.Enabled {
						row.Error = "account disabled"
					} else {
						m, _, mErr := managerWithDB(c, db, a.UID)
						if mErr != nil {
							row.Error = mErr.Error()
						} else {
							u, uErr := m.Usage(ctx)
							if uErr != nil {
								row.Error = uErr.Error()
							} else {
								row.Unlimited = u.Unlimited != nil && *u.Unlimited
								row.LimitBytes = u.Limit
								row.RemainingBytes = u.Remaining
								row.ResetTime = u.Reset
								row.Cached = false
							}
						}
					}
				} else {
					row.Unlimited = q.Unlimited
					row.LimitBytes = q.LimitBytes
					row.RemainingBytes = q.RemainingBytes
					row.ResetTime = q.ResetTime
					row.Cached = true
				}

				rows = append(rows, row)
			}

			if asJSON {
				printJSON(rows)
				return 0
			}

			fmt.Printf("%-32s  %-30s  %-8s  %-23s  %s\n", "UID", "EMAIL", "STATUS", "REMAINING / LIMIT", "RESET")
			fmt.Println(strings.Repeat("-", 110))
			for _, r := range rows {
				status := "enabled"
				if !r.Enabled {
					status = "disabled"
				}
				quotaStr := "unknown"
				if r.Error != "" {
					quotaStr = fmt.Sprintf("err: %s", r.Error)
				} else if r.Unlimited {
					quotaStr = "unlimited"
				} else if r.RemainingBytes != nil && r.LimitBytes != nil {
					cachedTag := ""
					if r.Cached {
						cachedTag = " (cached)"
					}
					quotaStr = fmt.Sprintf("%s / %s%s", formatBytes(*r.RemainingBytes), formatBytes(*r.LimitBytes), cachedTag)
				}
				reset := r.ResetTime
				if reset == "" {
					reset = "-"
				}
				fmt.Printf("%-32s  %-30s  %-8s  %-23s  %s\n", r.UID, r.Email, status, quotaStr, reset)
			}
			fmt.Println(strings.Repeat("-", 110))
			fmt.Printf("%d accounts (per-account quotas are not summed)\n", len(rows))
			return 0
		}

		// Single account resolution
		targetUID := uid
		if targetUID == "" {
			if len(accs) == 1 {
				targetUID = accs[0].UID
			} else {
				safeError(errors.New("multiple accounts present; specify --all or --uid <uid>"))
				return 1
			}
		}

		var targetAcc *storepkg.Account
		for i := range accs {
			if accs[i].UID == targetUID {
				targetAcc = &accs[i]
				break
			}
		}
		if targetAcc == nil {
			safeError(fmt.Errorf("account %q not found", targetUID))
			return 1
		}

		if !refresh {
			q, found, _ := db.GetQuota(ctx, targetAcc.ID)
			if found {
				u := token.Usage{
					Unlimited: &q.Unlimited,
					Limit:     q.LimitBytes,
					Remaining: q.RemainingBytes,
					Reset:     q.ResetTime,
				}
				if asJSON {
					printJSON(u)
				} else {
					lim := "-"
					if u.Limit != nil {
						lim = formatBytes(*u.Limit)
					}
					rem := "-"
					if u.Remaining != nil {
						rem = formatBytes(*u.Remaining)
					}
					fmt.Printf("uid: %s (cached)\nemail: %s\nremaining: %s\nlimit: %s\nreset: %s\n", targetAcc.UID, targetAcc.Email, rem, lim, u.Reset)
				}
				return 0
			}
		}

		m, _, err := managerWithDB(c, db, targetUID)
		if err != nil {
			safeError(err)
			return 1
		}
		u, e := m.Usage(ctx)
		if e != nil {
			safeError(e)
			return 1
		}
		if asJSON {
			printJSON(u)
		} else {
			lim := "-"
			if u.Limit != nil {
				lim = formatBytes(*u.Limit)
			}
			rem := "-"
			if u.Remaining != nil {
				rem = formatBytes(*u.Remaining)
			}
			fmt.Printf("uid: %s\nemail: %s\nremaining: %s\nlimit: %s\nreset: %s\n", targetAcc.UID, targetAcc.Email, rem, lim, u.Reset)
		}
		return 0
	}

	u, e := manager(c).Usage(context.Background())
	if e != nil {
		safeError(e)
		return 1
	}
	printJSON(u)
	return 0
}

// cmdLogin authenticates with an FxA email+password, publishes the renewal
// credentials, and (unless --no-verify) refreshes a ProxyPass to verify the
// whole chain. The password is read without echo and never retained.
func cmdLogin(c *config, email string, noVerify bool, totp string) int {
	if email == "" {
		fmt.Print("Firefox Account email: ")
		email = strings.TrimSpace(readLine())
	}
	email = strings.TrimSpace(email)
	if !strings.Contains(email, "@") {
		safeError(errors.New("a valid Firefox Account email is required"))
		return 2
	}
	fmt.Print("Firefox Account password: ")
	password, e := readPassword()
	fmt.Fprintln(os.Stderr)
	if e != nil {
		safeError(e)
		return 1
	}
	if password == "" {
		safeError(errors.New("password must not be empty"))
		return 2
	}
	ctx := context.Background()
	m := manager(c)
	opts := []func(*fxa.Client){}
	if c.fxaBase != "" {
		opts = append(opts, func(fc *fxa.Client) { fc.Base = c.fxaBase })
	}
	if totp != "" {
		opts = append(opts, func(fc *fxa.Client) {
			fc.TOTPPrompt = func() (string, error) { return totp, nil }
		})
	} else {
		// Install an interactive prompt so 2FA-enabled accounts aren't stuck;
		// the flag path above still lets callers supply the code non-interactively.
		opts = append(opts, func(fc *fxa.Client) {
			fc.TOTPPrompt = func() (string, error) {
				fmt.Fprint(os.Stderr, "Two-factor code: ")
				code, err := readPassword()
				fmt.Fprintln(os.Stderr)
				return strings.TrimSpace(code), err
			}
		})
	}
	sess, e := m.Login(ctx, email, password, opts...)
	if e != nil {
		if errors.Is(e, fxa.ErrWAFBlocked) {
			fmt.Fprintln(os.Stderr, "[!] 此网络无法用密码登录；请在注册机生成凭据包后运行: fxpool-proxy import-credentials <bundle>")
		}
		safeError(e)
		return 1
	}
	fmt.Fprintf(os.Stderr, "[+] authenticated uid=%s\n", sess.UID)
	if !noVerify {
		if _, e = m.Refresh(ctx, true); e != nil {
			safeError(errors.New("logged in but ProxyPass refresh failed; credentials published"))
			return 1
		}
		fmt.Println("[+] logged in; renewal credentials published and ProxyPass refreshed")
		return 0
	}
	fmt.Println("[+] logged in; renewal credentials published (not verified)")
	return 0
}

func readLine() string {
	b, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return b
}

func readPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, e := term.ReadPassword(fd)
		return string(b), e
	}
	b, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSuffix(b, "\n"), nil
}
func guide() {
	fmt.Print("Firefox 凭据获取（二选一）\n\n方式一：邮箱+密码自动登录（推荐，无需本机 Firefox）\n  运行：fxpool-proxy login\n  按提示输入 FxA 邮箱和密码（密码不回显），程序自动完成\n  登录 → 发布续期凭据 → 换取 ProxyPass 并验证。\n  已开启两步验证（2FA）的账号会在提示时输入验证码。\n\n方式二：从本机 Firefox 导出\n1. 在本机 Firefox 登录 Firefox Account，启用 IP Protection，并完成设备注册。\n2. 在本机运行：fxpool-proxy export-credentials\n   程序会自动读取配置目录中的 signedInUser.json，写出最小续期凭据包。\n3. 同机可直接：fxpool-proxy export-credentials --import\n   或把凭据包拷到 VPS 后：fxpool-proxy import-credentials /path/to/file --delete-source\n4. 用 fxpool-proxy token-status 检查续期状态。\n\n完整步骤见 README.md；凭据等同登录会话，不要分享。\n")
}
func cmdExport(c *config, out, profile, firefoxDir string, listOnly, doImport, noVerify bool) int {
	var cands []fxaexport.Candidate
	var err error
	if firefoxDir != "" {
		cands, err = fxaexport.DiscoverInRoot(firefoxDir)
	} else {
		cands, err = fxaexport.DiscoverCandidates()
	}
	if err != nil {
		safeError(err)
		return 1
	}
	if listOnly {
		for _, cand := range cands {
			status := "ok"
			if cand.Error != nil {
				status = cand.Error.Error()
			} else if cand.Bundle != nil {
				status = "signed-in email=" + cand.Bundle.Email + " uid=" + cand.Bundle.UID
			}
			def := ""
			if cand.Profile.IsDefault {
				def = " default"
			}
			fmt.Printf("%s%s\n  path: %s\n  status: %s\n", cand.Profile.Name, def, cand.Profile.Path, status)
		}
		return 0
	}
	chosen, err := fxaexport.Select(cands, profile)
	if err != nil {
		safeError(err)
		return 1
	}
	raw, err := fxaexport.EncodeBundle(*chosen.Bundle)
	if err != nil {
		safeError(err)
		return 1
	}
	if out == "-" {
		if _, err = os.Stdout.Write(raw); err != nil {
			safeError(err)
			return 1
		}
	} else {
		if err = securefile.AtomicWrite(out, raw, 0o600); err != nil {
			safeError(err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "[+] wrote %s (0600) from profile %q\n", out, chosen.Profile.Name)
		fmt.Fprintf(os.Stderr, "    email=%s uid=%s\n", chosen.Bundle.Email, chosen.Bundle.UID)
	}
	if doImport {
		path := out
		tmp := ""
		if path == "-" {
			f, e := os.CreateTemp("", "fxa-renewal-*.json")
			if e != nil {
				safeError(e)
				return 1
			}
			tmp = f.Name()
			_, e = f.Write(raw)
			_ = f.Chmod(0o600)
			_ = f.Close()
			if e != nil {
				_ = os.Remove(tmp)
				safeError(e)
				return 1
			}
			path = tmp
			defer os.Remove(tmp)
		}
		return cmdImport(c, path, false, noVerify)
	}
	return 0
}

// probeSource is one geo observation made through the node. IPs are omitted
// on purpose: reports are meant to be safe to paste into an issue.
type probeSource struct {
	Source  string `json:"source"`
	OK      bool   `json:"ok"`
	Country string `json:"country,omitempty"`
	Region  string `json:"region,omitempty"`
	City    string `json:"city,omitempty"`
	Org     string `json:"org,omitempty"`
	Error   string `json:"error,omitempty"`
}

type probeReport struct {
	NodeCountry   string        `json:"node_country"`
	NodeCity      string        `json:"node_city"`
	NodeHostname  string        `json:"node_hostname"`
	Expected      string        `json:"expected_country,omitempty"`
	Sources       []probeSource `json:"sources"`
	IPv4Egress    bool          `json:"ipv4_egress"`
	IPv6Egress    bool          `json:"ipv6_egress"`
	IPv4Error     string        `json:"ipv4_error,omitempty"`
	IPv6Error     string        `json:"ipv6_error,omitempty"`
	Warnings      []string      `json:"warnings,omitempty"`
	GeoDisclaimer string        `json:"geo_disclaimer"`
}

// probeTunnelOpener is the subset of upstream.Dialer needed by probe.
type probeTunnelOpener interface {
	Open(context.Context, serverlist.Node, string, int) (net.Conn, error)
}

func cmdProbe(c *config) int {
	nodes, e := store(c).Fetch(context.Background(), false, c.firefoxVersion, c.clientCountry, false)
	if e != nil {
		safeError(e)
		return 1
	}
	var chosen *serverlist.Node
	for i := range nodes {
		n := &nodes[i]
		if n.Supported && !n.Locked && n.Protocol == "connect" && n.Country != "REC" && (c.country == "" || strings.EqualFold(c.country, n.Country)) {
			chosen = n
			break
		}
	}
	if chosen == nil {
		fmt.Fprintln(os.Stderr, "no nodes")
		return 1
	}
	src, closeSrc, e := probeTokenSource(c)
	if e != nil {
		safeError(e)
		return 1
	}
	defer closeSrc()
	d := &upstream.Dialer{Tokens: src}
	return runProbe(context.Background(), d, *chosen, c.country)
}

// runProbe samples two independent geo sources and both address families. A
// country mismatch is a warning, never an automatic node rejection.
func runProbe(parent context.Context, d probeTunnelOpener, node serverlist.Node, expected string) int {
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	rep := probeReport{
		NodeCountry:   node.Country,
		NodeCity:      node.City,
		NodeHostname:  node.Hostname,
		Expected:      expected,
		GeoDisclaimer: "geolocation databases disagree and can lag; mismatches are warnings only",
	}
	if rep.Expected == "" && node.Country != "REC" {
		rep.Expected = node.Country
	}
	for _, src := range []struct {
		name, host, path string
	}{
		{"ipinfo.io", "ipinfo.io", "/json"},
		{"ifconfig.co", "ifconfig.co", "/json"},
	} {
		body, e := probeGET(ctx, d, node, src.host, 80, src.path)
		if e != nil {
			rep.Sources = append(rep.Sources, probeSource{Source: src.name, Error: probeError(e)})
			continue
		}
		var v map[string]any
		if json.Unmarshal(body, &v) != nil {
			rep.Sources = append(rep.Sources, probeSource{Source: src.name, Error: "non-JSON response"})
			continue
		}
		rep.Sources = append(rep.Sources, geoSource(src.name, v))
	}
	for _, fam := range []struct {
		family, host string
		dst          *bool
		errDst       *string
	}{
		{"ipv4", "ipv4.icanhazip.com", &rep.IPv4Egress, &rep.IPv4Error},
		{"ipv6", "ipv6.icanhazip.com", &rep.IPv6Egress, &rep.IPv6Error},
	} {
		body, e := probeGET(ctx, d, node, fam.host, 80, "/")
		if e != nil {
			*fam.errDst = probeError(e)
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(string(body)))
		if ip == nil || ipFamily(ip) != fam.family {
			*fam.errDst = "unexpected address family"
			continue
		}
		*fam.dst = true
	}
	rep.Warnings = probeWarnings(rep.Expected, rep.Sources)
	ok := rep.IPv4Egress || rep.IPv6Egress
	for _, src := range rep.Sources {
		if src.OK {
			ok = true
			break
		}
	}
	printJSON(rep)
	if !ok {
		return 1
	}
	return 0
}

func ipFamily(ip net.IP) string {
	if ip.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}

// geoSource maps the two supported JSON shapes to a credential-free summary.
func geoSource(name string, v map[string]any) probeSource {
	src := probeSource{Source: name, OK: true}
	pick := func(keys ...string) string {
		for _, k := range keys {
			if s, ok := v[k].(string); ok && s != "" {
				return s
			}
		}
		return ""
	}
	switch name {
	case "ifconfig.co":
		src.Country = pick("country_iso", "country")
		src.Region = pick("region_name", "region")
		src.City = pick("city")
		src.Org = pick("asn_org", "asn")
	default:
		src.Country = pick("country")
		src.Region = pick("region")
		src.City = pick("city")
		src.Org = pick("org")
	}
	return src
}

// probeWarnings reports disagreements without rejecting anything.
func probeWarnings(expected string, sources []probeSource) []string {
	var warnings []string
	seen := map[string]bool{}
	var countries []string
	for _, src := range sources {
		c := strings.ToUpper(strings.TrimSpace(src.Country))
		if !src.OK || c == "" {
			continue
		}
		if !seen[c] {
			seen[c] = true
			countries = append(countries, c)
		}
	}
	if len(countries) > 1 {
		warnings = append(warnings, "geo sources disagree on country: "+strings.Join(countries, ", "))
	}
	if expected = strings.ToUpper(strings.TrimSpace(expected)); expected != "" && expected != "REC" {
		for _, c := range countries {
			if c != expected {
				warnings = append(warnings, fmt.Sprintf("expected node country %s but observed %s (geo database or egress mapping; warning only)", expected, c))
			}
		}
	}
	return warnings
}

// probeGET makes one HTTP/1.1 GET through a CONNECT tunnel and returns the
// response body.
func probeGET(ctx context.Context, d probeTunnelOpener, node serverlist.Node, host string, port int, path string) ([]byte, error) {
	conn, e := d.Open(ctx, node, host, port)
	if e != nil {
		return nil, e
	}
	defer conn.Close()
	req := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nAccept: application/json\r\nUser-Agent: fxpool-proxy-probe/1\r\nConnection: close\r\n\r\n"
	if _, e = io.WriteString(conn, req); e != nil {
		return nil, e
	}
	resp, e := http.ReadResponse(bufioNew(conn), &http.Request{Method: http.MethodGet})
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if e != nil {
		return nil, e
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, host)
	}
	return b, nil
}

type readerConn struct{ net.Conn }

func bufioNew(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }

// udpProbePort is one entry in a udp-probe report. Tunnel records whether the
// MASQUE proxy accepted CONNECT-UDP for this port; Reply records whether any
// datagram came back within the timeout. A tunnel can be established with no
// reply (the target may not speak on that port).
type udpProbePort struct {
	Port     int    `json:"port"`
	Tunnel   string `json:"tunnel"`
	TunnelMS int64  `json:"tunnel_ms"`
	Reply    bool   `json:"reply"`
	Error    string `json:"error,omitempty"`
}

type udpProbeReport struct {
	Hostname string         `json:"hostname"`
	Port     int            `json:"masque_port"`
	Target   string         `json:"target"`
	Ports    []udpProbePort `json:"ports"`
	Note     string         `json:"note"`
}

// cmdUDPProbe measures CONNECT-UDP admission (and best-effort replies) per
// target port on one authorized MASQUE endpoint. The report contains no
// credentials.
func cmdUDPProbe(c *config) int {
	if strings.TrimSpace(c.masqueURI) == "" {
		safeError(errors.New("udp-probe requires --masque-uri"))
		return 2
	}
	node, e := masqueNodeFromURI(c.masqueURI)
	if e != nil {
		safeError(e)
		return 2
	}
	ports, e := parseProbePorts(c.probePorts)
	if e != nil {
		safeError(e)
		return 2
	}
	if c.probeTimeout <= 0 {
		safeError(errors.New("--probe-timeout must be positive"))
		return 2
	}
	src, closeSrc, e := probeTokenSource(c)
	if e != nil {
		safeError(e)
		return 1
	}
	defer closeSrc()
	d := &upstream.Dialer{Tokens: src}
	report := udpProbeReport{
		Hostname: node.Hostname,
		Port:     node.Port,
		Target:   c.probeTarget,
		Note:     "Tunnel=established means CONNECT-UDP was accepted for this port; Reply means a datagram returned within the timeout. This is not an application-level reachability guarantee.",
	}
	established := 0
	for _, port := range ports {
		r := probeUDPPort(d, node, c.probeTarget, port, c.probeTimeout)
		if r.Tunnel == "established" {
			established++
		}
		report.Ports = append(report.Ports, r)
	}
	printJSON(report)
	if established == 0 {
		return 1
	}
	return 0
}

func parseProbePorts(v string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, e := strconv.Atoi(part)
		if e != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid probe port %q", part)
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, errors.New("no probe ports configured")
	}
	return out, nil
}

// probeTokenSource reuses the account pool in multi-account mode, otherwise
// the single-account manager.
func probeTokenSource(c *config) (upstream.TokenSource, func(), error) {
	if c.accountMode != "" && strings.TrimSpace(c.proxyPass) == "" {
		db, err := openAccountDB(c)
		if err != nil {
			return nil, nil, err
		}
		p, err := accounts.NewPool(context.Background(), db, c.root, c.guardian, c.fxaBase, nil)
		if err != nil {
			_ = db.Close()
			return nil, nil, err
		}
		if p.Len() == 0 {
			_ = db.Close()
			return nil, nil, errors.New("no enabled accounts in pool; import credentials first")
		}
		return p, func() { _ = db.Close() }, nil
	}
	return manager(c), func() {}, nil
}

// cmdClockCheck reports the trusted server's clock offset from this machine's
// clock. It never changes JWT validation.
func cmdClockCheck(c *config) int {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	off, e := token.ServerDateOffset(ctx, &http.Client{Timeout: 10 * time.Second}, c.clockURL)
	if e != nil {
		safeError(fmt.Errorf("clock check: %w", e))
		return 1
	}
	printJSON(map[string]any{
		"url":                c.clockURL,
		"offset_seconds":     int64(off / time.Second),
		"resolution_seconds": 1,
		"note":               "positive means the trusted server clock is ahead; observation only, signed JWT exp is never extended",
	})
	return 0
}

type udpOpener interface {
	OpenUDP(context.Context, serverlist.Node, string, int) (net.PacketConn, error)
}

func probeUDPPort(d udpOpener, node serverlist.Node, target string, port int, timeout time.Duration) udpProbePort {
	r := udpProbePort{Port: port, Tunnel: "rejected"}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	pc, e := d.OpenUDP(ctx, node, target, port)
	r.TunnelMS = time.Since(start).Milliseconds()
	if e != nil {
		r.Error = probeError(e)
		return r
	}
	defer pc.Close()
	r.Tunnel = "established"
	payload := []byte{0, 0, 0, 0}
	if port == 53 {
		payload = dnsProbeQuery("example.com")
	}
	if _, e = pc.WriteTo(payload, nil); e != nil {
		r.Error = probeError(e)
		return r
	}
	_ = pc.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1500)
	n, _, e := pc.ReadFrom(buf)
	if e != nil {
		var ne net.Error
		if errors.As(e, &ne) && ne.Timeout() {
			return r // no reply within the timeout, tunnel still established
		}
		r.Error = probeError(e)
		return r
	}
	r.Reply = n > 0
	return r
}

func probeError(e error) string {
	s := strings.ReplaceAll(e.Error(), "\n", " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// dnsProbeQuery builds a minimal DNS A query so port 53 can produce a reply.
func dnsProbeQuery(name string) []byte {
	b := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			continue
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0x00, 0x00, 0x01, 0x00, 0x01)
	return b
}
func cmdRun(c *config) int {
	if e := validateRun(c); e != nil {
		safeError(e)
		return 2
	}
	nodes, e := store(c).Fetch(context.Background(), c.forceSync, c.firefoxVersion, c.clientCountry, c.includeLocked)
	if e != nil {
		safeError(e)
		return 1
	}
	nodes = filterNodes(nodes, c)
	var masqueNodes []serverlist.Node
	if c.masqueURI != "" {
		mn, e := masqueNodeFromURI(c.masqueURI)
		if e != nil {
			safeError(e)
			return 2
		}
		masqueNodes = append(masqueNodes, mn)
	}
	for _, n := range nodes {
		if n.Protocol == "masque" && n.TemplateString != "" {
			masqueNodes = append(masqueNodes, n)
		}
	}
	if len(nodes) == 0 && len(masqueNodes) == 0 {
		safeError(errors.New("no usable nodes selected"))
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var tokenSource upstream.TokenSource
	if c.accountMode != "" && strings.TrimSpace(c.proxyPass) == "" {
		// Multi-account mode: open DB and build a Pool.
		// When FXPOOL_PROXY_PASS_JWT is set it is a hard priority: bypass the
		// account pool and use the single-account Manager path below, which
		// already handles ExplicitProxyPass and the per-file reject list.
		db, err := openAccountDB(c)
		if err != nil {
			safeError(err)
			return 1
		}
		defer db.Close()
		p, err := accounts.NewPool(ctx, db, c.root, c.guardian, c.fxaBase, nil)
		if err != nil {
			safeError(err)
			return 1
		}
		if p.Len() == 0 && !c.allowNoToken {
			safeError(errors.New("no enabled accounts in pool; import credentials first"))
			return 1
		}
		if _, e := p.Ensure(ctx, false); e != nil && !c.allowNoToken {
			safeError(e)
			return 1
		}
		if c.quotaAware {
			p.EnableQuotaPolicy(accounts.QuotaPolicy{MaxAge: c.quotaMaxAge, MarginBytes: c.quotaMargin, Cooldown: c.quotaCooldown})
			go quotaLoop(ctx, p, c.quotaRefreshInterval)
		}
		tokenSource = p
		go refreshLoopPool(ctx, p)
	} else {
		// Single-account mode (or explicit JWT override): legacy file-backed Manager.
		m := manager(c)
		if _, e = m.Ensure(ctx, false); e != nil && !c.allowNoToken {
			safeError(e)
			return 1
		}
		tokenSource = m
		go refreshLoop(ctx, m)
	}

	dial := &upstream.Dialer{Tokens: tokenSource}
	ports, e := pool.AssignPorts(filepath.Join(c.root, "data", "port-map.json"), nodes, c.socksBase, c.httpBase)
	if e != nil {
		safeError(e)
		return 1
	}
	var udpSrv *pool.UDPServer
	var udpAddr string
	if len(masqueNodes) > 0 {
		udpSrv = pool.NewUDPServer(dial, masqueNodes)
		udpSrv.IdleTimeout = c.udpIdleTimeout
		udpSrv.MaxTunnelsPerClient = c.udpMaxTunnelsClient
		udpSrv.Logf = serverLogf
		udpListen := net.JoinHostPort(c.bind, strconv.Itoa(c.udpBase))
		a, e := udpSrv.Listen(udpListen)
		if e != nil {
			safeError(e)
			return 1
		}
		udpAddr = a.String()
		defer func() { _ = udpSrv.Close() }()
	}
	var servers []*pool.Server
	closeAll := func() {
		for i := len(servers) - 1; i >= 0; i-- {
			_ = servers[i].Close()
		}
	}
	defer closeAll()
	var eps []endpoint
	for _, n := range nodes {
		s := &pool.Server{Dialer: dial, Selector: pool.NewSelector([]serverlist.Node{n}, "rr"), Username: c.authUser, Password: c.authPass, AllowOpen: c.allowOpen, UDPRelay: udpSrv, IdleTimeout: c.idleTimeout, MaxConns: c.maxConns, Logf: serverLogf}
		ep := endpoint{node: n}
		assigned := ports[n.StableID()]
		if !c.noSocks {
			a, e := s.StartSOCKS(net.JoinHostPort(c.bind, strconv.Itoa(assigned.Socks)))
			if e != nil {
				safeError(e)
				return 1
			}
			ep.socks = a.String()
		}
		if !c.noHTTP {
			a, e := s.StartHTTP(net.JoinHostPort(c.bind, strconv.Itoa(assigned.HTTP)))
			if e != nil {
				safeError(e)
				return 1
			}
			ep.http = a.String()
		}
		servers = append(servers, s)
		eps = append(eps, ep)
	}
	aggregate := &pool.Server{Dialer: dial, Selector: pool.NewSelector(nodes, c.rotateMode), Username: c.authUser, Password: c.authPass, AllowOpen: c.allowOpen, UDPRelay: udpSrv, IdleTimeout: c.idleTimeout, MaxConns: c.maxConns, Logf: serverLogf}
	if !disabled(c.rotator) && !c.recommended {
		addr := c.rotator
		if addr == "" {
			addr = net.JoinHostPort(c.bind, "1090")
		}
		if _, e = aggregate.StartSOCKS(addr); e != nil {
			safeError(e)
			return 1
		}
	}
	if !disabled(c.httpRotator) && !c.recommended {
		addr := c.httpRotator
		if addr == "" {
			addr = net.JoinHostPort(c.bind, "8080")
		}
		if _, e = aggregate.StartHTTP(addr); e != nil {
			safeError(e)
			return 1
		}
	}
	servers = append(servers, aggregate)
	if e = export(c, eps); e != nil {
		safeError(e)
		return 1
	}
	if udpAddr != "" {
		fmt.Printf("[*] UDP relay (SOCKS5 UDP ASSOCIATE via MASQUE): %s\n", udpAddr)
	}
	fmt.Printf("[*] pool running: nodes=%d (credentials omitted)\n", len(eps))
	<-ctx.Done()
	fmt.Println("[*] stopping")
	return 0
}
func validateRun(c *config) error {
	if c.limit < 0 {
		return errors.New("--limit must be a positive integer")
	}
	if c.idleTimeout < 0 {
		return errors.New("--idle-timeout must be zero or positive")
	}
	if c.maxConns < 0 {
		return errors.New("--max-conns must be zero or positive")
	}
	if c.udpIdleTimeout < 0 {
		return errors.New("--udp-idle-timeout must be zero or positive")
	}
	if c.udpMaxTunnelsClient < 0 {
		return errors.New("--udp-max-tunnels-client must be zero or positive")
	}
	if c.quotaMargin < 0 {
		return errors.New("--quota-margin-bytes must be zero or positive")
	}
	if c.quotaMaxAge < 0 || c.quotaCooldown < 0 || c.quotaRefreshInterval < 0 {
		return errors.New("--quota-* durations must be zero or positive")
	}
	if c.quotaAware && c.quotaMaxAge <= 0 {
		return errors.New("--quota-aware requires --quota-max-age > 0")
	}
	if c.noSocks && c.noHTTP {
		return errors.New("--no-socks and --no-http cannot be used together")
	}
	if c.rotateMode != "random" && c.rotateMode != "rr" {
		return errors.New("--rotate-mode must be random or rr")
	}
	if c.countries != "" && c.recommended {
		return errors.New("--countries and --recommended cannot be used together")
	}
	if strings.Contains(strings.ToUpper(c.countries), "REC") {
		return errors.New("REC is not a country; use --recommended")
	}
	if (c.authUser == "") != (c.authPass == "") {
		return errors.New("both listen username and password are required")
	}
	ip := net.ParseIP(c.bind)
	loop := strings.EqualFold(c.bind, "localhost") || ip != nil && ip.IsLoopback()
	if !loop && c.authUser == "" && !c.allowOpen {
		return errors.New("refusing unauthenticated non-loopback listener")
	}
	if c.requireAuth && c.authUser == "" {
		return errors.New("listen authentication is required")
	}
	return nil
}
func filterNodes(nodes []serverlist.Node, c *config) []serverlist.Node {
	wanted := map[string]bool{}
	for _, x := range strings.Split(c.countries, ",") {
		if x = strings.TrimSpace(strings.ToUpper(x)); x != "" {
			wanted[x] = true
		}
	}
	out := nodes[:0]
	for _, n := range nodes {
		if !n.Supported || n.Locked {
			continue
		}
		if c.recommended != (n.Country == "REC") {
			continue
		}
		if len(wanted) > 0 && !wanted[n.Country] {
			continue
		}
		out = append(out, n)
		if c.limit > 0 && len(out) >= c.limit {
			break
		}
	}
	return out
}

// masqueNodeFromURI builds a MASQUE upstream node from a user-supplied URI
// template such as https://host:443/.well-known/masque/udp/{target_host}/{target_port}/.
// The template's host:port becomes the QUIC endpoint.
func masqueNodeFromURI(uri string) (serverlist.Node, error) {
	if !strings.HasPrefix(uri, "https://") {
		return serverlist.Node{}, errors.New("masque-uri must be an https:// URI template")
	}
	u, e := url.Parse(uri)
	if e != nil || u.Host == "" {
		return serverlist.Node{}, errors.New("invalid masque-uri: " + uri)
	}
	host, port, e := net.SplitHostPort(u.Host)
	if e != nil {
		host, port, e = u.Host, "443", nil
		if e != nil {
			return serverlist.Node{}, e
		}
	}
	p, e := strconv.Atoi(port)
	if e != nil || p < 1 || p > 65535 {
		return serverlist.Node{}, errors.New("invalid masque-uri port: " + port)
	}
	return serverlist.Node{
		Country: "REC", CountryName: "MASQUE", City: "MASQUE", CityName: "Configured MASQUE proxy",
		Hostname:       strings.ToLower(host),
		Port:           p,
		Protocol:       "masque",
		Scheme:         "https",
		Supported:      true,
		RecordID:       "masque-config",
		TemplateString: uri,
		MasqueHost:     strings.ToLower(host),
		MasquePort:     p,
	}, nil
}
func disabled(s string) bool {
	s = strings.ToLower(s)
	return s == "off" || s == "none" || s == "false"
}
func export(c *config, eps []endpoint) error {
	host := c.advertise
	if host == "" {
		host = c.bind
	}
	type item struct {
		Name      string `json:"name"`
		Country   string `json:"country"`
		City      string `json:"city"`
		Hostname  string `json:"hostname"`
		Port      int    `json:"port"`
		RecordID  string `json:"record_id"`
		Protocol  string `json:"protocol"`
		Scheme    string `json:"scheme"`
		Locked    bool   `json:"locked"`
		Supported bool   `json:"supported"`
		Socks     string `json:"socks,omitempty"`
		HTTP      string `json:"http,omitempty"`
		Label     string `json:"label"`
	}
	var meta []item
	var socks, httpLines, socksURLs, httpURLs []string
	auth := ""
	mode := os.FileMode(0o644)
	if c.authUser != "" {
		auth = url.QueryEscape(c.authUser) + ":" + url.QueryEscape(c.authPass) + "@"
		mode = 0o600
	}
	for _, ep := range eps {
		saddr, haddr := ep.socks, ep.http
		if saddr != "" {
			_, p, _ := net.SplitHostPort(saddr)
			saddr = net.JoinHostPort(host, p)
			socks = append(socks, saddr)
			socksURLs = append(socksURLs, "socks5h://"+auth+saddr)
		}
		if haddr != "" {
			_, p, _ := net.SplitHostPort(haddr)
			haddr = net.JoinHostPort(host, p)
			httpLines = append(httpLines, haddr)
			httpURLs = append(httpURLs, "http://"+auth+haddr)
		}
		meta = append(meta, item{ep.node.Country + "-" + ep.node.City, ep.node.Country, ep.node.City, ep.node.Hostname, ep.node.Port, ep.node.RecordID, ep.node.Protocol, ep.node.Scheme, ep.node.Locked, ep.node.Supported, saddr, haddr, ep.node.CountryName + "/" + ep.node.CityName + " (" + ep.node.Hostname + ")"})
	}
	writeLines := func(name string, lines []string, m os.FileMode) error {
		data := ""
		if len(lines) > 0 {
			data = strings.Join(lines, "\n") + "\n"
		}
		return securefile.AtomicWrite(filepath.Join(c.root, "export", name), []byte(data), m)
	}
	if e := writeLines("socks5.txt", socks, 0o644); e != nil {
		return e
	}
	if e := writeLines("http.txt", httpLines, 0o644); e != nil {
		return e
	}
	if e := writeLines("socks5_urls.txt", socksURLs, mode); e != nil {
		return e
	}
	if e := writeLines("http_urls.txt", httpURLs, mode); e != nil {
		return e
	}
	return securefile.AtomicJSON(filepath.Join(c.root, "export", "pool.json"), meta, 0o644)
}
func refreshLoop(ctx context.Context, m *token.Manager) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = m.Ensure(ctx, false)
		}
	}
}

// quotaLoop keeps quota snapshots fresh when --quota-aware is enabled. The
// first refresh runs immediately; errors are ignored and leave the previous
// snapshot in place.
func quotaLoop(ctx context.Context, p *accounts.Pool, interval time.Duration) {
	p.RefreshQuotas(ctx)
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.RefreshQuotas(ctx)
		}
	}
}

func refreshLoopPool(ctx context.Context, p *accounts.Pool) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.RefreshAll(ctx)
		}
	}
}
func cmdImport(c *config, path string, deleteSource, noVerify bool) int {
	if path == "" {
		safeError(errors.New("credential bundle path is required"))
		return 2
	}
	var b []byte
	var e error
	if path == "-" {
		b, e = io.ReadAll(io.LimitReader(os.Stdin, 16<<10+1))
	} else {
		b, e = securefile.ReadRegular(path, 16<<10, true)
	}
	if e != nil || len(b) > 16<<10 {
		safeError(errors.New("cannot safely read credential bundle"))
		return 2
	}
	var in struct {
		Schema       string `json:"schema"`
		Email        string `json:"email"`
		UID          string `json:"uid"`
		SessionToken string `json:"session_token"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(b)))
	decoder.DisallowUnknownFields()
	decodeErr := decoder.Decode(&in)
	if decodeErr != nil || in.Schema != "firefox-ip-protection-renewal-credentials-v1" || len(in.UID) != 32 || len(in.SessionToken) != 64 || !strings.Contains(in.Email, "@") {
		safeError(errors.New("invalid credential bundle"))
		return 2
	}
	cred := token.Credentials{Schema: 1, Email: in.Email, UID: strings.ToLower(in.UID), SessionToken: strings.ToLower(in.SessionToken)}

	if c.accountMode != "" {
		db, err := openAccountDB(c)
		if err != nil {
			safeError(err)
			return 1
		}
		defer db.Close()
		m, _, err := managerWithDB(c, db, "")
		if err != nil {
			// First import: no account yet. Use a bare DB-backed manager.
			bk := &storepkg.ManagerBackend{DB: db}
			m = token.NewManager(c.root, c.guardian)
			if c.fxaBase != "" {
				m.FxAAuth = strings.TrimRight(c.fxaBase, "/")
			}
			m.Store = bk
		}
		if e = m.PublishCredentials(cred); e != nil {
			safeError(e)
			return 1
		}
		if !noVerify {
			if _, e = m.Refresh(context.Background(), true); e != nil {
				safeError(errors.New("credentials imported but verification failed; source kept"))
				return 1
			}
		}
	} else {
		if e = manager(c).PublishCredentials(cred); e != nil {
			safeError(e)
			return 1
		}
		if !noVerify {
			if _, e = manager(c).Refresh(context.Background(), true); e != nil {
				safeError(errors.New("credentials imported but verification failed; source kept"))
				return 1
			}
		}
	}
	if deleteSource && path != "-" {
		if e = os.Remove(path); e != nil {
			safeError(errors.New("verified but source could not be deleted"))
			return 1
		}
	}
	fmt.Println("[+] Firefox renewal credentials imported successfully")
	return 0
}

// cmdAccounts handles the "accounts" sub-command family:
// accounts list|enable|disable|remove
func cmdAccounts(c *config, subArgs []string) int {
	if len(subArgs) == 0 {
		fmt.Fprintln(os.Stderr, "usage: fxpool-proxy accounts <list|enable|disable|remove>")
		return 2
	}
	db, err := openAccountDB(c)
	if err != nil {
		safeError(err)
		return 1
	}
	defer db.Close()
	ctx := context.Background()
	sub := subArgs[0]
	rest := subArgs[1:]

	switch sub {
	case "list":
		listJSON := false
		sf := flag.NewFlagSet("accounts list", flag.ContinueOnError)
		sf.BoolVar(&listJSON, "json", false, "output JSON")
		_ = sf.Parse(rest)
		accs, err := db.ListAccounts(ctx)
		if err != nil {
			safeError(err)
			return 1
		}
		quotas, _ := db.ListQuotas(ctx)
		if listJSON {
			type row struct {
				UID            string `json:"uid"`
				Email          string `json:"email"`
				Enabled        bool   `json:"enabled"`
				Result         string `json:"refresh_result"`
				Label          string `json:"label"`
				LimitBytes     *int   `json:"limit_bytes,omitempty"`
				RemainingBytes *int   `json:"remaining_bytes,omitempty"`
			}
			var rows []row
			for _, a := range accs {
				rs, _ := db.GetRefreshState(ctx, a.ID)
				r := row{UID: a.UID, Email: a.Email, Enabled: a.Enabled, Result: rs.Result, Label: a.Label}
				if q, ok := quotas[a.ID]; ok {
					r.LimitBytes = q.LimitBytes
					r.RemainingBytes = q.RemainingBytes
				}
				rows = append(rows, r)
			}
			printJSON(rows)
			return 0
		}
		for _, a := range accs {
			rs, _ := db.GetRefreshState(ctx, a.ID)
			pp, ppErr := db.GetProxyPass(ctx, a.ID)
			ttl := ""
			if ppErr == nil {
				secs := time.Until(pp.ExpiresAt).Seconds()
				if secs > 0 {
					ttl = fmt.Sprintf("ttl=%ds", int64(secs))
				} else {
					ttl = "expired"
				}
			}
			enabled := "enabled"
			if !a.Enabled {
				enabled = "disabled"
			}
			quotaInfo := ""
			if q, ok := quotas[a.ID]; ok && q.RemainingBytes != nil && q.LimitBytes != nil {
				quotaInfo = fmt.Sprintf("quota=%s/%s", formatBytes(*q.RemainingBytes), formatBytes(*q.LimitBytes))
			}
			fmt.Printf("uid=%-32s %s  state=%-20s %-11s %s\n", a.UID, enabled, rs.Result, ttl, quotaInfo)
		}
		return 0

	case "enable", "disable":
		if len(rest) == 0 {
			fmt.Fprintf(os.Stderr, "usage: accounts %s <uid>\n", sub)
			return 2
		}
		uid := rest[0]
		if err := db.SetAccountEnabled(ctx, uid, sub == "enable"); err != nil {
			safeError(err)
			return 1
		}
		fmt.Printf("[+] account %s %sd\n", uid, sub)
		return 0

	case "remove":
		yes := false
		sf := flag.NewFlagSet("accounts remove", flag.ContinueOnError)
		sf.BoolVar(&yes, "yes", false, "confirm deletion")
		_ = sf.Parse(rest)
		args := sf.Args()
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "usage: accounts remove --yes <uid>")
			return 2
		}
		if !yes {
			fmt.Fprintln(os.Stderr, "[!] pass --yes to confirm deletion of account and all its data")
			return 2
		}
		uid := args[0]
		tx, err := db.Begin(ctx)
		if err != nil {
			safeError(err)
			return 1
		}
		if err := db.DeleteAccount(ctx, tx, uid); err != nil {
			_ = tx.Rollback()
			safeError(err)
			return 1
		}
		if err := tx.Commit(); err != nil {
			safeError(err)
			return 1
		}
		fmt.Printf("[+] account %s removed\n", uid)
		return 0

	default:
		fmt.Fprintln(os.Stderr, "unknown accounts sub-command:", sub)
		return 2
	}
}
func safeError(e error) { fmt.Fprintf(os.Stderr, "[!] %s\n", e.Error()) }
func serverLogf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[!] "+format+"\n", args...)
}
func printJSON(v any) { b, _ := json.MarshalIndent(v, "", "  "); fmt.Println(string(b)) }

var _ = url.QueryEscape
