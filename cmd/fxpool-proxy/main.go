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
	socksBase, httpBase, udpBase, limit                                                                                                                                                 int
	forceSync, allowNoToken, noSocks, noHTTP, requireAuth, allowOpen, includeLocked, recommended                                                                                        bool
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
	f.IntVar(&c.limit, "limit", 0, "maximum node count")
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
	return f, c
}
func main() { os.Exit(run(os.Args[1:])) }
func run(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: fxpool-proxy <sync|token-status|token-refresh|usage|how-to-token|probe|run|login|export-credentials|import-credentials|accounts>")
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
		return cmdUsage(c)
	case "how-to-token":
		guide()
		return 0
	case "probe":
		return cmdProbe(c)
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
func cmdUsage(c *config) int {
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
		m, _, err := managerWithDB(c, db, "")
		if err != nil {
			safeError(err)
			return 1
		}
		u, e := m.Usage(context.Background())
		if e != nil {
			safeError(e)
			return 1
		}
		printJSON(u)
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
	d := &upstream.Dialer{Tokens: manager(c)}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	conn, e := d.Open(ctx, *chosen, "ipinfo.io", 80)
	if e != nil {
		safeError(e)
		return 1
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET /json HTTP/1.1\r\nHost: ipinfo.io\r\nAccept: application/json\r\nConnection: close\r\n\r\n")
	resp, e := http.ReadResponse(bufioNew(conn), &http.Request{Method: "GET"})
	if e != nil || resp.StatusCode != 200 {
		safeError(errors.New("probe response failed"))
		return 1
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if e != nil {
		safeError(e)
		return 1
	}
	var v map[string]any
	if json.Unmarshal(b, &v) != nil {
		fmt.Println("probe succeeded")
		return 0
	}
	safe := map[string]any{}
	for _, k := range []string{"country", "region", "city", "org"} {
		if val, ok := v[k]; ok {
			safe[k] = val
		}
	}
	printJSON(safe)
	return 0
}

type readerConn struct{ net.Conn }

func bufioNew(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }
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
	var servers []*pool.Server
	closeAll := func() {
		for i := len(servers) - 1; i >= 0; i-- {
			_ = servers[i].Close()
		}
	}
	defer closeAll()
	var eps []endpoint
	for _, n := range nodes {
		s := &pool.Server{Dialer: dial, Selector: pool.NewSelector([]serverlist.Node{n}, "rr"), Username: c.authUser, Password: c.authPass, AllowOpen: c.allowOpen}
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
	aggregate := &pool.Server{Dialer: dial, Selector: pool.NewSelector(nodes, c.rotateMode), Username: c.authUser, Password: c.authPass, AllowOpen: c.allowOpen}
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
	var udpSrv *pool.UDPServer
	var udpAddr string
	if len(masqueNodes) > 0 {
		udpSrv = pool.NewUDPServer(dial, masqueNodes)
		udpListen := net.JoinHostPort(c.bind, strconv.Itoa(c.udpBase))
		a, e := udpSrv.Listen(udpListen)
		if e != nil {
			safeError(e)
			return 1
		}
		udpAddr = a.String()
		defer func() { _ = udpSrv.Close() }()
	}
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
		if listJSON {
			type row struct {
				UID     string `json:"uid"`
				Email   string `json:"email"`
				Enabled bool   `json:"enabled"`
				Result  string `json:"refresh_result"`
				Label   string `json:"label"`
			}
			var rows []row
			for _, a := range accs {
				rs, _ := db.GetRefreshState(ctx, a.ID)
				rows = append(rows, row{a.UID, a.Email, a.Enabled, rs.Result, a.Label})
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
			fmt.Printf("uid=%-32s %s  state=%-20s %s\n", a.UID, enabled, rs.Result, ttl)
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
func printJSON(v any)   { b, _ := json.MarshalIndent(v, "", "  "); fmt.Println(string(b)) }

var _ = url.QueryEscape
