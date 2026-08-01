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

	"fxpool-proxy/internal/fxaexport"
	"fxpool-proxy/internal/pool"
	"fxpool-proxy/internal/securefile"
	"fxpool-proxy/internal/serverlist"
	"fxpool-proxy/internal/token"
	"fxpool-proxy/internal/upstream"
)

// version is replaced from the release tag at build time with -ldflags.
var version = "dev"

type config struct {
	root, guardian, serverURL, proxyPass, fxaToken, bind, advertise, rotator, httpRotator, rotateMode, countries, country, authUser, authPass, firefoxVersion, clientCountry string
	socksBase, httpBase, limit                                                                                                                                               int
	forceSync, allowNoToken, noSocks, noHTTP, requireAuth, allowOpen, includeLocked, recommended                                                                             bool
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
	f.StringVar(&c.proxyPass, "proxy-pass-jwt", env("PROXY_PASS_JWT", ""), "explicit ProxyPass JWT")
	f.StringVar(&c.fxaToken, "fxa-token", env("FXA_TOKEN", ""), "temporary FxA OAuth access token")
	f.StringVar(&c.bind, "bind", env("BIND", "127.0.0.1"), "listen address")
	f.StringVar(&c.advertise, "advertise-host", env("ADVERTISE_HOST", ""), "exported host")
	f.IntVar(&c.socksBase, "socks-base", 21000, "first per-node SOCKS port")
	f.IntVar(&c.httpBase, "http-base", 31000, "first per-node HTTP port")
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
	f.BoolVar(&c.includeLocked, "include-locked", false, "include locked records diagnostically")
	f.BoolVar(&c.recommended, "recommended", false, "use REC records only")
	return f, c
}
func main() { os.Exit(run(os.Args[1:])) }
func run(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: fxpool-proxy <sync|token-status|token-refresh|usage|how-to-token|probe|run|export-credentials|import-credentials>")
		return 2
	}
	cmd := argv[0]
	f, c := flagsFor(cmd)
	force := false
	deleteSource, noVerify := false, false
	bundle := ""
	exportOut, exportProfile, exportFirefoxDir := "fxa-renewal-credentials.json", "", ""
	exportList, exportImport, exportStdout := false, false, false
	if cmd == "token-refresh" {
		f.BoolVar(&force, "force", false, "force refresh")
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
	if cmd == "import-credentials" && len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		bundle = args[0]
		args = args[1:]
	}
	if e := f.Parse(args); e != nil {
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
		return cmdRefresh(c, force)
	case "usage":
		return cmdUsage(c)
	case "how-to-token":
		guide()
		return 0
	case "probe":
		return cmdProbe(c)
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
	m.ExplicitProxyPass = strings.TrimSpace(c.proxyPass)
	m.AccessToken = strings.TrimSpace(c.fxaToken)
	return m
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
func cmdRefresh(c *config, force bool) int {
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
	u, e := manager(c).Usage(context.Background())
	if e != nil {
		safeError(e)
		return 1
	}
	printJSON(u)
	return 0
}
func guide() {
	fmt.Print("Firefox 桌面凭据导出/导入\n\n1. 在本机 Firefox 登录 Firefox Account，启用 IP Protection，并完成设备注册。\n2. 在本机运行：fxpool-proxy export-credentials\n   程序会自动读取配置目录中的 signedInUser.json，写出最小续期凭据包。\n3. 同机可直接：fxpool-proxy export-credentials --import\n   或把凭据包拷到 VPS 后：fxpool-proxy import-credentials /path/to/file --delete-source\n4. 用 fxpool-proxy token-status 检查续期状态。\n\n完整步骤见 README.md；凭据包等同登录会话，不要分享。\n")
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
		if n.Supported && !n.Locked && n.Country != "REC" && (c.country == "" || strings.EqualFold(c.country, n.Country)) {
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
	if len(nodes) == 0 {
		safeError(errors.New("no usable nodes selected"))
		return 1
	}
	m := manager(c)
	if _, e = m.Ensure(context.Background(), false); e != nil && !c.allowNoToken {
		safeError(e)
		return 1
	}
	dial := &upstream.Dialer{Tokens: m}
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
	if e = export(c, eps); e != nil {
		safeError(e)
		return 1
	}
	fmt.Printf("[*] pool running: nodes=%d (credentials omitted)\n", len(eps))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go refreshLoop(ctx, m)
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
	if deleteSource && path != "-" {
		if e = os.Remove(path); e != nil {
			safeError(errors.New("verified but source could not be deleted"))
			return 1
		}
	}
	fmt.Println("[+] Firefox renewal credentials imported successfully")
	return 0
}
func safeError(e error) { fmt.Fprintf(os.Stderr, "[!] %s\n", e.Error()) }
func printJSON(v any)   { b, _ := json.MarshalIndent(v, "", "  "); fmt.Println(string(b)) }

var _ = url.QueryEscape
