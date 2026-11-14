package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"fxpool-proxy/internal/serverlist"
)

type accountAwareTokenSource struct {
	mu       sync.Mutex
	token    string
	account  string
	rejected []string
	onForce  func() (string, string, error)
}

func (s *accountAwareTokenSource) Ensure(ctx context.Context, force bool) (string, error) {
	tok, _, err := s.EnsureAccount(ctx, force)
	return tok, err
}

func (s *accountAwareTokenSource) EnsureAccount(_ context.Context, force bool) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if force && s.onForce != nil {
		tok, acc, err := s.onForce()
		if err != nil {
			return "", "", err
		}
		s.token = tok
		s.account = acc
	}
	return s.token, s.account, nil
}

func (s *accountAwareTokenSource) Reject(tok string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rejected = append(s.rejected, tok)
	return nil
}

func (s *accountAwareTokenSource) set(tok, acc string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = tok
	s.account = acc
}

func startH2ConnectServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var newConns atomic.Int32
	srv := httptest.NewUnstartedServer(handler)
	srv.EnableHTTP2 = true
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			newConns.Add(1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &newConns
}

func h2EchoConnectHandler(authLog *[]string, authMu *sync.Mutex) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "connect only", http.StatusMethodNotAllowed)
			return
		}
		if authLog != nil {
			authMu.Lock()
			*authLog = append(*authLog, r.Header.Get("Proxy-Authorization"))
			authMu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		buf := make([]byte, 4096)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
			if err != nil {
				return
			}
		}
	}
}

func TestH2SessionReuseAndHalfClose(t *testing.T) {
	var authMu sync.Mutex
	var auths []string
	srv, newConns := startH2ConnectServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "connect only", http.StatusMethodNotAllowed)
			return
		}
		authMu.Lock()
		auths = append(auths, r.Header.Get("Proxy-Authorization"))
		authMu.Unlock()
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		reqBytes, _ := io.ReadAll(r.Body)
		time.Sleep(20 * time.Millisecond)
		_, _ = w.Write(append([]byte("echo:"), reqBytes...))
	})

	node := serverlist.Node{Hostname: "127.0.0.1", Port: portOf(t, srv.URL), Protocol: "connect", Scheme: "https", Supported: true}
	src := &accountAwareTokenSource{token: "tok-1", account: "acct-1"}
	d := &Dialer{
		Tokens:            src,
		TLSConfig:         &tls.Config{InsecureSkipVerify: true},
		UpstreamTransport: TransportH2,
		KeepAliveInterval: -1,
	}
	defer d.Close()

	for i := range 3 {
		conn, err := d.Open(context.Background(), node, "example.com", 443)
		if err != nil {
			t.Fatalf("Open %d: %v", i, err)
		}
		if _, err := io.WriteString(conn, "ping"); err != nil {
			conn.Close()
			t.Fatalf("Write %d: %v", i, err)
		}
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			if err := cw.CloseWrite(); err != nil {
				conn.Close()
				t.Fatalf("CloseWrite %d: %v", i, err)
			}
		} else {
			conn.Close()
			t.Fatal("expected CloseWrite support on H2 stream conn")
		}
		got, err := io.ReadAll(conn)
		conn.Close()
		if err != nil {
			t.Fatalf("ReadAll %d: %v", i, err)
		}
		if string(got) != "echo:ping" {
			t.Fatalf("got %q, want %q", got, "echo:ping")
		}
	}

	if got := newConns.Load(); got != 1 {
		t.Fatalf("expected 1 reused TLS/H2 connection, got %d", got)
	}
	if len(auths) != 3 {
		t.Fatalf("expected 3 CONNECT requests, got %d", len(auths))
	}
}

func TestH2TokenRenewalUpdatesNewStreamsWithoutDroppingInFlight(t *testing.T) {
	var authMu sync.Mutex
	var auths []string
	srv, newConns := startH2ConnectServer(t, h2EchoConnectHandler(&auths, &authMu))

	node := serverlist.Node{Hostname: "127.0.0.1", Port: portOf(t, srv.URL), Protocol: "connect", Scheme: "https", Supported: true}
	src := &accountAwareTokenSource{token: "tok-old", account: "acct-1"}
	d := &Dialer{
		Tokens:            src,
		TLSConfig:         &tls.Config{InsecureSkipVerify: true},
		UpstreamTransport: TransportH2,
		KeepAliveInterval: -1,
	}
	defer d.Close()

	// Stream 1 stays open across token renewal.
	c1, err := d.Open(context.Background(), node, "example.com", 443)
	if err != nil {
		t.Fatalf("Open stream 1: %v", err)
	}
	defer c1.Close()

	// Rotate token in-place (simulating background ProxyPass renewal).
	src.set("tok-new", "acct-1")

	// Stream 2 should reuse the same H2 connection with the new token.
	c2, err := d.Open(context.Background(), node, "example.org", 443)
	if err != nil {
		t.Fatalf("Open stream 2: %v", err)
	}
	defer c2.Close()

	// In-flight stream 1 must still work uninterrupted.
	if _, err := io.WriteString(c1, "still-alive"); err != nil {
		t.Fatalf("write c1: %v", err)
	}
	buf := make([]byte, len("still-alive"))
	if _, err := io.ReadFull(c1, buf); err != nil {
		t.Fatalf("read c1: %v", err)
	}
	if string(buf) != "still-alive" {
		t.Fatalf("c1 echo = %q, want %q", buf, "still-alive")
	}

	if got := newConns.Load(); got != 1 {
		t.Fatalf("expected 1 H2 connection across token renewal, got %d", got)
	}
	authMu.Lock()
	defer authMu.Unlock()
	if len(auths) != 2 || auths[0] != "Bearer tok-old" || auths[1] != "Bearer tok-new" {
		t.Fatalf("Proxy-Authorization headers = %v", auths)
	}
}

func TestH2Auth401RefreshesTokenWithoutRebuildingSession(t *testing.T) {
	var authMu sync.Mutex
	var auths []string
	srv, newConns := startH2ConnectServer(t, func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Proxy-Authorization")
		authMu.Lock()
		auths = append(auths, auth)
		authMu.Unlock()
		if auth == "Bearer expired" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = io.WriteString(w, "ok")
	})

	node := serverlist.Node{Hostname: "127.0.0.1", Port: portOf(t, srv.URL), Protocol: "connect", Scheme: "https", Supported: true}
	src := &accountAwareTokenSource{
		token:   "expired",
		account: "acct-1",
		onForce: func() (string, string, error) {
			return "fresh", "acct-1", nil
		},
	}
	d := &Dialer{
		Tokens:            src,
		TLSConfig:         &tls.Config{InsecureSkipVerify: true},
		UpstreamTransport: TransportH2,
		KeepAliveInterval: -1,
	}
	defer d.Close()

	conn, err := d.Open(context.Background(), node, "example.com", 443)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer conn.Close()

	got, err := io.ReadAll(conn)
	if err != nil || string(got) != "ok" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	if gotConns := newConns.Load(); gotConns != 1 {
		t.Fatalf("expected 1 H2 connection (not rebuilt on 401), got %d", gotConns)
	}
	if len(src.rejected) != 1 || src.rejected[0] != "expired" {
		t.Fatalf("rejected = %v, want [expired]", src.rejected)
	}
	if len(auths) != 2 || auths[0] != "Bearer expired" || auths[1] != "Bearer fresh" {
		t.Fatalf("auths = %v", auths)
	}
}

func TestH2IsolatesSessionsPerAccount(t *testing.T) {
	srv, newConns := startH2ConnectServer(t, h2EchoConnectHandler(nil, nil))
	node := serverlist.Node{Hostname: "127.0.0.1", Port: portOf(t, srv.URL), Protocol: "connect", Scheme: "https", Supported: true}
	src := &accountAwareTokenSource{token: "tok-a", account: "acct-a"}
	d := &Dialer{
		Tokens:            src,
		TLSConfig:         &tls.Config{InsecureSkipVerify: true},
		UpstreamTransport: TransportH2,
		KeepAliveInterval: -1,
	}
	defer d.Close()

	c1, err := d.Open(context.Background(), node, "example.com", 443)
	if err != nil {
		t.Fatalf("Open acct-a: %v", err)
	}
	c1.Close()

	src.set("tok-b", "acct-b")
	c2, err := d.Open(context.Background(), node, "example.com", 443)
	if err != nil {
		t.Fatalf("Open acct-b: %v", err)
	}
	c2.Close()

	if got := newConns.Load(); got != 2 {
		t.Fatalf("expected 2 isolated H2 connections (one per account), got %d", got)
	}
}

func TestH2EvictsBrokenSessionAndRedials(t *testing.T) {
	var count atomic.Int32
	srv, newConns := startH2ConnectServer(t, func(w http.ResponseWriter, r *http.Request) {
		if count.Add(1) == 1 {
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			return
		}
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = io.WriteString(w, "recovered")
	})

	node := serverlist.Node{Hostname: "127.0.0.1", Port: portOf(t, srv.URL), Protocol: "connect", Scheme: "https", Supported: true}
	src := &accountAwareTokenSource{token: "tok", account: "acct-1"}
	d := &Dialer{
		Tokens:            src,
		TLSConfig:         &tls.Config{InsecureSkipVerify: true},
		UpstreamTransport: TransportH2,
		KeepAliveInterval: -1,
	}
	defer d.Close()

	c1, err := d.Open(context.Background(), node, "example.com", 443)
	if err != nil {
		t.Fatalf("Open 1: %v", err)
	}
	c1.Close()

	// Force-close the underlying H2 session on the client side to simulate a
	// dropped connection, then verify Open evicts and redials transparently.
	pool := d.getSessionPool()
	key := sessionKey{transport: TransportH2, nodeID: node.StableID(), accountKey: "acct-1"}
	pool.mu.Lock()
	ps := pool.sessions[key]
	pool.mu.Unlock()
	if ps == nil {
		t.Fatal("expected pooled session")
	}
	_ = ps.sess.close()

	c2, err := d.Open(context.Background(), node, "example.com", 443)
	if err != nil {
		t.Fatalf("Open 2 after drop: %v", err)
	}
	defer c2.Close()
	got, err := io.ReadAll(c2)
	if err != nil || string(got) != "recovered" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	if gotConns := newConns.Load(); gotConns != 2 {
		t.Fatalf("expected 2 connections after redial, got %d", gotConns)
	}
}

func TestH2ConcurrentColdStartCoalescesDial(t *testing.T) {
	srv, newConns := startH2ConnectServer(t, h2EchoConnectHandler(nil, nil))
	node := serverlist.Node{Hostname: "127.0.0.1", Port: portOf(t, srv.URL), Protocol: "connect", Scheme: "https", Supported: true}
	src := &accountAwareTokenSource{token: "tok", account: "acct-1"}
	d := &Dialer{
		Tokens:            src,
		TLSConfig:         &tls.Config{InsecureSkipVerify: true},
		UpstreamTransport: TransportH2,
		KeepAliveInterval: -1,
	}
	defer d.Close()

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := d.Open(context.Background(), node, "example.com", 443)
			if err != nil {
				errs <- err
				return
			}
			defer c.Close()
			if _, err := io.WriteString(c, "hi"); err != nil {
				errs <- err
				return
			}
			buf := make([]byte, 2)
			if _, err := io.ReadFull(c, buf); err != nil {
				errs <- err
				return
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if got := newConns.Load(); got != 1 {
		t.Fatalf("expected 1 coalesced TLS/H2 connection, got %d", got)
	}
}

func TestH2IdleReapAndMaxSessionsCap(t *testing.T) {
	srv, _ := startH2ConnectServer(t, h2EchoConnectHandler(nil, nil))
	port := portOf(t, srv.URL)
	src := &accountAwareTokenSource{token: "tok", account: "acct-1"}
	d := &Dialer{
		Tokens:            src,
		TLSConfig:         &tls.Config{InsecureSkipVerify: true},
		UpstreamTransport: TransportH2,
		SessionIdleTTL:    80 * time.Millisecond,
		MaxSessions:       2,
		KeepAliveInterval: -1,
	}
	defer d.Close()

	for _, acct := range []string{"a1", "a2", "a3"} {
		src.set("tok", acct)
		c, err := d.Open(context.Background(), serverlist.Node{Hostname: "127.0.0.1", Port: port, Protocol: "connect", Scheme: "https", Supported: true}, "example.com", 443)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}

	pool := d.getSessionPool()
	pool.mu.Lock()
	countAfterCap := len(pool.sessions)
	pool.mu.Unlock()
	if countAfterCap > 2 {
		t.Fatalf("expected <= 2 sessions due to MaxSessions cap, got %d", countAfterCap)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pool.mu.Lock()
		n := len(pool.sessions)
		pool.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("expected idle sessions to be reaped after SessionIdleTTL")
}

func TestH3SessionReuseAndTokenRenewal(t *testing.T) {
	tlsCfg := testTLSConfig(t)
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpConn.Close() })

	var authMu sync.Mutex
	var auths []string
	var remoteMu sync.Mutex
	remotes := map[string]struct{}{}

	h3Srv := &http3.Server{
		TLSConfig: tlsCfg,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				http.Error(w, "connect only", http.StatusMethodNotAllowed)
				return
			}
			authMu.Lock()
			auths = append(auths, r.Header.Get("Proxy-Authorization"))
			authMu.Unlock()
			remoteMu.Lock()
			remotes[r.RemoteAddr] = struct{}{}
			remoteMu.Unlock()

			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			buf := make([]byte, 4096)
			for {
				n, rerr := r.Body.Read(buf)
				if n > 0 {
					if _, werr := w.Write(buf[:n]); werr != nil {
						return
					}
					if f, ok := w.(http.Flusher); ok {
						f.Flush()
					}
				}
				if rerr != nil {
					return
				}
			}
		}),
	}
	tr := &quic.Transport{Conn: udpConn}
	ln, err := tr.ListenEarly(http3.ConfigureTLSConfig(tlsCfg), &quic.Config{InitialPacketSize: 1200})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = h3Srv.Close()
		_ = ln.Close()
		_ = tr.Close()
	})
	go func() { _ = h3Srv.ServeListener(ln) }()

	port := udpConn.LocalAddr().(*net.UDPAddr).Port
	node := serverlist.Node{Hostname: "127.0.0.1", Port: port, Protocol: "connect", Scheme: "https", Supported: true}
	src := &accountAwareTokenSource{token: "h3-old", account: "acct-h3"}
	d := &Dialer{
		Tokens:            src,
		TLSConfig:         &tls.Config{InsecureSkipVerify: true},
		UpstreamTransport: TransportH3,
		KeepAliveInterval: -1,
	}
	defer d.Close()

	c1, err := d.Open(context.Background(), node, "example.com", 443)
	if err != nil {
		t.Fatalf("H3 Open 1: %v", err)
	}
	defer c1.Close()

	// Rotate token in-place while c1 is open.
	src.set("h3-new", "acct-h3")

	c2, err := d.Open(context.Background(), node, "example.org", 443)
	if err != nil {
		t.Fatalf("H3 Open 2: %v", err)
	}
	defer c2.Close()

	if _, err := io.WriteString(c1, "ping-h3"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("ping-h3"))
	if _, err := io.ReadFull(c1, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping-h3" {
		t.Fatalf("c1 = %q, want ping-h3", buf)
	}

	if _, err := io.WriteString(c2, "half"); err != nil {
		t.Fatal(err)
	}
	if cw, ok := c2.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil {
			t.Fatalf("H3 CloseWrite: %v", err)
		}
	}
	got2, err := io.ReadAll(c2)
	if err != nil {
		t.Fatalf("H3 ReadAll after CloseWrite: %v", err)
	}
	if string(got2) != "half" {
		t.Fatalf("c2 = %q, want half", got2)
	}

	remoteMu.Lock()
	remoteCount := len(remotes)
	remoteMu.Unlock()
	if remoteCount != 1 {
		t.Fatalf("expected 1 reused QUIC/H3 connection (1 remote addr), got %d", remoteCount)
	}
	authMu.Lock()
	defer authMu.Unlock()
	if len(auths) != 2 || auths[0] != "Bearer h3-old" || auths[1] != "Bearer h3-new" {
		t.Fatalf("H3 Proxy-Authorization headers = %v", auths)
	}
}

func TestParseUpstreamTransport(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    UpstreamTransport
		wantErr bool
	}{
		{"", TransportH1, false},
		{"h1", TransportH1, false},
		{"H2", TransportH2, false},
		{"h3", TransportH3, false},
		{"quic", "", true},
	} {
		got, err := ParseUpstreamTransport(tc.in)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Fatalf("ParseUpstreamTransport(%q) = (%q, %v), want (%q, err=%v)", tc.in, got, err, tc.want, tc.wantErr)
		}
	}
}

var _ = errors.New
