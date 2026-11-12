package pool

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"fxpool-proxy/internal/serverlist"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const MaxBody = 8 << 20

// defaultDrainTimeout bounds how long a relay waits for the opposite direction
// to finish after one side reaches EOF, as long as no data moves.
const defaultDrainTimeout = 5 * time.Second

type TunnelDialer interface {
	Open(context.Context, serverlist.Node, string, int) (net.Conn, error)
}
type Server struct {
	Dialer             TunnelDialer
	Selector           *Selector
	Username, Password string
	AllowOpen          bool
	// UDPRelay, when set, allows this SOCKS5 server to handle UDP ASSOCIATE
	// (CMD=3) by telling the client the relay address and registering its IP
	// as authorized. Without this, CMD=3 returns "command not supported".
	UDPRelay *UDPServer
	// IdleTimeout bounds how long a relayed TCP connection may stay silent in
	// both directions. Zero disables idle reclamation. The timer is shared by
	// both directions so an active upload is not mistaken for an idle link.
	IdleTimeout time.Duration
	// DrainTimeout bounds how long relay waits for the remaining direction
	// after one side reaches EOF. Zero uses defaultDrainTimeout; a negative
	// value closes both sides immediately.
	DrainTimeout time.Duration
	// MaxConns caps concurrent client connections across every listener of
	// this Server. Zero means unlimited. Excess connections are closed as soon
	// as they are accepted, before any protocol bytes are read.
	MaxConns int
	// Logf, when set, receives diagnostic messages for failed CONNECTs.
	Logf        func(format string, args ...any)
	listeners   []net.Listener
	connections map[net.Conn]struct{}
	connMu      sync.Mutex
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
	active      atomic.Int64
}

func (s *Server) StartSOCKS(addr string) (net.Addr, error) { return s.start(addr, s.handleSOCKS) }
func (s *Server) StartHTTP(addr string) (net.Addr, error)  { return s.start(addr, s.handleHTTP) }
func (s *Server) start(addr string, handler func(net.Conn)) (net.Addr, error) {
	if s.ctx == nil {
		s.ctx, s.cancel = context.WithCancel(context.Background())
	}
	l, e := net.Listen("tcp", addr)
	if e != nil {
		return nil, e
	}
	s.listeners = append(s.listeners, l)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			n := s.active.Add(1)
			if s.MaxConns > 0 && n > int64(s.MaxConns) {
				s.active.Add(-1)
				_ = c.Close()
				continue
			}
			s.connMu.Lock()
			if s.connections == nil {
				s.connections = map[net.Conn]struct{}{}
			}
			s.connections[c] = struct{}{}
			s.connMu.Unlock()
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer s.active.Add(-1)
				defer c.Close()
				defer func() { s.connMu.Lock(); delete(s.connections, c); s.connMu.Unlock() }()
				handler(c)
			}()
		}
	}()
	return l.Addr(), nil
}
func (s *Server) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	for _, l := range s.listeners {
		_ = l.Close()
	}
	s.connMu.Lock()
	for c := range s.connections {
		_ = c.Close()
	}
	s.connMu.Unlock()
	s.wg.Wait()
	return nil
}
func readExact(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	_, e := io.ReadFull(r, b)
	return b, e
}
func (s *Server) authorized(user, pass string) bool {
	return s.Username == "" && s.Password == "" || user == s.Username && pass == s.Password
}
func (s *Server) handleSOCKS(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	h, e := readExact(c, 2)
	if e != nil || h[0] != 5 {
		return
	}
	methods, e := readExact(c, int(h[1]))
	if e != nil {
		return
	}
	method := byte(0)
	if s.Username != "" || s.Password != "" {
		method = 2
	}
	found := false
	for _, m := range methods {
		if m == method {
			found = true
		}
	}
	if !found {
		_, _ = c.Write([]byte{5, 255})
		return
	}
	_, _ = c.Write([]byte{5, method})
	if method == 2 {
		v, e := readExact(c, 2)
		if e != nil || v[0] != 1 {
			return
		}
		u, e := readExact(c, int(v[1]))
		if e != nil {
			return
		}
		pl, e := readExact(c, 1)
		if e != nil {
			return
		}
		p, e := readExact(c, int(pl[0]))
		if e != nil {
			return
		}
		if !s.authorized(string(u), string(p)) {
			_, _ = c.Write([]byte{1, 1})
			return
		}
		_, _ = c.Write([]byte{1, 0})
	}
	r, e := readExact(c, 4)
	if e != nil || r[0] != 5 {
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	cmd := r[1]
	if cmd != 1 && !(cmd == 3 && s.UDPRelay != nil) {
		// CMD=1 (CONNECT) is always supported; CMD=3 (UDP ASSOCIATE) requires
		// a configured UDPRelay. All other commands are unsupported.
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch r[3] {
	case 1:
		b, e := readExact(c, 4)
		if e != nil {
			return
		}
		host = net.IP(b).String()
	case 4:
		b, e := readExact(c, 16)
		if e != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		n, e := readExact(c, 1)
		if e != nil || n[0] == 0 {
			return
		}
		b, e := readExact(c, int(n[0]))
		if e != nil {
			return
		}
		host = string(b)
	default:
		_, _ = c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	pb, e := readExact(c, 2)
	if e != nil {
		return
	}
	port := int(pb[0])<<8 | int(pb[1])
	if cmd == 3 {
		// UDP ASSOCIATE: register this client's IP as authorized and tell it
		// the relay's listen address. The TCP control connection is held open
		// until the client closes it; when it closes we have no reliable way to
		// de-register the IP (another session from the same host may still be
		// active) so we keep it registered for the lifetime of the process.
		relayAddr := s.UDPRelay.conn.LocalAddr()
		bindIP, bindPort, _ := net.SplitHostPort(relayAddr.String())
		bp, _ := strconv.Atoi(bindPort)
		// Send the bind address back to the client in the SOCKS5 reply frame.
		var reply []byte
		if ip4 := net.ParseIP(bindIP).To4(); ip4 != nil {
			reply = []byte{5, 0, 0, 1, ip4[0], ip4[1], ip4[2], ip4[3], byte(bp >> 8), byte(bp)}
		} else {
			// IPv6 — encode as ATYP=4.
			ip6 := net.ParseIP(bindIP).To16()
			reply = append([]byte{5, 0, 0, 4}, ip6...)
			reply = append(reply, byte(bp>>8), byte(bp))
		}
		s.UDPRelay.AllowClient(c.RemoteAddr())
		_, _ = c.Write(reply)
		// Hold the TCP control connection open. The client will close it when
		// it is done with the UDP association; until then we block here.
		_ = c.SetDeadline(time.Time{})
		buf := make([]byte, 1)
		_, _ = c.Read(buf) // blocks until client closes the connection
		return
	}
	up, e := s.open(host, port)
	if e != nil {
		s.logf("socks connect %s:%d failed: %v", host, port, e)
		_, _ = c.Write([]byte{5, socksReply(e), 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	_ = c.SetDeadline(time.Time{})
	s.relay(c, up)
}
func (s *Server) open(host string, port int) (net.Conn, error) {
	excluded := map[string]bool{}
	var last error
	for range 3 {
		n, e := s.Selector.Choose(excluded)
		if e != nil {
			if last != nil {
				break
			}
			return nil, e
		}
		excluded[n.StableID()] = true
		up, e := s.Dialer.Open(s.ctx, n, host, port)
		if e == nil {
			return up, nil
		}
		last = e
	}
	return nil, last
}
func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// upstreamStatusError is implemented by dialer errors that carry the HTTP
// status of a failed upstream CONNECT. Declared locally to keep pool free of
// an upstream import.
type upstreamStatusError interface{ UpstreamStatus() int }

// socksReply maps a tunnel failure to a SOCKS5 CONNECT reply code.
func socksReply(err error) byte {
	var se upstreamStatusError
	if errors.As(err, &se) {
		switch se.UpstreamStatus() {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusProxyAuthRequired:
			return 0x02 // connection not allowed by ruleset
		}
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() || errors.Is(err, syscall.ETIMEDOUT) {
		return 0x06 // TTL expired / timeout
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return 0x05 // connection refused
	}
	if errors.Is(err, syscall.ENETUNREACH) {
		return 0x03 // network unreachable
	}
	var dns *net.DNSError
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.As(err, &dns) {
		return 0x04 // host unreachable
	}
	return 0x01 // general failure
}

// idleTracker records the last moment either direction moved bytes. It backs
// both idle reclamation and the activity-based drain check.
type idleTracker struct {
	last atomic.Int64
	idle time.Duration
	a, b net.Conn
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

func newIdleTracker(a, b net.Conn, idle time.Duration) *idleTracker {
	t := &idleTracker{idle: idle, a: a, b: b, stop: make(chan struct{}), done: make(chan struct{})}
	t.touch()
	if idle > 0 {
		go t.run()
	}
	return t
}
func (t *idleTracker) touch() { t.last.Store(time.Now().UnixNano()) }
func (t *idleTracker) idleFor() time.Duration {
	return time.Since(time.Unix(0, t.last.Load()))
}
func (t *idleTracker) run() {
	defer close(t.done)
	every := t.idle / 2
	if every < 10*time.Millisecond {
		every = 10 * time.Millisecond
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-ticker.C:
			if t.idleFor() > t.idle {
				_ = t.a.Close()
				_ = t.b.Close()
				return
			}
		}
	}
}
func (t *idleTracker) close() {
	if t.idle <= 0 {
		return
	}
	t.once.Do(func() { close(t.stop) })
	<-t.done
}

type trackedConn struct {
	net.Conn
	t *idleTracker
}

func (c *trackedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.t.touch()
	}
	return n, err
}
func (c *trackedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.t.touch()
	}
	return n, err
}
func (c *trackedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// relay copies both directions, propagating half-closes, and waits for both
// directions to finish so the caller's deferred Close cannot truncate the
// response that is still in flight.
func relay(a, b net.Conn, idle, drain time.Duration) {
	t := newIdleTracker(a, b, idle)
	defer t.close()
	ta, tb := &trackedConn{Conn: a, t: t}, &trackedConn{Conn: b, t: t}
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyOne(ta, tb)
	go copyOne(tb, ta)
	<-done
	if drain <= 0 {
		_ = a.Close()
		_ = b.Close()
		<-done
		return
	}
	every := drain / 4
	if every < 10*time.Millisecond {
		every = 10 * time.Millisecond
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			// The drain timer measures inactivity, not wall clock: a large
			// response that keeps writing refreshes t.last and is never cut.
			if t.idleFor() > drain {
				_ = a.Close()
				_ = b.Close()
				<-done
				return
			}
		}
	}
}

// relayOneWay copies src to dst with the same shared-idle semantics as relay,
// but does not wait for traffic in the opposite direction.
func relayOneWay(dst, src net.Conn, idle time.Duration) {
	if idle <= 0 {
		_, _ = io.Copy(dst, src)
		return
	}
	t := newIdleTracker(dst, src, idle)
	defer t.close()
	_, _ = io.Copy(&trackedConn{Conn: dst, t: t}, &trackedConn{Conn: src, t: t})
}

func (s *Server) relay(a, b net.Conn) {
	drain := s.DrainTimeout
	if drain == 0 {
		drain = defaultDrainTimeout
	}
	relay(a, b, s.IdleTimeout, drain)
}
func (s *Server) handleHTTP(c net.Conn) {
	// Bound only the request-line/header parse. The request body and the
	// tunneled stream must not inherit an absolute deadline.
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReaderSize(c, 64<<10)
	req, e := http.ReadRequest(br)
	if e != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	if !s.httpAuth(req) {
		writeHTTP(c, 407, "proxy authentication required")
		return
	}
	if req.Method == http.MethodConnect {
		s.handleConnect(c, req)
		return
	}
	s.handleForward(c, req)
}
func (s *Server) httpAuth(r *http.Request) bool {
	if s.Username == "" && s.Password == "" {
		return true
	}
	raw := r.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(raw, "Basic ") {
		return false
	}
	b, e := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(raw, "Basic ")))
	if e != nil {
		return false
	}
	u, p, ok := strings.Cut(string(b), ":")
	return ok && s.authorized(u, p)
}
func parseAuthority(v string, def int) (string, int, error) {
	if strings.ContainsAny(v, "\r\n\x00/@?#") {
		return "", 0, errors.New("invalid authority")
	}
	h, p, e := net.SplitHostPort(v)
	if e != nil {
		if !strings.Contains(v, ":") && def > 0 {
			return v, def, nil
		}
		return "", 0, e
	}
	n, e := strconv.Atoi(p)
	if e != nil || n < 1 || n > 65535 {
		return "", 0, errors.New("invalid port")
	}
	return h, n, nil
}
func (s *Server) handleConnect(c net.Conn, r *http.Request) {
	host, port, e := parseAuthority(r.Host, 443)
	if e != nil {
		writeHTTP(c, 400, "bad CONNECT authority")
		return
	}
	up, e := s.open(host, port)
	if e != nil {
		s.logf("http connect %s failed: %v", r.Host, e)
		writeHTTP(c, 502, "upstream unavailable")
		return
	}
	defer up.Close()
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = c.SetDeadline(time.Time{})
	s.relay(c, up)
}

var hop = map[string]bool{"connection": true, "keep-alive": true, "proxy-authenticate": true, "proxy-authorization": true, "proxy-connection": true, "te": true, "trailer": true, "transfer-encoding": true, "upgrade": true}

func (s *Server) handleForward(c net.Conn, r *http.Request) {
	if r.URL == nil || r.URL.Scheme != "http" || r.URL.Host == "" || r.URL.User != nil {
		writeHTTP(c, 400, "only absolute-form http URLs are supported")
		return
	}
	if len(r.TransferEncoding) > 0 {
		writeHTTP(c, 501, "Transfer-Encoding is not supported")
		return
	}
	if r.ContentLength < 0 || r.ContentLength > MaxBody {
		writeHTTP(c, 413, "invalid Content-Length")
		return
	}
	body, e := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if e != nil || int64(len(body)) != r.ContentLength {
		writeHTTP(c, 400, "invalid request body")
		return
	}
	host := r.URL.Hostname()
	port := r.URL.Port()
	pn := 80
	if port != "" {
		pn, e = strconv.Atoi(port)
		if e != nil {
			writeHTTP(c, 400, "invalid destination port")
			return
		}
	}
	up, e := s.open(host, pn)
	if e != nil {
		writeHTTP(c, 502, "upstream unavailable")
		return
	}
	defer up.Close()
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	if r.URL.RawQuery != "" {
		path += "?" + r.URL.RawQuery
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, "%s %s HTTP/1.1\r\nHost: %s\r\n", r.Method, path, r.URL.Host)
	for k, vals := range r.Header {
		if hop[strings.ToLower(k)] || strings.EqualFold(k, "Host") {
			continue
		}
		for _, v := range vals {
			fmt.Fprintf(&out, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(&out, "Connection: close\r\nContent-Length: %d\r\n\r\n", len(body))
	out.Write(body)
	if _, e = up.Write(out.Bytes()); e != nil {
		return
	}
	relayOneWay(c, up, s.IdleTimeout)
}
func writeHTTP(w io.Writer, status int, msg string) {
	body := msg + "\n"
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), len(body), body)
}

var _ = url.URL{}
