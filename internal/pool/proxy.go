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
	"time"
)

const MaxBody = 8 << 20

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
	UDPRelay   *UDPServer
	listeners  []net.Listener
	connections map[net.Conn]struct{}
	connMu     sync.Mutex
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
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
			s.connMu.Lock()
			if s.connections == nil {
				s.connections = map[net.Conn]struct{}{}
			}
			s.connections[c] = struct{}{}
			s.connMu.Unlock()
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
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
		_, _ = c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	_ = c.SetDeadline(time.Time{})
	relay(c, up)
}
func (s *Server) open(host string, port int) (net.Conn, error) {
	excluded := map[string]bool{}
	var last error
	for i := 0; i < 3; i++ {
		n, e := s.Selector.Choose(excluded)
		if e != nil {
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
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	<-done
}
func (s *Server) handleHTTP(c net.Conn) {
	br := bufio.NewReaderSize(c, 64<<10)
	req, e := http.ReadRequest(br)
	if e != nil {
		return
	}
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
		writeHTTP(c, 502, "upstream unavailable")
		return
	}
	defer up.Close()
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	relay(c, up)
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
	_, _ = io.Copy(c, up)
}
func writeHTTP(w io.Writer, status int, msg string) {
	body := msg + "\n"
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), len(body), body)
}

var _ = url.URL{}
