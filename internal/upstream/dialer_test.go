package upstream

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"fxpool-proxy/internal/serverlist"
)

// This captures the net/http ownership rule that caused successful CONNECT
// tunnels to be closed before a nested TLS handshake could begin.
func TestSuccessfulConnectBodyMustRemainOpen(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { _, _ = io.WriteString(server, "HTTP/1.1 200 Connection Established\r\n\r\nhello") }()
	resp, e := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodConnect})
	if e != nil {
		t.Fatal(e)
	}
	buf := make([]byte, 5)
	if _, e = io.ReadFull(resp.Body, buf); e != nil {
		t.Fatal(e)
	}
	if string(buf) != "hello" {
		t.Fatalf("got %q", buf)
	}
}

// bufferedConn must forward CloseWrite to the underlying TCP connection so a
// client half-close reaches the upstream tunnel instead of stopping at the
// buffered reader wrapper.
func TestBufferedConnCloseWrite(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	peers := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			peers <- nil
			return
		}
		peers <- c
	}()
	c, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	peer := <-peers
	if peer == nil {
		t.Fatal("accept failed")
	}
	defer peer.Close()

	bc := &bufferedConn{Conn: c, r: bufio.NewReader(c)}
	if e = bc.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, e = peer.Read(buf); e != io.EOF {
		t.Fatalf("peer read = %v, want EOF", e)
	}
}

// bufferedConn wrapping *tls.Conn must not send TLS close_notify on CloseWrite,
// so a client half-close does not tear down the outer HTTPS CONNECT tunnel
// before the upstream server finishes sending its response.
func TestBufferedConnTLSCloseWriteDoesNotBreakCONNECTResponse(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		// Wait briefly for the client's request + CloseWrite before replying.
		buf := make([]byte, 4)
		_, _ = io.ReadFull(conn, buf)
		time.Sleep(30 * time.Millisecond)
		_, _ = io.WriteString(conn, "pong")
	}))
	defer srv.Close()

	node := serverlist.Node{Hostname: "127.0.0.1", Port: portOf(t, srv.URL), Protocol: "connect", Scheme: "https", Supported: true}
	src := &fakeTokenSource{tokens: []string{"tok"}}
	d := &Dialer{Tokens: src, TLSConfig: &tls.Config{InsecureSkipVerify: true}}
	conn, e := d.Open(context.Background(), node, "example.com", 80)
	if e != nil {
		t.Fatalf("Open: %v", e)
	}
	defer conn.Close()

	if _, e = io.WriteString(conn, "ping"); e != nil {
		t.Fatal(e)
	}
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		if e = cw.CloseWrite(); e != nil {
			t.Fatal(e)
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, e := io.ReadAll(conn)
	if e != nil {
		t.Fatalf("ReadAll after CloseWrite: %v (got %q)", e, got)
	}
	if string(got) != "pong" {
		t.Fatalf("got %q, want %q", got, "pong")
	}
}

type fakeTokenSource struct {
	tokens    []string
	idx       int
	forceUsed bool
	rejected  []string
}

func (f *fakeTokenSource) Ensure(_ context.Context, force bool) (string, error) {
	if force {
		f.forceUsed = true
		if f.idx+1 < len(f.tokens) {
			f.idx++
		}
	}
	return f.tokens[f.idx], nil
}
func (f *fakeTokenSource) Reject(tok string) error { f.rejected = append(f.rejected, tok); return nil }

func connectTestServer(t *testing.T, status int, onOK func(net.Conn)) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "connect only", http.StatusMethodNotAllowed)
			return
		}
		h := w.(http.Hijacker)
		conn, _, err := h.Hijack()
		if err != nil {
			return
		}
		if status != http.StatusOK {
			_, _ = io.WriteString(conn, "HTTP/1.1 "+strconv.Itoa(status)+" Nope\r\n\r\n")
			conn.Close()
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		if onOK != nil {
			onOK(conn)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCONNECTAuthRefreshRetry(t *testing.T) {
	var attempts atomic.Int32
	var auths []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auths = append(auths, r.Header.Get("Proxy-Authorization"))
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		if attempts.Add(1) == 1 {
			_, _ = io.WriteString(conn, "HTTP/1.1 401 Unauthorized\r\n\r\n")
			conn.Close()
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\nhello")
	}))
	defer srv.Close()

	node := serverlist.Node{Hostname: "127.0.0.1", Port: portOf(t, srv.URL), Protocol: "connect", Scheme: "https", Supported: true}
	src := &fakeTokenSource{tokens: []string{"old", "new"}}
	d := &Dialer{Tokens: src, TLSConfig: &tls.Config{InsecureSkipVerify: true}}
	conn, e := d.Open(context.Background(), node, "example.com", 80)
	if e != nil {
		t.Fatalf("Open: %v", e)
	}
	defer conn.Close()
	if !src.forceUsed || len(src.rejected) != 1 || src.rejected[0] != "old" {
		t.Fatalf("force=%v rejected=%v", src.forceUsed, src.rejected)
	}
	if len(auths) != 2 || auths[0] != "Bearer old" || auths[1] != "Bearer new" {
		t.Fatalf("authorization headers = %v", auths)
	}
	buf := make([]byte, 5)
	if _, e = io.ReadFull(conn, buf); e != nil || string(buf) != "hello" {
		t.Fatalf("tunnel body = %q, %v", buf, e)
	}
}

func TestCONNECTNonAuthErrorDoesNotRefresh(t *testing.T) {
	srv := connectTestServer(t, http.StatusServiceUnavailable, nil)
	node := serverlist.Node{Hostname: "127.0.0.1", Port: portOf(t, srv.URL), Protocol: "connect", Scheme: "https", Supported: true}
	src := &fakeTokenSource{tokens: []string{"old", "new"}}
	d := &Dialer{Tokens: src, TLSConfig: &tls.Config{InsecureSkipVerify: true}}
	if _, e := d.Open(context.Background(), node, "example.com", 80); e == nil {
		t.Fatal("expected a CONNECT error")
	}
	if src.forceUsed || len(src.rejected) != 0 {
		t.Fatalf("force=%v rejected=%v, want no refresh", src.forceUsed, src.rejected)
	}
}

func portOf(t *testing.T, rawurl string) int {
	t.Helper()
	u, e := url.Parse(rawurl)
	if e != nil {
		t.Fatal(e)
	}
	p, e := strconv.Atoi(u.Port())
	if e != nil {
		t.Fatal(e)
	}
	return p
}
