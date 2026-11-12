package pool

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"fxpool-proxy/internal/serverlist"
)

type fakeDialer func(context.Context, serverlist.Node, string, int) (net.Conn, error)

func (f fakeDialer) Open(ctx context.Context, n serverlist.Node, host string, port int) (net.Conn, error) {
	return f(ctx, n, host, port)
}

func testNode() serverlist.Node {
	return serverlist.Node{
		Country:   "US",
		Hostname:  "upstream.invalid",
		Port:      443,
		Protocol:  "connect",
		Scheme:    "https",
		Supported: true,
		RecordID:  "test-node",
	}
}

func startSocks(t *testing.T, s *Server) string {
	t.Helper()
	a, err := s.StartSOCKS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return a.String()
}

// socksRequest performs the no-auth greeting and one CONNECT request with an
// explicit ATYP/address, returning the SOCKS5 REP byte.
func socksRequest(t *testing.T, c net.Conn, atyp byte, addr []byte, port int) byte {
	t.Helper()
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(c, greeting); err != nil {
		t.Fatal(err)
	}
	if greeting[0] != 5 || greeting[1] != 0 {
		t.Fatalf("greeting = %v", greeting)
	}
	req := []byte{5, 1, 0, atyp}
	req = append(req, addr...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	return reply[1]
}

func connectIPv4(t *testing.T, c net.Conn, host string, port int) byte {
	t.Helper()
	return socksRequest(t, c, 1, net.ParseIP(host).To4(), port)
}

func dialTest(t *testing.T, addr string) *net.TCPConn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c.(*net.TCPConn)
}

func TestRelayHalfCloseDeliversResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type upstreamResult struct {
		request string
		err     error
	}
	upstream := make(chan upstreamResult, 1)
	go func() {
		up, err := ln.Accept()
		if err != nil {
			upstream <- upstreamResult{err: err}
			return
		}
		defer up.Close()
		b, err := io.ReadAll(up)
		if err != nil {
			upstream <- upstreamResult{err: err}
			return
		}
		// The sleep makes the pre-fix relay (which returns on the first EOF and
		// then closes both connections) lose this response deterministically.
		time.Sleep(100 * time.Millisecond)
		_, err = up.Write([]byte("pong"))
		upstream <- upstreamResult{request: string(b), err: err}
	}()

	s := &Server{
		Dialer: fakeDialer(func(context.Context, serverlist.Node, string, int) (net.Conn, error) {
			return net.Dial("tcp", ln.Addr().String())
		}),
		Selector: NewSelector([]serverlist.Node{testNode()}, "rr"),
	}
	addr := startSocks(t, s)
	c := dialTest(t, addr)
	if rep := connectIPv4(t, c, "203.0.113.7", 443); rep != 0 {
		t.Fatalf("CONNECT reply = %#x", rep)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(got) != "pong" {
		t.Fatalf("response = %q, want %q", got, "pong")
	}
	r := <-upstream
	if r.err != nil {
		t.Fatal(r.err)
	}
	if r.request != "ping" {
		t.Fatalf("upstream request = %q", r.request)
	}
}

func TestRelayDrainTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	hold := make(chan struct{})
	defer close(hold)
	go func() {
		up, err := ln.Accept()
		if err != nil {
			return
		}
		defer up.Close()
		_, _ = io.Copy(io.Discard, up)
		<-hold // never answer, never close on our own
	}()

	s := &Server{
		Dialer: fakeDialer(func(context.Context, serverlist.Node, string, int) (net.Conn, error) {
			return net.Dial("tcp", ln.Addr().String())
		}),
		Selector:     NewSelector([]serverlist.Node{testNode()}, "rr"),
		DrainTimeout: 100 * time.Millisecond,
	}
	addr := startSocks(t, s)
	c := dialTest(t, addr)
	if rep := connectIPv4(t, c, "203.0.113.7", 443); rep != 0 {
		t.Fatalf("CONNECT reply = %#x", rep)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, err := c.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("read = %v, want EOF", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("drain took %v", elapsed)
	}
}

func TestRelayDrainDoesNotTruncateActiveResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const blocks = 10
	go func() {
		up, err := ln.Accept()
		if err != nil {
			return
		}
		defer up.Close()
		_, _ = io.Copy(io.Discard, up)
		for range blocks {
			time.Sleep(50 * time.Millisecond)
			if _, err := up.Write([]byte("0123456789")); err != nil {
				return
			}
		}
	}()

	s := &Server{
		Dialer: fakeDialer(func(context.Context, serverlist.Node, string, int) (net.Conn, error) {
			return net.Dial("tcp", ln.Addr().String())
		}),
		Selector:     NewSelector([]serverlist.Node{testNode()}, "rr"),
		DrainTimeout: 100 * time.Millisecond,
	}
	addr := startSocks(t, s)
	c := dialTest(t, addr)
	if rep := connectIPv4(t, c, "203.0.113.7", 443); rep != 0 {
		t.Fatalf("CONNECT reply = %#x", rep)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if len(got) != blocks*10 {
		t.Fatalf("received %d bytes, want %d", len(got), blocks*10)
	}
}

func TestIdleTimeoutClosesConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	hold := make(chan struct{})
	defer close(hold)
	go func() {
		up, err := ln.Accept()
		if err != nil {
			return
		}
		defer up.Close()
		<-hold
	}()

	s := &Server{
		Dialer: fakeDialer(func(context.Context, serverlist.Node, string, int) (net.Conn, error) {
			return net.Dial("tcp", ln.Addr().String())
		}),
		Selector:    NewSelector([]serverlist.Node{testNode()}, "rr"),
		IdleTimeout: 100 * time.Millisecond,
	}
	addr := startSocks(t, s)
	c := dialTest(t, addr)
	if rep := connectIPv4(t, c, "203.0.113.7", 443); rep != 0 {
		t.Fatalf("CONNECT reply = %#x", rep)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, err := c.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("read = %v, want EOF after idle timeout", err)
	}
}

func TestIdleTimeoutKeepsActiveUpload(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		up, err := ln.Accept()
		if err != nil {
			return
		}
		defer up.Close()
		if _, err := io.Copy(io.Discard, up); err != nil {
			return
		}
		_, _ = up.Write([]byte("ok"))
	}()

	s := &Server{
		Dialer: fakeDialer(func(context.Context, serverlist.Node, string, int) (net.Conn, error) {
			return net.Dial("tcp", ln.Addr().String())
		}),
		Selector:    NewSelector([]serverlist.Node{testNode()}, "rr"),
		IdleTimeout: 300 * time.Millisecond,
	}
	addr := startSocks(t, s)
	c := dialTest(t, addr)
	if rep := connectIPv4(t, c, "203.0.113.7", 443); rep != 0 {
		t.Fatalf("CONNECT reply = %#x", rep)
	}
	for range 20 {
		if _, err := c.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(got) != "ok" {
		t.Fatalf("response = %q, want %q", got, "ok")
	}
}

func TestMaxConnsRejectsExcess(t *testing.T) {
	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	s := &Server{
		Dialer: fakeDialer(func(context.Context, serverlist.Node, string, int) (net.Conn, error) {
			return serverPipe, nil
		}),
		Selector:     NewSelector([]serverlist.Node{testNode()}, "rr"),
		MaxConns:     1,
		DrainTimeout: 100 * time.Millisecond,
	}
	addr := startSocks(t, s)
	first := dialTest(t, addr)
	if rep := connectIPv4(t, first, "203.0.113.7", 443); rep != 0 {
		t.Fatalf("first CONNECT reply = %#x", rep)
	}

	second := dialTest(t, addr)
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	_, err := second.Read(buf)
	if !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("second connection read = %v, want EOF/reset", err)
	}
}

func TestSOCKSReplyMapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want byte
	}{
		{"upstream 403", &connectStatusError{status: 403}, 0x02},
		{"upstream 407", &connectStatusError{status: 407}, 0x02},
		{"upstream 429", &connectStatusError{status: 429}, 0x01},
		{"connection refused", os.NewSyscallError("connect", syscall.ECONNREFUSED), 0x05},
		{"dns", &net.DNSError{Err: "no such host", Name: "example.invalid"}, 0x04},
		{"deadline", context.DeadlineExceeded, 0x06},
		{"network unreachable", os.NewSyscallError("connect", syscall.ENETUNREACH), 0x03},
		{"host unreachable", os.NewSyscallError("connect", syscall.EHOSTUNREACH), 0x04},
		{"generic", errors.New("x"), 0x01},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := socksReply(tt.err); got != tt.want {
				t.Fatalf("socksReply = %#x, want %#x", got, tt.want)
			}
		})
	}
}

type connectStatusError struct{ status int }

func (e *connectStatusError) Error() string       { return "upstream CONNECT failed" }
func (e *connectStatusError) UpstreamStatus() int { return e.status }

func TestSOCKSConnectErrorReply(t *testing.T) {
	s := &Server{
		Dialer: fakeDialer(func(context.Context, serverlist.Node, string, int) (net.Conn, error) {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
		}),
		Selector: NewSelector([]serverlist.Node{testNode()}, "rr"),
	}
	addr := startSocks(t, s)
	c := dialTest(t, addr)
	if rep := connectIPv4(t, c, "203.0.113.7", 443); rep != 0x05 {
		t.Fatalf("CONNECT reply = %#x, want 0x05", rep)
	}
}

func TestSOCKSUnsupportedAddrType(t *testing.T) {
	s := &Server{
		Dialer: fakeDialer(func(context.Context, serverlist.Node, string, int) (net.Conn, error) {
			return nil, errors.New("must not be dialed")
		}),
		Selector: NewSelector([]serverlist.Node{testNode()}, "rr"),
	}
	addr := startSocks(t, s)
	c := dialTest(t, addr)
	if rep := socksRequest(t, c, 2, []byte{0, 0, 0, 0}, 80); rep != 0x08 {
		t.Fatalf("CONNECT reply = %#x, want 0x08", rep)
	}
}

func TestSOCKS5UDPAssociateAuthorizesClient(t *testing.T) {
	pc := newFakePacketConn()
	udpSrv := NewUDPServer(&fakeUDPDialer{pc: pc}, []serverlist.Node{{Protocol: "masque", Supported: true}})
	udpAddr, e := udpSrv.Listen("127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer udpSrv.Close()

	s := &Server{
		Dialer: fakeDialer(func(context.Context, serverlist.Node, string, int) (net.Conn, error) {
			return nil, errors.New("unused")
		}),
		Selector: NewSelector([]serverlist.Node{testNode()}, "rr"),
		UDPRelay: udpSrv,
	}
	addr := startSocks(t, s)
	c := dialTest(t, addr)
	if _, e = c.Write([]byte{5, 1, 0}); e != nil {
		t.Fatal(e)
	}
	auth := make([]byte, 2)
	if _, e = io.ReadFull(c, auth); e != nil || auth[1] != 0 {
		t.Fatalf("auth = %v, %v", auth, e)
	}
	// CMD=3 (UDP ASSOCIATE), ATYP=1, 0.0.0.0:0
	if _, e = c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); e != nil {
		t.Fatal(e)
	}
	rep := make([]byte, 10)
	if _, e = io.ReadFull(c, rep); e != nil {
		t.Fatal(e)
	}
	if rep[1] != 0 {
		t.Fatalf("UDP ASSOCIATE reply = %#x, want 0x00", rep[1])
	}
	gotPort := int(rep[8])<<8 | int(rep[9])
	wantPort := udpAddr.(*net.UDPAddr).Port
	if gotPort != wantPort {
		t.Fatalf("bound UDP port = %d, want %d", gotPort, wantPort)
	}

	ucli, e := net.DialUDP("udp4", nil, udpAddr.(*net.UDPAddr))
	if e != nil {
		t.Fatal(e)
	}
	defer ucli.Close()
	if _, e = ucli.Write(udpFrame(443, "assoc-ok")); e != nil {
		t.Fatal(e)
	}
	if !waitFor(t, 2*time.Second, func() bool { return string(pc.lastPayload()) == "assoc-ok" }) {
		t.Fatalf("tunnel payload = %q, want %q", pc.lastPayload(), "assoc-ok")
	}
}
