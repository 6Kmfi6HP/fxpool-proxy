package pool

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"fxpool-proxy/internal/serverlist"
)

// fakePacketConn is an in-memory net.PacketConn used to stub a MASQUE tunnel.
type fakePacketConn struct {
	mu     sync.Mutex
	queue  [][]byte
	conns  chan []byte // datagrams the fake "target" emits
	closed chan struct{}
}

func newFakePacketConn() *fakePacketConn {
	return &fakePacketConn{conns: make(chan []byte, 16), closed: make(chan struct{})}
}
func (f *fakePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case d := <-f.conns:
		return copy(b, d), nil, nil
	case <-f.closed:
		return 0, nil, net.ErrClosed
	}
}
func (f *fakePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	f.mu.Lock()
	f.queue = append(f.queue, append([]byte(nil), p...))
	f.mu.Unlock()
	return len(p), nil
}
func (f *fakePacketConn) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}
func (f *fakePacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (f *fakePacketConn) RemoteAddr() net.Addr               { return &net.UDPAddr{} }
func (f *fakePacketConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakePacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakePacketConn) SetWriteDeadline(t time.Time) error { return nil }

func (f *fakePacketConn) lastPayload() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.queue) == 0 {
		return nil
	}
	return f.queue[len(f.queue)-1]
}

type fakeUDPDialer struct{ pc *fakePacketConn }

func (d *fakeUDPDialer) OpenUDP(ctx context.Context, n serverlist.Node, host string, port int) (net.PacketConn, error) {
	return d.pc, nil
}

// perClientUDPDialer returns a fresh fakePacketConn for each OpenUDP call so
// each (client, destination) pair gets its own tunnel. This models the real
// MASQUE dialer, which opens a new QUIC connection per call.
type perClientUDPDialer struct {
	mu   sync.Mutex
	conns []*fakePacketConn
}

func (d *perClientUDPDialer) OpenUDP(ctx context.Context, n serverlist.Node, host string, port int) (net.PacketConn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	pc := newFakePacketConn()
	d.conns = append(d.conns, pc)
	return pc, nil
}

func (d *perClientUDPDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.conns)
}

func (d *perClientUDPDialer) get(i int) *fakePacketConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.conns[i]
}

// TestUDPServerIsolatesTunnelsPerClient verifies that two clients sending to the
// same destination each get their own tunnel, and that replies are delivered
// only to the originating client (not cross-delivered).
func TestUDPServerIsolatesTunnelsPerClient(t *testing.T) {
	d := &perClientUDPDialer{}
	srv := NewUDPServer(d, []serverlist.Node{{Protocol: "masque", Supported: true}})
	a, e := srv.Listen("127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer srv.Close()
	udpAddr := a.(*net.UDPAddr)

	// Build a SOCKS5 UDP frame targeting port 53.
	makeFrame := func(payload string) []byte {
		frame := []byte{0, 0, 0, 3, 11}
		frame = append(frame, "dns.example"...)
		frame = append(frame, 0x00, 0x35) // port 53
		return append(frame, payload...)
	}

	cli1, e := net.DialUDP("udp4", nil, udpAddr)
	if e != nil {
		t.Fatal(e)
	}
	defer cli1.Close()
	srv.AllowClient(cli1.LocalAddr())

	cli2, e := net.DialUDP("udp4", nil, udpAddr)
	if e != nil {
		t.Fatal(e)
	}
	defer cli2.Close()
	srv.AllowClient(cli2.LocalAddr())

	// Client 1 sends first.
	if _, e = cli1.Write(makeFrame("from-client1")); e != nil {
		t.Fatal(e)
	}
	// Give the server time to open the first tunnel.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if d.count() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Client 2 sends to the same destination — must create a second tunnel.
	if _, e = cli2.Write(makeFrame("from-client2")); e != nil {
		t.Fatal(e)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if d.count() >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if d.count() != 2 {
		t.Fatalf("expected 2 independent tunnels, got %d", d.count())
	}

	// Send a reply on tunnel 0 — it must arrive only at client 1.
	d.get(0).conns <- []byte("reply-to-client1")
	buf := make([]byte, 512)
	_ = cli1.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := cli1.ReadFrom(buf)
	if err != nil {
		t.Fatalf("client1 read reply: %v", err)
	}
	if n < len("reply-to-client1") || string(buf[n-len("reply-to-client1"):n]) != "reply-to-client1" {
		t.Fatalf("client1 got wrong reply: %q", buf[:n])
	}

	// Send a reply on tunnel 1 — it must arrive only at client 2.
	d.get(1).conns <- []byte("reply-to-client2")
	_ = cli2.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = cli2.ReadFrom(buf)
	if err != nil {
		t.Fatalf("client2 read reply: %v", err)
	}
	if n < len("reply-to-client2") || string(buf[n-len("reply-to-client2"):n]) != "reply-to-client2" {
		t.Fatalf("client2 got wrong reply: %q", buf[:n])
	}
}
// verifies the payload is forwarded to the MASQUE tunnel and the reply is
// framed back to the client.
func TestUDPServerRelaysSOCKS5Frames(t *testing.T) {
	pc := newFakePacketConn()
	d := &fakeUDPDialer{pc: pc}
	srv := NewUDPServer(d, []serverlist.Node{{Protocol: "masque", Supported: true}})
	a, e := srv.Listen("127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer srv.Close()
	udpAddr := a.(*net.UDPAddr)

	// Build a SOCKS5 UDP frame: RSV FRAG ATYP=domain len "dns.example" PORT DATA
	frame := []byte{0, 0, 0, 3, 11}
	frame = append(frame, "dns.example"...) // 11 bytes
	frame = append(frame, 0x00, 0x35)       // port 53
	frame = append(frame, "hello-udp"...)

	cli, e := net.DialUDP("udp4", nil, udpAddr)
	if e != nil {
		t.Fatal(e)
	}
	defer cli.Close()
	// Register the client as authorized (simulates a successful SOCKS5 UDP
	// ASSOCIATE handshake) so its datagrams pass the auth check.
	srv.AllowClient(cli.LocalAddr())
	if _, e = cli.Write(frame); e != nil {
		t.Fatal(e)
	}

	// The fake tunnel's WriteTo should have received the payload.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pl := pc.lastPayload(); string(pl) == "hello-udp" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if string(pc.lastPayload()) != "hello-udp" {
		t.Fatalf("tunnel payload = %q, want %q", pc.lastPayload(), "hello-udp")
	}

	// Emit a reply from the "target" and verify it is framed back.
	pc.conns <- []byte("world-udp")
	buf := make([]byte, 512)
	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, e := cli.ReadFrom(buf)
	if e != nil {
		t.Fatalf("read reply: %v", e)
	}
	// Reply should be a SOCKS5 UDP frame: RSV FRAG ATYP=domain len ... DATA world-udp
	if n < 4 || string(buf[n-len("world-udp"):n]) != "world-udp" {
		t.Fatalf("framed reply = %q", string(buf[:n]))
	}
}
