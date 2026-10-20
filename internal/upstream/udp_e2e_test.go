package upstream

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"fxpool-proxy/internal/pool"
	"fxpool-proxy/internal/serverlist"
)

// TestUDPServerEndToEndMASQUE wires a real in-process MASQUE proxy, a real
// upstream.Dialer, and a pool.UDPServer together. Two UDP clients send SOCKS5
// UDP ASSOCIATE datagrams to the same echo target; each client must receive
// only its own reply. This exercises the full chain: SOCKS5 framing, per
// (client, destination) tunnel isolation, MASQUE CONNECT-UDP, and reply
// routing back to the originating client.
func TestUDPServerEndToEndMASQUE(t *testing.T) {
	tmpl, closeProxy := startMASQUEProxy(t)
	defer closeProxy()

	// Local UDP echo target: echoes every datagram back to its sender.
	echoTarget, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer echoTarget.Close()
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, addr, err := echoTarget.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = echoTarget.WriteTo(buf[:n], addr)
		}
	}()
	targetPort := echoTarget.LocalAddr().(*net.UDPAddr).Port

	d := &Dialer{
		Tokens: stubToken{},
		MasqueTLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{http3.NextProtoH3},
		},
	}
	node := serverlist.Node{
		Protocol:       "masque",
		Scheme:         "https",
		Supported:      true,
		TemplateString: tmpl,
	}

	srv := pool.NewUDPServer(d, []serverlist.Node{node})
	a, e := srv.Listen("127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer srv.Close()
	udpAddr := a.(*net.UDPAddr)

	// SOCKS5 UDP frame: RSV(2) FRAG(1) ATYP=1(IPv4) DST.ADDR(4) DST.PORT(2) DATA.
	// 127.0.0.1 is used so the MASQUE proxy (also local) can reach the echo target.
	makeFrame := func(payload string) []byte {
		frame := []byte{0, 0, 0, 1}
		frame = append(frame, net.IPv4(127, 0, 0, 1).To4()...)
		frame = append(frame, byte(targetPort>>8), byte(targetPort))
		return append(frame, payload...)
	}

	cli1, e := net.DialUDP("udp4", nil, udpAddr)
	if e != nil {
		t.Fatal(e)
	}
	defer cli1.Close()
	cli2, e := net.DialUDP("udp4", nil, udpAddr)
	if e != nil {
		t.Fatal(e)
	}
	defer cli2.Close()
	// Register both client IPs — simulates a successful SOCKS5 UDP ASSOCIATE
	// handshake that a real SOCKS5 server would perform before accepting UDP.
	srv.AllowClient(cli1.LocalAddr())
	srv.AllowClient(cli2.LocalAddr())

	// Both clients send to the same destination; each must get its own tunnel.
	if _, e = cli1.Write(makeFrame("e2e-client1")); e != nil {
		t.Fatal(e)
	}
	if _, e = cli2.Write(makeFrame("e2e-client2")); e != nil {
		t.Fatal(e)
	}

	readReply := func(cli *net.UDPConn, want string) {
		buf := make([]byte, 512)
		_ = cli.SetReadDeadline(time.Now().Add(8 * time.Second))
		n, _, err := cli.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read reply: %v", err)
		}
		// The reply is a SOCKS5 UDP frame; the echoed payload is at the end.
		if n < len(want) || string(buf[n-len(want):n]) != want {
			t.Fatalf("reply = %q, want suffix %q", string(buf[:n]), want)
		}
	}
	readReply(cli1, "e2e-client1")
	readReply(cli2, "e2e-client2")
}
