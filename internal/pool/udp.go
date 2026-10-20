package pool

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"

	"fxpool-proxy/internal/serverlist"
)

// UDPDialer opens a datagram tunnel to a target host:port. MASQUE nodes provide
// this; CONNECT-only nodes do not (a TCP tunnel cannot carry UDP).
type UDPDialer interface {
	OpenUDP(context.Context, serverlist.Node, string, int) (net.PacketConn, error)
}

// UDPServer relays SOCKS5 UDP ASSOCIATE datagrams through the MASQUE nodes.
// Each client datagram carries its own destination in SOCKS5 UDP header form:
//
//	RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT DATA
//
// A per-(client, destination) CONNECT-UDP tunnel is opened on demand. Replies
// are framed with the SOCKS5 UDP header of the destination and sent back to
// the originating client address.
type UDPServer struct {
	Dialer  UDPDialer
	Nodes   []serverlist.Node
	conn    *net.UDPConn
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	tunnels map[string]net.PacketConn // key: client|destination
	wg      sync.WaitGroup
}

func NewUDPServer(d UDPDialer, nodes []serverlist.Node) *UDPServer {
	return &UDPServer{Dialer: d, Nodes: nodes, tunnels: map[string]net.PacketConn{}}
}

// Listen binds the UDP relay socket and starts serving. Returns the bound
// address (to learn the chosen port).
func (s *UDPServer) Listen(addr string) (net.Addr, error) {
	if s.ctx == nil {
		s.ctx, s.cancel = context.WithCancel(context.Background())
	}
	c, e := net.ListenPacket("udp", addr)
	if e != nil {
		return nil, e
	}
	s.conn = c.(*net.UDPConn)
	s.wg.Add(1)
	go s.readLoop()
	return c.LocalAddr(), nil
}

func (s *UDPServer) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.mu.Lock()
	for k, t := range s.tunnels {
		_ = t.Close()
		delete(s.tunnels, k)
	}
	s.mu.Unlock()
	s.wg.Wait()
	return nil
}

func (s *UDPServer) readLoop() {
	defer s.wg.Done()
	buf := make([]byte, 64<<10)
	for {
		n, raddr, e := s.conn.ReadFrom(buf)
		if e != nil {
			return
		}
		s.handlePacket(buf[:n], raddr)
	}
}

func (s *UDPServer) handlePacket(pkt []byte, raddr net.Addr) {
	if len(pkt) < 7 || pkt[2] != 0 {
		return // unsupported FRAG
	}
	rest := pkt[3:]
	host, port, addrLen, e := parseSocksAddr(rest)
	if e != nil || host == "" {
		return
	}
	payload := rest[addrLen:]
	destKey := net.JoinHostPort(host, strconv.Itoa(port))
	// Include the client address so two clients sending to the same destination
	// get independent tunnels and independent reply routing. Sharing one tunnel
	// would lose the first client's raddr and misdeliver replies to later clients.
	key := raddr.String() + "|" + destKey

	s.mu.Lock()
	t, ok := s.tunnels[key]
	if !ok {
		if len(s.Nodes) == 0 {
			s.mu.Unlock()
			return
		}
		ctx := s.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		tunnel, err := s.Dialer.OpenUDP(ctx, s.Nodes[0], host, port)
		if err != nil {
			s.mu.Unlock()
			return
		}
		t = tunnel
		s.tunnels[key] = t
		s.wg.Add(1)
		go s.relayBack(key, t, raddr, destKey)
	}
	s.mu.Unlock()

	if _, e = t.WriteTo(payload, nil); e != nil {
		return
	}
}

// relayBack reads datagrams from the tunnel and returns them to the client,
// framed with the destination's SOCKS5 UDP header. raddr is the originating
// client address captured when the tunnel was created; destKey is the
// host:port used to frame the SOCKS5 reply header.
func (s *UDPServer) relayBack(key string, t net.PacketConn, raddr net.Addr, destKey string) {
	defer s.wg.Done()
	defer s.dropTunnel(key, t)
	buf := make([]byte, 64<<10)
	for {
		n, _, e := t.ReadFrom(buf)
		if e != nil {
			return
		}
		framed := dSOCKSHeader(buf[:n], destKey)
		if s.conn == nil {
			return
		}
		if _, e = s.conn.WriteTo(framed, raddr); e != nil {
			return
		}
	}
}

func (s *UDPServer) dropTunnel(key string, t net.PacketConn) {
	s.mu.Lock()
	if s.tunnels[key] == t {
		delete(s.tunnels, key)
	}
	s.mu.Unlock()
	_ = t.Close()
}

// parseSocksAddr decodes a SOCKS5 UDP address (ATYP + ADDR + PORT), returning
// host, port, and total bytes consumed.
func parseSocksAddr(b []byte) (string, int, int, error) {
	if len(b) < 1 {
		return "", 0, 0, errors.New("short addr")
	}
	switch b[0] {
	case 1: // IPv4
		if len(b) < 1+4+2 {
			return "", 0, 0, errors.New("short ipv4")
		}
		return net.IP(b[1:5]).String(), int(b[5])<<8 | int(b[6]), 7, nil
	case 3: // domain
		if len(b) < 2 {
			return "", 0, 0, errors.New("short domain")
		}
		l := int(b[1])
		if len(b) < 2+l+2 {
			return "", 0, 0, errors.New("short domain")
		}
		return string(b[2 : 2+l]), int(b[2+l])<<8 | int(b[2+l+1]), 2 + l + 2, nil
	case 4: // IPv6
		if len(b) < 1+16+2 {
			return "", 0, 0, errors.New("short ipv6")
		}
		return net.IP(b[1:17]).String(), int(b[17])<<8 | int(b[18]), 19, nil
	}
	return "", 0, 0, errors.New("unsupported atyp")
}

// dSOCKSHeader frames a datagram with the SOCKS5 UDP header of the destination
// address. key is host:port.
func dSOCKSHeader(payload []byte, key string) []byte {
	h, p, err := net.SplitHostPort(key)
	if err != nil {
		return payload
	}
	port, _ := strconv.Atoi(p)
	out := make([]byte, 0, 4+len(h)+2+len(payload))
	out = append(out, 0, 0, 0, 3, byte(len(h))) // RSV FRAG ATYP=domain len
	out = append(out, h...)
	out = append(out, byte(port>>8), byte(port))
	return append(out, payload...)
}
