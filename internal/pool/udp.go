package pool

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

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
//
// Clients must be registered via AllowClient before their datagrams are
// forwarded. The SOCKS5 handler calls AllowClient after a successful UDP
// ASSOCIATE handshake so unauthenticated senders are silently dropped.
type UDPServer struct {
	Dialer UDPDialer
	Nodes  []serverlist.Node
	// IdleTimeout closes a tunnel that has seen no traffic in either direction
	// for this long. Zero disables idle reclamation.
	IdleTimeout time.Duration
	// MaxTunnelsPerClient caps concurrent tunnels per client address. Zero
	// means unlimited. Datagrams beyond the cap are dropped because SOCKS5 UDP
	// has no per-datagram error channel.
	MaxTunnelsPerClient int
	// Logf, when set, receives rate-limited diagnostics for tunnel failures.
	Logf        func(format string, args ...any)
	conn        *net.UDPConn
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	tunnels     map[string]*udpTunnel // key: client|destination
	clientCount map[string]int        // key: client address
	allowed     map[string]struct{}   // key: client IP (no port)
	nodeIndex   atomic.Uint64
	rejected    atomic.Uint64
	idleClosed  atomic.Uint64
	lastErrLog  atomic.Int64
	wg          sync.WaitGroup
}

// udpTunnel serializes writes against Close so a sweep or relay error cannot
// race a datagram write.
type udpTunnel struct {
	conn      net.PacketConn
	clientKey string
	last      atomic.Int64
	mu        sync.Mutex
	closed    bool
}

func (t *udpTunnel) touch() { t.last.Store(time.Now().UnixNano()) }
func (t *udpTunnel) idleFor() time.Duration {
	return time.Since(time.Unix(0, t.last.Load()))
}
func (t *udpTunnel) write(p []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return net.ErrClosed
	}
	n, err := t.conn.WriteTo(p, nil)
	if n > 0 {
		t.touch()
	}
	return err
}
func (t *udpTunnel) close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()
	return t.conn.Close()
}

// UDPStats is a diagnostic snapshot of the relay's resource usage.
type UDPStats struct {
	Tunnels      int
	Clients      int
	Rejected     uint64
	IdleClosed   uint64
	MaxPerClient int
	IdleTimeout  time.Duration
}

func NewUDPServer(d UDPDialer, nodes []serverlist.Node) *UDPServer {
	return &UDPServer{
		Dialer:      d,
		Nodes:       nodes,
		tunnels:     map[string]*udpTunnel{},
		clientCount: map[string]int{},
		allowed:     map[string]struct{}{},
	}
}

func (s *UDPServer) logf(format string, args ...any) {
	if s.Logf == nil {
		return
	}
	now := time.Now().UnixNano()
	prev := s.lastErrLog.Load()
	if now-prev < int64(5*time.Second) || !s.lastErrLog.CompareAndSwap(prev, now) {
		return
	}
	s.Logf(format, args...)
}

// Stats returns a snapshot for diagnostics and tests.
func (s *UDPServer) Stats() UDPStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return UDPStats{
		Tunnels:      len(s.tunnels),
		Clients:      len(s.clientCount),
		Rejected:     s.rejected.Load(),
		IdleClosed:   s.idleClosed.Load(),
		MaxPerClient: s.MaxTunnelsPerClient,
		IdleTimeout:  s.IdleTimeout,
	}
}

// AllowClient registers the client IP as authorized to use the UDP relay.
// Called by the SOCKS5 handler after a successful UDP ASSOCIATE handshake.
// Only the IP is checked; the ephemeral UDP source port may differ from the
// TCP control connection port.
func (s *UDPServer) AllowClient(addr net.Addr) {
	ip := addrIP(addr)
	if ip == "" {
		return
	}
	s.mu.Lock()
	s.allowed[ip] = struct{}{}
	s.mu.Unlock()
}

// addrIP extracts the host portion of a net.Addr, stripping the port.
func addrIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	h, _, e := net.SplitHostPort(addr.String())
	if e != nil {
		return addr.String()
	}
	return h
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
	if s.IdleTimeout > 0 {
		s.wg.Add(1)
		go s.sweepLoop()
	}
	return c.LocalAddr(), nil
}

// sweepLoop closes tunnels that have been silent for IdleTimeout.
func (s *UDPServer) sweepLoop() {
	defer s.wg.Done()
	every := s.IdleTimeout / 4
	if every < 10*time.Millisecond {
		every = 10 * time.Millisecond
	}
	if every > time.Minute {
		every = time.Minute
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.sweepIdle()
		}
	}
}

func (s *UDPServer) sweepIdle() {
	s.mu.Lock()
	var stale []string
	var staleTunnels []*udpTunnel
	for key, t := range s.tunnels {
		if t.idleFor() > s.IdleTimeout {
			stale = append(stale, key)
			staleTunnels = append(staleTunnels, t)
		}
	}
	s.mu.Unlock()
	for i, key := range stale {
		s.removeTunnel(key, staleTunnels[i], true)
	}
}

func (s *UDPServer) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.mu.Lock()
	tunnels := make([]*udpTunnel, 0, len(s.tunnels))
	keys := make([]string, 0, len(s.tunnels))
	for k, t := range s.tunnels {
		keys = append(keys, k)
		tunnels = append(tunnels, t)
	}
	s.mu.Unlock()
	for i, k := range keys {
		s.removeTunnel(k, tunnels[i], false)
	}
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

// isAllowed reports whether raddr's IP has been registered via AllowClient.
func (s *UDPServer) isAllowed(raddr net.Addr) bool {
	ip := addrIP(raddr)
	if ip == "" {
		return false
	}
	s.mu.Lock()
	_, ok := s.allowed[ip]
	s.mu.Unlock()
	return ok
}

func (s *UDPServer) handlePacket(pkt []byte, raddr net.Addr) {
	// Drop datagrams from clients that have not completed a SOCKS5 UDP
	// ASSOCIATE handshake on the companion TCP listener. This gates the relay
	// behind the same authentication mechanism as the TCP tunnels.
	if !s.isAllowed(raddr) {
		return
	}
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
	clientKey := raddr.String()
	key := clientKey + "|" + destKey

	s.mu.Lock()
	t, ok := s.tunnels[key]
	s.mu.Unlock()
	if !ok {
		if len(s.Nodes) == 0 {
			return
		}
		// Advisory check before the (possibly slow) tunnel dial; the
		// authoritative cap check happens at registration below.
		s.mu.Lock()
		full := s.MaxTunnelsPerClient > 0 && s.clientCount[clientKey] >= s.MaxTunnelsPerClient
		s.mu.Unlock()
		if full {
			s.rejected.Add(1)
			return
		}
		ctx := s.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		tunnel, err := s.Dialer.OpenUDP(ctx, s.pickNode(), host, port)
		if err != nil {
			s.logf("udp tunnel %s failed: %v", destKey, err)
			return
		}
		t = &udpTunnel{conn: tunnel, clientKey: clientKey}
		t.touch()
		s.mu.Lock()
		if existing, found := s.tunnels[key]; found {
			s.mu.Unlock()
			_ = t.close()
			t = existing
		} else if s.MaxTunnelsPerClient > 0 && s.clientCount[clientKey] >= s.MaxTunnelsPerClient {
			s.mu.Unlock()
			_ = t.close()
			s.rejected.Add(1)
			return
		} else {
			s.tunnels[key] = t
			s.clientCount[clientKey]++
			s.mu.Unlock()
			s.wg.Add(1)
			go s.relayBack(key, t, raddr, destKey)
		}
	}

	if err := t.write(payload); err != nil {
		s.removeTunnel(key, t, false)
	}
}

// pickNode rotates across the configured MASQUE nodes so one unreachable node
// does not sink every new tunnel.
func (s *UDPServer) pickNode() serverlist.Node {
	i := s.nodeIndex.Add(1) - 1
	return s.Nodes[i%uint64(len(s.Nodes))]
}

// relayBack reads datagrams from the tunnel and returns them to the client,
// framed with the destination's SOCKS5 UDP header. raddr is the originating
// client address captured when the tunnel was created; destKey is the
// host:port used to frame the SOCKS5 reply header.
func (s *UDPServer) relayBack(key string, t *udpTunnel, raddr net.Addr, destKey string) {
	defer s.wg.Done()
	defer s.removeTunnel(key, t, false)
	buf := make([]byte, 64<<10)
	for {
		n, _, e := t.conn.ReadFrom(buf)
		if e != nil {
			return
		}
		if n > 0 {
			t.touch()
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

// removeTunnel deletes the mapping (once) and closes the tunnel. Both the
// idle sweeper and relayBack may race here; only the first removal decrements
// the client's tunnel count and (when idle is true) records the idle reclaim
// while holding s.mu so Stats() cannot observe Tunnels==0 before IdleClosed.
func (s *UDPServer) removeTunnel(key string, t *udpTunnel, idle bool) bool {
	removed := false
	s.mu.Lock()
	if cur, ok := s.tunnels[key]; ok && cur == t {
		delete(s.tunnels, key)
		if n := s.clientCount[t.clientKey]; n <= 1 {
			delete(s.clientCount, t.clientKey)
		} else {
			s.clientCount[t.clientKey] = n - 1
		}
		if idle {
			s.idleClosed.Add(1)
		}
		removed = true
	}
	s.mu.Unlock()
	_ = t.close()
	return removed
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
