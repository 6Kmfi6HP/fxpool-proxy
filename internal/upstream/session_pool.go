package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

	"fxpool-proxy/internal/serverlist"
)

// UpstreamTransport selects how TCP CONNECT tunnels are established to an
// upstream Fastly node.
type UpstreamTransport string

const (
	// TransportH1 opens a fresh TCP + TLS + HTTP/1.1 CONNECT tunnel per Open
	// call (default).
	TransportH1 UpstreamTransport = "h1"
	// TransportH2 multiplexes CONNECT streams over pooled HTTP/2 over TLS
	// sessions (opt-in).
	TransportH2 UpstreamTransport = "h2"
	// TransportH3 multiplexes CONNECT streams over pooled HTTP/3 over QUIC
	// sessions (opt-in).
	TransportH3 UpstreamTransport = "h3"
)

const (
	defaultSessionIdleTTL    = 5 * time.Minute
	defaultMaxSessions       = 64
	defaultKeepAliveInterval = 30 * time.Second
	defaultPingTimeout       = 10 * time.Second
)

// ParseUpstreamTransport validates and normalizes an upstream transport name.
// Empty string defaults to TransportH1.
func ParseUpstreamTransport(raw string) (UpstreamTransport, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(TransportH1):
		return TransportH1, nil
	case string(TransportH2):
		return TransportH2, nil
	case string(TransportH3):
		return TransportH3, nil
	default:
		return "", fmt.Errorf("unsupported upstream transport %q (want h1, h2, or h3)", raw)
	}
}

// AccountTokenSource is an optional extension of TokenSource that returns a
// stable account identifier alongside the bearer token so pooled upstream
// sessions remain isolated per account.
type AccountTokenSource interface {
	TokenSource
	EnsureAccount(ctx context.Context, force bool) (token string, accountKey string, err error)
}

func (d *Dialer) ensureToken(ctx context.Context, force bool) (token, accountKey string, err error) {
	if ats, ok := d.Tokens.(AccountTokenSource); ok {
		return ats.EnsureAccount(ctx, force)
	}
	tok, err := d.Tokens.Ensure(ctx, force)
	if err != nil {
		return "", "", err
	}
	return tok, "default", nil
}

func (d *Dialer) transportMode() (UpstreamTransport, error) {
	return ParseUpstreamTransport(string(d.UpstreamTransport))
}

func (d *Dialer) maxResponseBytes() int64 {
	if d.MaxResponseBytes > 0 {
		return d.MaxResponseBytes
	}
	return 64 << 10
}

type sessionKey struct {
	transport  UpstreamTransport
	nodeID     string
	accountKey string
}

type upstreamSession interface {
	openStream(ctx context.Context, maxRespBytes int64, targetHost string, targetPort int, token string) (net.Conn, int, error)
	isAlive() bool
	ping(ctx context.Context) error
	close() error
	activeCount() int64
}

type pooledSession struct {
	key      sessionKey
	sess     upstreamSession
	lastUsed atomic.Int64
}

func newPooledSession(key sessionKey, sess upstreamSession) *pooledSession {
	ps := &pooledSession{key: key, sess: sess}
	ps.touch()
	return ps
}

func (p *pooledSession) touch() {
	p.lastUsed.Store(time.Now().UnixNano())
}

func (p *pooledSession) lastUsedTime() time.Time {
	return time.Unix(0, p.lastUsed.Load())
}

type dialCall struct {
	done chan struct{}
	sess *pooledSession
	err  error
}

type sessionPool struct {
	idleTTL           time.Duration
	maxSessions       int
	keepAliveInterval time.Duration

	mu       sync.Mutex
	sessions map[sessionKey]*pooledSession
	inflight map[sessionKey]*dialCall
	closed   bool

	stopOnce sync.Once
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

func newSessionPool(idleTTL time.Duration, maxSessions int, keepAliveInterval time.Duration) *sessionPool {
	if idleTTL <= 0 {
		idleTTL = defaultSessionIdleTTL
	}
	if maxSessions <= 0 {
		maxSessions = defaultMaxSessions
	}
	if keepAliveInterval == 0 {
		keepAliveInterval = defaultKeepAliveInterval
	}
	p := &sessionPool{
		idleTTL:           idleTTL,
		maxSessions:       maxSessions,
		keepAliveInterval: keepAliveInterval,
		sessions:          make(map[sessionKey]*pooledSession),
		inflight:          make(map[sessionKey]*dialCall),
		stopCh:            make(chan struct{}),
	}
	p.wg.Add(1)
	go p.maintenanceLoop()
	return p
}

func (p *sessionPool) maintenanceLoop() {
	defer p.wg.Done()
	sweepEvery := p.idleTTL / 2
	if sweepEvery > 30*time.Second {
		sweepEvery = 30 * time.Second
	}
	if sweepEvery < 50*time.Millisecond {
		sweepEvery = 50 * time.Millisecond
	}
	sweepTicker := time.NewTicker(sweepEvery)
	defer sweepTicker.Stop()

	var pingCh <-chan time.Time
	if p.keepAliveInterval > 0 {
		pingTicker := time.NewTicker(p.keepAliveInterval)
		defer pingTicker.Stop()
		pingCh = pingTicker.C
	}

	for {
		select {
		case <-p.stopCh:
			return
		case <-sweepTicker.C:
			p.sweep()
		case <-pingCh:
			p.pingAll()
		}
	}
}

func (p *sessionPool) sweep() {
	now := time.Now()
	var toClose []*pooledSession

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	for k, ps := range p.sessions {
		if !ps.sess.isAlive() {
			delete(p.sessions, k)
			toClose = append(toClose, ps)
			continue
		}
		if ps.sess.activeCount() == 0 && now.Sub(ps.lastUsedTime()) > p.idleTTL {
			delete(p.sessions, k)
			toClose = append(toClose, ps)
		}
	}
	p.mu.Unlock()

	for _, ps := range toClose {
		_ = ps.sess.close()
	}
}

func (p *sessionPool) pingAll() {
	type target struct {
		key sessionKey
		ps  *pooledSession
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	targets := make([]target, 0, len(p.sessions))
	for k, ps := range p.sessions {
		targets = append(targets, target{key: k, ps: ps})
	}
	p.mu.Unlock()

	timeout := defaultPingTimeout
	if p.keepAliveInterval > 0 && p.keepAliveInterval < timeout {
		timeout = p.keepAliveInterval
	}
	for _, t := range targets {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		err := t.ps.sess.ping(ctx)
		cancel()
		if err != nil {
			p.evict(t.key, t.ps)
		}
	}
}

func (p *sessionPool) close() error {
	var toClose []*pooledSession
	p.stopOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		for k, ps := range p.sessions {
			toClose = append(toClose, ps)
			delete(p.sessions, k)
		}
		p.mu.Unlock()
		close(p.stopCh)
	})
	for _, ps := range toClose {
		_ = ps.sess.close()
	}
	p.wg.Wait()
	return nil
}

func (p *sessionPool) evict(key sessionKey, target *pooledSession) {
	p.mu.Lock()
	cur, ok := p.sessions[key]
	if !ok || cur != target {
		p.mu.Unlock()
		return
	}
	delete(p.sessions, key)
	p.mu.Unlock()
	_ = target.sess.close()
}

func (p *sessionPool) getOrDial(ctx context.Context, d *Dialer, key sessionKey, node serverlist.Node) (*pooledSession, error) {
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, net.ErrClosed
		}
		if ps, ok := p.sessions[key]; ok {
			if ps.sess.isAlive() {
				ps.touch()
				p.mu.Unlock()
				return ps, nil
			}
			delete(p.sessions, key)
			p.mu.Unlock()
			_ = ps.sess.close()
			continue
		}
		if call, ok := p.inflight[key]; ok {
			p.mu.Unlock()
			select {
			case <-call.done:
				return call.sess, call.err
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		call := &dialCall{done: make(chan struct{})}
		p.inflight[key] = call
		p.mu.Unlock()

		sess, err := d.dialSession(ctx, key.transport, node)

		var evicted *pooledSession
		var ps *pooledSession
		p.mu.Lock()
		delete(p.inflight, key)
		if err == nil && p.closed {
			err = net.ErrClosed
		}
		if err == nil {
			if p.maxSessions > 0 && len(p.sessions) >= p.maxSessions {
				evicted = p.pickEvictionLocked()
				if evicted != nil {
					delete(p.sessions, evicted.key)
				}
			}
			ps = newPooledSession(key, sess)
			p.sessions[key] = ps
		}
		call.sess = ps
		call.err = err
		close(call.done)
		p.mu.Unlock()

		if err != nil && sess != nil {
			_ = sess.close()
		}
		if evicted != nil {
			_ = evicted.sess.close()
		}
		return ps, err
	}
}

func (p *sessionPool) pickEvictionLocked() *pooledSession {
	var oldestIdle *pooledSession
	var oldestAny *pooledSession
	for _, ps := range p.sessions {
		if oldestAny == nil || ps.lastUsedTime().Before(oldestAny.lastUsedTime()) {
			oldestAny = ps
		}
		if ps.sess.activeCount() == 0 {
			if oldestIdle == nil || ps.lastUsedTime().Before(oldestIdle.lastUsedTime()) {
				oldestIdle = ps
			}
		}
	}
	if oldestIdle != nil {
		return oldestIdle
	}
	return oldestAny
}

func (p *sessionPool) acquireAndOpen(ctx context.Context, d *Dialer, mode UpstreamTransport, node serverlist.Node, accountKey, targetHost string, targetPort int, token string) (net.Conn, int, error) {
	key := sessionKey{
		transport:  mode,
		nodeID:     node.StableID(),
		accountKey: accountKey,
	}
	ps, err := p.getOrDial(ctx, d, key, node)
	if err != nil {
		return nil, 0, err
	}
	conn, status, err := ps.sess.openStream(ctx, d.maxResponseBytes(), targetHost, targetPort, token)
	if err == nil {
		ps.touch()
		return conn, 200, nil
	}
	// HTTP status errors (e.g. 401/403/407 auth failure or 502 target
	// unreachable) mean the underlying H2/H3 session is healthy; keep it in the
	// pool so token refresh or other streams can reuse it.
	if status != 0 {
		return nil, status, err
	}
	// Transport error: evict the broken session and retry once on a fresh one.
	p.evict(key, ps)
	ps, err = p.getOrDial(ctx, d, key, node)
	if err != nil {
		return nil, 0, err
	}
	conn, status, err = ps.sess.openStream(ctx, d.maxResponseBytes(), targetHost, targetPort, token)
	if err == nil {
		ps.touch()
		return conn, 200, nil
	}
	if status == 0 {
		p.evict(key, ps)
	}
	return nil, status, err
}

func (d *Dialer) getSessionPool() *sessionPool {
	d.poolOnce.Do(func() {
		d.pool = newSessionPool(d.SessionIdleTTL, d.MaxSessions, d.KeepAliveInterval)
	})
	return d.pool
}

// Close shuts down any pooled HTTP/2 or HTTP/3 upstream sessions and stops
// background maintenance goroutines.
func (d *Dialer) Close() error {
	if d.pool == nil {
		return nil
	}
	return d.pool.close()
}

func (d *Dialer) dialSession(ctx context.Context, mode UpstreamTransport, node serverlist.Node) (upstreamSession, error) {
	switch mode {
	case TransportH2:
		return d.dialH2Session(ctx, node)
	case TransportH3:
		return d.dialH3Session(ctx, node)
	default:
		return nil, fmt.Errorf("cannot dial pooled session for transport %q", mode)
	}
}

func (d *Dialer) netDialer() *net.Dialer {
	if d.NetDialer != nil {
		return d.NetDialer
	}
	return &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
}

func (d *Dialer) dialH2Session(ctx context.Context, node serverlist.Node) (*h2Session, error) {
	nd := d.netDialer()
	raw, err := nd.DialContext(ctx, "tcp", authority(node.Hostname, node.Port))
	if err != nil {
		return nil, err
	}
	cfg := d.TLSConfig
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	clone := cfg.Clone()
	if clone.ServerName == "" {
		clone.ServerName = node.Hostname
	}
	clone.NextProtos = []string{"h2"}

	tlsConn := tls.Client(raw, clone)
	if deadline, ok := ctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	} else {
		_ = tlsConn.SetDeadline(time.Now().Add(20 * time.Second))
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = tlsConn.SetDeadline(time.Time{})

	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		_ = tlsConn.Close()
		return nil, errors.New("upstream proxy did not negotiate HTTP/2")
	}

	tr := &http2.Transport{DisableCompression: true}
	cc, err := tr.NewClientConn(tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return &h2Session{
		tlsConn: tlsConn,
		cc:      cc,
	}, nil
}

type h2Session struct {
	tlsConn       *tls.Conn
	cc            *http2.ClientConn
	activeStreams atomic.Int64
	closed        atomic.Bool
}

func (s *h2Session) activeCount() int64 { return s.activeStreams.Load() }

func (s *h2Session) isAlive() bool {
	if s.closed.Load() {
		return false
	}
	st := s.cc.State()
	return !st.Closed && !st.Closing
}

func (s *h2Session) ping(ctx context.Context) error {
	if !s.isAlive() {
		return net.ErrClosed
	}
	return s.cc.Ping(ctx)
}

func (s *h2Session) close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	err := s.cc.Close()
	if err2 := s.tlsConn.Close(); err == nil {
		err = err2
	}
	return err
}

func (s *h2Session) openStream(ctx context.Context, maxRespBytes int64, targetHost string, targetPort int, token string) (net.Conn, int, error) {
	if !s.isAlive() {
		return nil, 0, net.ErrClosed
	}
	dest := authority(targetHost, targetPort)
	pr, pw := io.Pipe()
	// Use a detached stream context so a caller's dial timeout does not abort an
	// established tunnel after Open returns; handshake cancellation is wired below.
	streamCtx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(streamCtx, http.MethodConnect, "https://"+dest, pr)
	if err != nil {
		cancel()
		_ = pr.Close()
		_ = pw.Close()
		return nil, 0, err
	}
	req.Host = dest
	req.Header.Set("Proxy-Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "firefox-ip-protection-pool/3.0")

	type rtResult struct {
		resp *http.Response
		err  error
	}
	ch := make(chan rtResult, 1)
	go func() {
		resp, rtErr := s.cc.RoundTrip(req)
		ch <- rtResult{resp: resp, err: rtErr}
	}()

	var res rtResult
	select {
	case res = <-ch:
	case <-ctx.Done():
		cancel()
		_ = pr.Close()
		_ = pw.Close()
		go func() {
			if r := <-ch; r.resp != nil && r.resp.Body != nil {
				_ = r.resp.Body.Close()
			}
		}()
		return nil, 0, ctx.Err()
	}

	if res.err != nil {
		cancel()
		_ = pr.Close()
		_ = pw.Close()
		return nil, 0, res.err
	}
	resp := res.resp
	if resp.ContentLength > maxRespBytes {
		_ = resp.Body.Close()
		cancel()
		_ = pr.Close()
		_ = pw.Close()
		return nil, resp.StatusCode, &CONNECTError{Status: resp.StatusCode, Err: errors.New("CONNECT response too large")}
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxRespBytes+1))
		_ = resp.Body.Close()
		cancel()
		_ = pr.Close()
		_ = pw.Close()
		return nil, resp.StatusCode, &CONNECTError{Status: resp.StatusCode}
	}

	s.activeStreams.Add(1)
	return &h2StreamConn{
		reader:     resp.Body,
		writer:     pw,
		reqReader:  pr,
		cancel:     cancel,
		localAddr:  s.tlsConn.LocalAddr(),
		remoteAddr: s.tlsConn.RemoteAddr(),
		onClose:    func() { s.activeStreams.Add(-1) },
	}, http.StatusOK, nil
}

type h2StreamConn struct {
	reader         io.ReadCloser
	writer         *io.PipeWriter
	reqReader      *io.PipeReader
	cancel         context.CancelFunc
	localAddr      net.Addr
	remoteAddr     net.Addr
	onClose        func()
	closeWriteOnce sync.Once
	closeOnce      sync.Once
}

func (c *h2StreamConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *h2StreamConn) Write(p []byte) (int, error) { return c.writer.Write(p) }

// CloseWrite sends HTTP/2 END_STREAM on the request body while keeping the
// response stream open so the origin can finish sending data.
func (c *h2StreamConn) CloseWrite() error {
	var err error
	c.closeWriteOnce.Do(func() {
		err = c.writer.Close()
	})
	return err
}

func (c *h2StreamConn) Close() error {
	c.closeOnce.Do(func() {
		_ = c.writer.Close()
		_ = c.reqReader.Close()
		c.cancel()
		_ = c.reader.Close()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return nil
}

func (c *h2StreamConn) LocalAddr() net.Addr              { return c.localAddr }
func (c *h2StreamConn) RemoteAddr() net.Addr             { return c.remoteAddr }
func (c *h2StreamConn) SetDeadline(time.Time) error      { return nil }
func (c *h2StreamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *h2StreamConn) SetWriteDeadline(time.Time) error { return nil }

func (d *Dialer) dialH3Session(ctx context.Context, node serverlist.Node) (*h3Session, error) {
	proxyAddr := authority(node.Hostname, node.Port)

	var tlsConf *tls.Config
	if d.MasqueTLSConfig != nil {
		tlsConf = d.MasqueTLSConfig.Clone()
	} else if d.TLSConfig != nil {
		tlsConf = d.TLSConfig.Clone()
	} else {
		tlsConf = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	if tlsConf.ServerName == "" {
		tlsConf.ServerName = node.Hostname
	}
	tlsConf.NextProtos = []string{http3.NextProtoH3}

	var quicConf *quic.Config
	if d.MasqueQUICConfig != nil {
		quicConf = d.MasqueQUICConfig.Clone()
	} else {
		quicConf = &quic.Config{
			InitialPacketSize: 1200,
			KeepAlivePeriod:   30 * time.Second,
		}
	}
	if quicConf.KeepAlivePeriod == 0 {
		quicConf.KeepAlivePeriod = 30 * time.Second
	}

	qconn, err := quic.DialAddr(ctx, proxyAddr, tlsConf, quicConf)
	if err != nil {
		return nil, err
	}
	tr := &http3.Transport{DisableCompression: true}
	cc := tr.NewClientConn(qconn)
	return &h3Session{
		qconn: qconn,
		cc:    cc,
	}, nil
}

type h3Session struct {
	qconn         *quic.Conn
	cc            *http3.ClientConn
	activeStreams atomic.Int64
	closed        atomic.Bool
}

func (s *h3Session) activeCount() int64 { return s.activeStreams.Load() }

func (s *h3Session) isAlive() bool {
	if s.closed.Load() {
		return false
	}
	return s.qconn.Context().Err() == nil
}

func (s *h3Session) ping(context.Context) error {
	if !s.isAlive() {
		return net.ErrClosed
	}
	return nil
}

func (s *h3Session) close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	return s.qconn.CloseWithError(0, "session closed")
}

func (s *h3Session) openStream(ctx context.Context, maxRespBytes int64, targetHost string, targetPort int, token string) (net.Conn, int, error) {
	if !s.isAlive() {
		return nil, 0, net.ErrClosed
	}
	str, err := s.cc.OpenRequestStream(ctx)
	if err != nil {
		return nil, 0, err
	}

	dest := authority(targetHost, targetPort)
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Scheme: "https", Host: dest},
		Host:   dest,
		Header: http.Header{
			"Proxy-Authorization": []string{"Bearer " + token},
			"User-Agent":          []string{"firefox-ip-protection-pool/3.0"},
		},
	}

	// Watch ctx during the CONNECT header/response exchange; once 200 OK is
	// received, the stream outlives any per-dial context.
	handshakeDone := make(chan struct{})
	stopWatch := context.AfterFunc(ctx, func() {
		select {
		case <-handshakeDone:
		default:
			str.CancelRead(0)
			str.CancelWrite(0)
			_ = str.Close()
		}
	})

	if err := str.SendRequestHeader(req); err != nil {
		close(handshakeDone)
		stopWatch()
		str.CancelRead(0)
		str.CancelWrite(0)
		_ = str.Close()
		return nil, 0, err
	}
	resp, err := str.ReadResponse()
	close(handshakeDone)
	stopWatch()
	if err != nil {
		str.CancelRead(0)
		str.CancelWrite(0)
		_ = str.Close()
		return nil, 0, err
	}

	if resp.ContentLength > maxRespBytes {
		_ = resp.Body.Close()
		str.CancelRead(0)
		str.CancelWrite(0)
		_ = str.Close()
		return nil, resp.StatusCode, &CONNECTError{Status: resp.StatusCode, Err: errors.New("CONNECT response too large")}
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxRespBytes+1))
		_ = resp.Body.Close()
		str.CancelRead(0)
		str.CancelWrite(0)
		_ = str.Close()
		return nil, resp.StatusCode, &CONNECTError{Status: resp.StatusCode}
	}

	s.activeStreams.Add(1)
	return &h3StreamConn{
		str:        str,
		localAddr:  s.qconn.LocalAddr(),
		remoteAddr: s.qconn.RemoteAddr(),
		onClose:    func() { s.activeStreams.Add(-1) },
	}, http.StatusOK, nil
}

type h3StreamConn struct {
	str            *http3.RequestStream
	localAddr      net.Addr
	remoteAddr     net.Addr
	onClose        func()
	closeWriteOnce sync.Once
	closeOnce      sync.Once
}

func (c *h3StreamConn) Read(p []byte) (int, error)  { return c.str.Read(p) }
func (c *h3StreamConn) Write(p []byte) (int, error) { return c.str.Write(p) }

// CloseWrite closes the send side (QUIC FIN) while keeping reads open.
func (c *h3StreamConn) CloseWrite() error {
	var err error
	c.closeWriteOnce.Do(func() {
		err = c.str.Close()
	})
	return err
}

func (c *h3StreamConn) Close() error {
	c.closeOnce.Do(func() {
		c.str.CancelRead(0)
		c.str.CancelWrite(0)
		_ = c.str.Close()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return nil
}

func (c *h3StreamConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *h3StreamConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *h3StreamConn) SetDeadline(t time.Time) error      { return c.str.SetDeadline(t) }
func (c *h3StreamConn) SetReadDeadline(t time.Time) error  { return c.str.SetReadDeadline(t) }
func (c *h3StreamConn) SetWriteDeadline(t time.Time) error { return c.str.SetWriteDeadline(t) }
