package upstream

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"fxpool-proxy/internal/serverlist"
)

type TokenSource interface {
	Ensure(context.Context, bool) (string, error)
	Reject(string) error
}

// errUnsupportedProtocol is returned when a node advertises a protocol this
// dialer cannot speak.
var errUnsupportedProtocol = errors.New("unsupported upstream protocol")

type Dialer struct {
	Tokens           TokenSource
	TLSConfig        *tls.Config
	NetDialer        *net.Dialer
	MaxResponseBytes int64
	// MasqueTLSConfig is used when dialing the QUIC connection to a MASQUE
	// proxy. When nil, a config with the "h3" ALPN is derived from TLSConfig.
	MasqueTLSConfig *tls.Config
	// MasqueQUICConfig configures the QUIC connection to the MASQUE proxy.
	MasqueQUICConfig *quic.Config
}
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
func authority(host string, port int) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + strconv.Itoa(port)
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}
func (d *Dialer) Open(ctx context.Context, node serverlist.Node, targetHost string, targetPort int) (net.Conn, error) {
	if !node.Supported || node.Protocol != "connect" {
		return nil, errUnsupportedProtocol
	}
	token, e := d.Tokens.Ensure(ctx, false)
	if e != nil {
		return nil, e
	}
	c, status, e := d.once(ctx, node, targetHost, targetPort, token)
	if e == nil {
		return c, nil
	}
	if status != 401 && status != 403 && status != 407 {
		return nil, e
	}
	_ = d.Tokens.Reject(token)
	token, e = d.Tokens.Ensure(ctx, true)
	if e != nil {
		return nil, e
	}
	c, _, e = d.once(ctx, node, targetHost, targetPort, token)
	return c, e
}

// once establishes a TCP tunnel to the selected node via HTTPS CONNECT.
// status is 200 on success, or an HTTP status on tunnel failure.
func (d *Dialer) once(ctx context.Context, node serverlist.Node, targetHost string, targetPort int, token string) (net.Conn, int, error) {
	return d.connectOnce(ctx, node, targetHost, targetPort, token)
}
func (d *Dialer) connectOnce(ctx context.Context, node serverlist.Node, targetHost string, targetPort int, token string) (net.Conn, int, error) {
	nd := d.NetDialer
	if nd == nil {
		nd = &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	}
	raw, e := nd.DialContext(ctx, "tcp", authority(node.Hostname, node.Port))
	if e != nil {
		return nil, 0, e
	}
	cfg := d.TLSConfig
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	clone := cfg.Clone()
	if clone.ServerName == "" {
		clone.ServerName = node.Hostname
	}
	conn := tls.Client(raw, clone)
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	}
	if e = conn.HandshakeContext(ctx); e != nil {
		raw.Close()
		return nil, 0, e
	}
	dest := authority(targetHost, targetPort)
	if _, e = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Bearer %s\r\nUser-Agent: firefox-ip-protection-pool/3.0\r\nConnection: keep-alive\r\n\r\n", dest, dest, token); e != nil {
		conn.Close()
		return nil, 0, e
	}
	br := bufio.NewReaderSize(conn, 16<<10)
	req := &http.Request{Method: http.MethodConnect}
	resp, e := http.ReadResponse(br, req)
	if e != nil {
		conn.Close()
		return nil, 0, e
	}
	limit := d.MaxResponseBytes
	if limit == 0 {
		limit = 64 << 10
	}
	if resp.ContentLength > limit {
		_ = resp.Body.Close()
		conn.Close()
		return nil, resp.StatusCode, errors.New("CONNECT response too large")
	}
	if resp.StatusCode != 200 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, limit+1))
		_ = resp.Body.Close()
		conn.Close()
		return nil, resp.StatusCode, fmt.Errorf("upstream CONNECT HTTP %d", resp.StatusCode)
	}
	// A successful CONNECT response transfers ownership of the underlying
	// connection to the caller. Closing resp.Body here closes that tunnel.
	_ = conn.SetDeadline(time.Time{})
	return &bufferedConn{conn, br}, 200, nil
}

// openMASQUE establishes an HTTP/3 CONNECT-UDP (RFC 9298) tunnel to the target
// through the node's MASQUE proxy. Each call opens a fresh QUIC connection to
// the proxy and a single CONNECT-UDP stream. The returned net.PacketConn
// carries UDP datagrams to the target (one datagram per ReadFrom/WriteTo).
func (d *Dialer) openMASQUE(ctx context.Context, node serverlist.Node, targetHost string, targetPort int, token string) (*masque.Conn, error) {
	if node.TemplateString == "" {
		return nil, errors.New("masque node has no templateString")
	}
	tmpl, e := uritemplate.New(node.TemplateString)
	if e != nil {
		return nil, fmt.Errorf("masque: invalid URI template: %w", e)
	}
	req, e := masque.NewRequest(ctx, tmpl, authority(targetHost, targetPort))
	if e != nil {
		return nil, e
	}
	req.Header().Set("Proxy-Authorization", "Bearer "+token)
	req.Header().Set("User-Agent", "firefox-ip-protection-pool/3.0")

	tlsConf := d.MasqueTLSConfig
	if tlsConf == nil {
		tlsConf = &tls.Config{NextProtos: []string{http3.NextProtoH3}}
	} else {
		tlsConf = tlsConf.Clone()
	}
	if tlsConf.ServerName == "" && node.MasqueHost != "" {
		tlsConf.ServerName = node.MasqueHost
	}
	quicConf := d.MasqueQUICConfig
	if quicConf == nil {
		quicConf = &quic.Config{
			EnableDatagrams:   true,
			InitialPacketSize: 1350,
		}
	} else if !quicConf.EnableDatagrams {
		return nil, errors.New("masque: QUICConfig must enable datagrams")
	}
	tr := &masque.Transport{TLSClientConfig: tlsConf, QUICConfig: quicConf}
	conn, resp, e := tr.Dial(req)
	if e != nil {
		return nil, e
	}
	if resp.StatusCode != 200 {
		_ = conn.Close()
		return nil, fmt.Errorf("upstream MASQUE HTTP %d", resp.StatusCode)
	}
	return conn, nil
}

// OpenUDP dials a UDP tunnel to the target. Only MASQUE nodes support UDP;
// the CONNECT path returns errUnsupportedProtocol.
func (d *Dialer) OpenUDP(ctx context.Context, node serverlist.Node, targetHost string, targetPort int) (net.PacketConn, error) {
	if !node.Supported || node.Protocol != "masque" {
		return nil, errUnsupportedProtocol
	}
	token, e := d.Tokens.Ensure(ctx, false)
	if e != nil {
		return nil, e
	}
	c, e := d.openMASQUE(ctx, node, targetHost, targetPort, token)
	if e == nil {
		return c, nil
	}
	_ = d.Tokens.Reject(token)
	token, e = d.Tokens.Ensure(ctx, true)
	if e != nil {
		return nil, e
	}
	return d.openMASQUE(ctx, node, targetHost, targetPort, token)
}
