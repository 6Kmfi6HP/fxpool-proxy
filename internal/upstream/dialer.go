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
	"net/url"
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

// masqueEndpoint returns the QUIC host and port to dial for the MASQUE proxy.
// For Remote Settings nodes, MasqueHost/MasquePort hold the proxy endpoint
// (which may differ from the general Hostname/Port). For manually supplied
// templates, the authority is parsed from the template URI itself.
func masqueEndpoint(node serverlist.Node) (host string, port int, err error) {
	if node.MasqueHost != "" && node.MasquePort > 0 {
		return node.MasqueHost, node.MasquePort, nil
	}
	// Fall back to parsing the authority from the URI template.
	if node.TemplateString == "" {
		return "", 0, errors.New("masque node has no templateString or MasqueHost")
	}
	u, e := url.Parse(node.TemplateString)
	if e != nil || u.Host == "" {
		return "", 0, fmt.Errorf("masque: cannot derive endpoint from templateString %q", node.TemplateString)
	}
	h, p, e := net.SplitHostPort(u.Host)
	if e != nil {
		// No port in host; default to 443 for https.
		return strings.ToLower(u.Host), 443, nil
	}
	pp, e := strconv.Atoi(p)
	if e != nil || pp < 1 || pp > 65535 {
		return "", 0, fmt.Errorf("masque: invalid port in templateString: %q", p)
	}
	return strings.ToLower(h), pp, nil
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

	proxyHost, proxyPort, e := masqueEndpoint(node)
	if e != nil {
		return nil, e
	}
	proxyAddr := authority(proxyHost, proxyPort)

	tlsConf := d.MasqueTLSConfig
	if tlsConf == nil {
		tlsConf = &tls.Config{NextProtos: []string{http3.NextProtoH3}}
	} else {
		tlsConf = tlsConf.Clone()
	}
	if tlsConf.ServerName == "" {
		tlsConf.ServerName = proxyHost
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
	// Pin the transport to the resolved proxy endpoint via DialAddr so that the
	// QUIC connection goes to the correct host:port regardless of what the URI
	// template's authority says (Remote Settings nodes where MasqueHost/MasquePort
	// differ from Hostname/Port, or manually supplied templates with no port).
	tr := &masque.Transport{
		TLSClientConfig: tlsConf,
		QUICConfig:      quicConf,
		DialAddr: func(ctx context.Context, _ string, tlsCfg *tls.Config, quicCfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, proxyAddr, tlsCfg, quicCfg)
		},
	}
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

// isMASQUEAuthError reports whether err came from an HTTP 401, 403, or 407
// response during a MASQUE dial. Only these statuses indicate a bad or expired
// token; all other failures (DNS, network, unsupported template) are not
// auth-related and must not trigger a credential refresh.
func isMASQUEAuthError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "MASQUE HTTP 401") ||
		strings.Contains(s, "MASQUE HTTP 403") ||
		strings.Contains(s, "MASQUE HTTP 407")
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
	// Only refresh credentials for authentication failures. DNS errors, network
	// timeouts, invalid templates, and unsupported server responses are not
	// auth-related; retrying with a new token there would reject a valid token
	// and cause unnecessary account refreshes on every new destination.
	if !isMASQUEAuthError(e) {
		return nil, e
	}
	_ = d.Tokens.Reject(token)
	token, e = d.Tokens.Ensure(ctx, true)
	if e != nil {
		return nil, e
	}
	return d.openMASQUE(ctx, node, targetHost, targetPort, token)
}
