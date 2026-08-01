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

	"fxpool-proxy/internal/serverlist"
)

type TokenSource interface {
	Ensure(context.Context, bool) (string, error)
	Reject(string) error
}
type Dialer struct {
	Tokens           TokenSource
	TLSConfig        *tls.Config
	NetDialer        *net.Dialer
	MaxResponseBytes int64
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
	if !node.Supported || node.Protocol != "connect" || node.Scheme != "https" {
		return nil, errors.New("unsupported upstream protocol")
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
func (d *Dialer) once(ctx context.Context, node serverlist.Node, targetHost string, targetPort int, token string) (net.Conn, int, error) {
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
