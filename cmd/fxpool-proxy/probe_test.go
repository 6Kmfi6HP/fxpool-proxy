package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"fxpool-proxy/internal/serverlist"
)

type probeTimeoutError struct{}

func (probeTimeoutError) Error() string   { return "i/o timeout" }
func (probeTimeoutError) Timeout() bool   { return true }
func (probeTimeoutError) Temporary() bool { return true }

type probeFakeConn struct {
	reply bool
}

func (c *probeFakeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.reply {
		return copy(p, []byte("pong")), &net.UDPAddr{}, nil
	}
	return 0, nil, probeTimeoutError{}
}
func (c *probeFakeConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *probeFakeConn) Close() error                              { return nil }
func (c *probeFakeConn) LocalAddr() net.Addr                       { return &net.UDPAddr{} }
func (c *probeFakeConn) SetDeadline(time.Time) error               { return nil }
func (c *probeFakeConn) SetReadDeadline(time.Time) error           { return nil }
func (c *probeFakeConn) SetWriteDeadline(time.Time) error          { return nil }

type probeFakeOpener struct {
	conn *probeFakeConn
	err  error
	port int
}

func (o *probeFakeOpener) OpenUDP(_ context.Context, _ serverlist.Node, _ string, port int) (net.PacketConn, error) {
	o.port = port
	if o.err != nil {
		return nil, o.err
	}
	return o.conn, nil
}

func TestProbeUDPPortReportsTunnelAndReply(t *testing.T) {
	o := &probeFakeOpener{conn: &probeFakeConn{reply: true}}
	r := probeUDPPort(o, serverlist.Node{}, "1.1.1.1", 53, 100*time.Millisecond)
	if r.Tunnel != "established" || !r.Reply || r.Error != "" {
		t.Fatalf("unexpected report: %+v", r)
	}
	if o.port != 53 {
		t.Fatalf("port = %d", o.port)
	}
}

func TestProbeUDPPortTunnelWithoutReply(t *testing.T) {
	o := &probeFakeOpener{conn: &probeFakeConn{}}
	r := probeUDPPort(o, serverlist.Node{}, "1.1.1.1", 443, 50*time.Millisecond)
	if r.Tunnel != "established" || r.Reply || r.Error != "" {
		t.Fatalf("unexpected report: %+v", r)
	}
}

func TestProbeUDPPortOpenError(t *testing.T) {
	o := &probeFakeOpener{err: errors.New("no route to host")}
	r := probeUDPPort(o, serverlist.Node{}, "1.1.1.1", 443, 50*time.Millisecond)
	if r.Tunnel != "rejected" || r.Reply || r.Error == "" {
		t.Fatalf("unexpected report: %+v", r)
	}
}

func TestParseProbePorts(t *testing.T) {
	got, e := parseProbePorts("53, 443,,8080")
	if e != nil {
		t.Fatal(e)
	}
	if len(got) != 3 || got[0] != 53 || got[2] != 8080 {
		t.Fatalf("ports = %v", got)
	}
	for _, bad := range []string{"", "0", "70000", "abc"} {
		if _, e := parseProbePorts(bad); e == nil {
			t.Fatalf("parseProbePorts(%q) accepted", bad)
		}
	}
}

func TestGeoSourceMapping(t *testing.T) {
	ipinfo := geoSource("ipinfo.io", map[string]any{"country": "US", "region": "California", "city": "San Jose", "org": "AS54113 Fastly"})
	if !ipinfo.OK || ipinfo.Country != "US" || ipinfo.Region != "California" || ipinfo.City != "San Jose" || ipinfo.Org == "" {
		t.Fatalf("ipinfo mapping: %+v", ipinfo)
	}
	ifconfig := geoSource("ifconfig.co", map[string]any{"country_iso": "DE", "region_name": "Hesse", "city": "Frankfurt", "asn_org": "Fastly"})
	if !ifconfig.OK || ifconfig.Country != "DE" || ifconfig.Region != "Hesse" || ifconfig.City != "Frankfurt" || ifconfig.Org != "Fastly" {
		t.Fatalf("ifconfig mapping: %+v", ifconfig)
	}
}

func TestProbeWarningsAreNonDestructive(t *testing.T) {
	sources := []probeSource{
		{Source: "a", OK: true, Country: "US"},
		{Source: "b", OK: true, Country: "DE"},
		{Source: "c", Country: ""},
	}
	w := probeWarnings("US", sources)
	if len(w) != 2 {
		t.Fatalf("warnings = %v", w)
	}
	if probeWarnings("US", []probeSource{{Source: "a", OK: true, Country: "US"}}) != nil {
		t.Fatal("matching country produced a warning")
	}
	if probeWarnings("REC", []probeSource{{Source: "a", OK: true, Country: "JP"}}) != nil {
		t.Fatal("REC expected produced a country warning")
	}
}

func TestIPFamily(t *testing.T) {
	if got := ipFamily(net.ParseIP("192.0.2.1")); got != "ipv4" {
		t.Fatalf("family = %s", got)
	}
	if got := ipFamily(net.ParseIP("2001:db8::1")); got != "ipv6" {
		t.Fatalf("family = %s", got)
	}
}
