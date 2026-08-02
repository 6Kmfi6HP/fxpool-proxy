package upstream

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"fxpool-proxy/internal/serverlist"
)

// stubToken returns a fixed token and never rejects it.
type stubToken struct{}

func (stubToken) Ensure(context.Context, bool) (string, error) { return "test-token", nil }
func (stubToken) Reject(string) error                          { return nil }

// selfSigned certs for the in-process MASQUE proxy.
func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, e := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{http3.NextProtoH3},
	}
}

// startMASQUEProxy runs an in-process HTTP/3 CONNECT-UDP proxy and returns its
// URI template along with a close function.
func startMASQUEProxy(t *testing.T) (template string, closeFn func()) {
	t.Helper()
	probe, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if e != nil {
		t.Fatal(e)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close() // release; http3.Server will bind its own

	templateStr := "https://127.0.0.1:" + fmt.Sprintf("%d", port) + "/.well-known/masque/udp/{target_host}/{target_port}/"
	tmpl, e := uritemplate.New(templateStr)
	if e != nil {
		t.Fatal(e)
	}
	tlsConf := http3.ConfigureTLSConfig(testTLSConfig(t))
	srv := &http3.Server{
		Addr:            "127.0.0.1:" + fmt.Sprintf("%d", port),
		TLSConfig:       tlsConf,
		EnableDatagrams: true,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	proxy := masque.Proxy{}
	u, e := url.Parse(templateStr)
	if e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(u.Path, func(w http.ResponseWriter, r *http.Request) {
		req, err := masque.ParseProxyRequest(r, tmpl)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = proxy.Proxy(w, req)
	})
	srv.Handler = mux
	go func() { _ = srv.ListenAndServe() }()
	closeFn = func() { _ = srv.Close() }
	return templateStr, closeFn
}

// TestMASQUEUDPEndToEnd starts a local CONNECT-UDP proxy and a local UDP echo
// target, then verifies a datagram flows through the MASQUE tunnel.
func TestMASQUEUDPEndToEnd(t *testing.T) {
	tmpl, closeProxy := startMASQUEProxy(t)
	defer closeProxy()

	// Local UDP echo target.
	udpTarget, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer udpTarget.Close()
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, addr, err := udpTarget.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udpTarget.WriteTo(buf[:n], addr) // echo back
		}
	}()

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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pc, e := d.OpenUDP(ctx, node, "127.0.0.1", udpTarget.LocalAddr().(*net.UDPAddr).Port)
	if e != nil {
		t.Fatalf("OpenUDP: %v", e)
	}
	defer pc.Close()

	if _, e = pc.WriteTo([]byte("ping-over-masque"), nil); e != nil {
		t.Fatalf("WriteTo: %v", e)
	}
	buf := make([]byte, 64)
	n, _, e := pc.ReadFrom(buf)
	if e != nil {
		t.Fatalf("ReadFrom: %v", e)
	}
	if string(buf[:n]) != "ping-over-masque" {
		t.Fatalf("echo mismatch: %q", string(buf[:n]))
	}
}

// TestOpenDispatchRejectsUnknownProtocol ensures the TCP gate still fail-closes.
func TestOpenDispatchRejectsUnknownProtocol(t *testing.T) {
	d := &Dialer{Tokens: stubToken{}}
	// Unknown protocol via TCP Open.
	_, e := d.Open(context.Background(), serverlist.Node{Protocol: "weird", Scheme: "https", Supported: true}, "h", 80)
	if e == nil {
		t.Fatal("expected error for unknown protocol")
	}
	if !errors.Is(e, errUnsupportedProtocol) {
		t.Fatalf("unexpected error: %v", e)
	}
	// MASQUE node via TCP Open is rejected (TCP tunnel cannot carry datagrams).
	_, e2 := d.Open(context.Background(), serverlist.Node{Protocol: "masque", Scheme: "https", Supported: true}, "h", 80)
	if e2 == nil {
		t.Fatal("expected error opening masque node over TCP Open")
	}
	if !errors.Is(e2, errUnsupportedProtocol) {
		t.Fatalf("unexpected error: %v", e2)
	}
	// connect node via OpenUDP is rejected.
	_, e3 := d.OpenUDP(context.Background(), serverlist.Node{Protocol: "connect", Scheme: "https", Supported: true}, "h", 80)
	if e3 == nil {
		t.Fatal("expected error opening connect node over UDP")
	}
}
