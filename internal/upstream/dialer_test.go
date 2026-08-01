package upstream

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"testing"
)

// This captures the net/http ownership rule that caused successful CONNECT
// tunnels to be closed before a nested TLS handshake could begin.
func TestSuccessfulConnectBodyMustRemainOpen(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { _, _ = io.WriteString(server, "HTTP/1.1 200 Connection Established\r\n\r\nhello") }()
	resp, e := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodConnect})
	if e != nil {
		t.Fatal(e)
	}
	buf := make([]byte, 5)
	if _, e = io.ReadFull(resp.Body, buf); e != nil {
		t.Fatal(e)
	}
	if string(buf) != "hello" {
		t.Fatalf("got %q", buf)
	}
}
