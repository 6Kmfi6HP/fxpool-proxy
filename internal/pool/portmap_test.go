package pool

import (
	"fxpool-proxy/internal/serverlist"
	"path/filepath"
	"testing"
)

func TestPortMapStableAcrossReorder(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ports.json")
	a := serverlist.Node{Country: "US", City: "a", Hostname: "a.example", Port: 2499, Protocol: "connect", RecordID: "a"}
	b := serverlist.Node{Country: "DE", City: "b", Hostname: "b.example", Port: 2499, Protocol: "connect", RecordID: "b"}
	one, e := AssignPorts(p, []serverlist.Node{a, b}, 21000, 31000)
	if e != nil {
		t.Fatal(e)
	}
	two, e := AssignPorts(p, []serverlist.Node{b, a}, 21000, 31000)
	if e != nil {
		t.Fatal(e)
	}
	if one[a.StableID()] != two[a.StableID()] || one[b.StableID()] != two[b.StableID()] {
		t.Fatal("ports drifted")
	}
}
