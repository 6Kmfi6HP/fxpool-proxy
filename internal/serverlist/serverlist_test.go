package serverlist

import (
	"testing"
)

func TestEvaluateFailsClosed(t *testing.T) {
	if !Evaluate(`env.version|versionCompare("151.0a1") >= 0 && env.country != "CN"`, "155.0a1", "US") {
		t.Fatal("known expression rejected")
	}
	if Evaluate(`env.unsupported == true`, "155.0a1", "US") {
		t.Fatal("unknown expression accepted")
	}
}
func TestParseProtocolSelection(t *testing.T) {
	raw := []byte(`{"data":[{"id":"de","code":"DE","name":"Germany","cities":[{"code":"fra","name":"Frankfurt","servers":[{"hostname":"x.example","port":2499,"protocols":[{"protocol":"masque","scheme":"https"},{"protocol":"connect","scheme":"https"}]}]}]},{"id":"mx","code":"MX","cities":[{"code":"q","servers":[{"hostname":"m.example","protocols":[{"protocol":"masque"}]}]}]}]}`)
	n, e := Parse(raw, "155.0a1", "US", false)
	if e != nil {
		t.Fatal(e)
	}
	if len(n) != 2 || n[0].Protocol != "connect" || !n[0].Supported || n[1].Supported {
		t.Fatalf("unexpected nodes: %#v", n)
	}
}
