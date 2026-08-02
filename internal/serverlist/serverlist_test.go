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
	if n[0].TemplateString != "" {
		t.Fatalf("de should have no template: %#v", n[0])
	}
}
func TestParsePrefersMasqueWithTemplate(t *testing.T) {
	raw := []byte(`{"data":[{"id":"de","code":"DE","name":"Germany","cities":[{"code":"fra","name":"Frankfurt","servers":[{"hostname":"mq.example","port":2499,"protocols":[{"protocol":"masque","scheme":"https","templateString":"https://mq.example/.well-known/masque/udp/{target_host}/{target_port}/"},{"protocol":"connect","scheme":"https"}]}]}]}]}`)
	n, e := Parse(raw, "155.0a1", "US", false)
	if e != nil {
		t.Fatal(e)
	}
	if len(n) != 1 {
		t.Fatalf("expected 1 node, got %d", len(n))
	}
	if n[0].Protocol != "masque" || !n[0].Supported {
		t.Fatalf("expected supported masque node, got %#v", n[0])
	}
	if n[0].TemplateString != "https://mq.example/.well-known/masque/udp/{target_host}/{target_port}/" {
		t.Fatalf("unexpected template: %#v", n[0].TemplateString)
	}
}
func TestParseMasqueWithoutTemplateFallsBackToConnect(t *testing.T) {
	// masque entry without a template should not block a usable connect entry.
	raw := []byte(`{"data":[{"id":"fr","code":"FR","name":"France","cities":[{"code":"par","servers":[{"hostname":"f.example","protocols":[{"protocol":"masque","scheme":"https"},{"protocol":"connect","scheme":"https","host":"f.connect.example"}]}]}]}]}`)
	n, e := Parse(raw, "155.0a1", "US", false)
	if e != nil {
		t.Fatal(e)
	}
	if len(n) != 1 || n[0].Protocol != "connect" || !n[0].Supported {
		t.Fatalf("expected fallback to connect, got %#v", n)
	}
}
