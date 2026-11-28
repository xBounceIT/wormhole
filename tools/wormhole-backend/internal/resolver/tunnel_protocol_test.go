package resolver

import "testing"

func TestTunnelProtocolsKeepWebAndReleaseIntentsDistinct(t *testing.T) {
	for protocol, want := range map[int]string{0: "ssh", 1: "rdp", 3: "http", 4: "https", 6: "vnc", 7: "sftp", -1: "", 2: "", 5: "", 99: ""} {
		if got := TunnelProtocol(protocol); got != want {
			t.Fatal(protocol, got, want)
		}
	}
	if DefaultPath(3) != "reveal" || DefaultPath(4) != "reveal" {
		t.Fatal("route names changed release authorization intents")
	}
}
