package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestConfigDecodesPhysicalTransportPlan(t *testing.T) {
	const payload = `{
		"profile_ovpn":"client\nremote vpn.example.test 443 tcp\n",
		"transport_adapter_ids":["adapter-a","adapter-b"],
		"transport_remotes":[
			{"host":"vpn.example.test","port":"443","protocol":"tcp"},
			{"host":"198.51.100.7","port":"1194","protocol":"udp4"}
		]
	}`

	var cfg config
	if err := json.Unmarshal([]byte(payload), &cfg); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(cfg.TransportAdapterIDs) != 2 || cfg.TransportAdapterIDs[1] != "adapter-b" {
		t.Fatalf("unexpected adapter IDs: %#v", cfg.TransportAdapterIDs)
	}
	if len(cfg.TransportRemotes) != 2 {
		t.Fatalf("unexpected remotes: %#v", cfg.TransportRemotes)
	}
	if got := cfg.TransportRemotes[0]; got.Host != "vpn.example.test" || got.Port != "443" || got.Protocol != "tcp" {
		t.Fatalf("unexpected first remote: %#v", got)
	}
	if got := cfg.TransportRemotes[1]; got.Host != "198.51.100.7" || got.Protocol != "udp4" {
		t.Fatalf("unexpected second remote: %#v", got)
	}
}

func TestValidateTransportIsolationRequiresBothHalves(t *testing.T) {
	t.Parallel()

	err := validateTransportIsolation(config{
		TransportAdapterIDs: []string{"adapter-a"},
	})
	if err == nil || !strings.Contains(err.Error(), "must be supplied together") {
		t.Fatalf("validateTransportIsolation() error = %v, want paired-field error", err)
	}
}

func TestValidateTransportIsolationRejectsIncompleteRemote(t *testing.T) {
	t.Parallel()

	err := validateTransportIsolation(config{
		TransportAdapterIDs: []string{"adapter-a"},
		TransportRemotes:    []transportRemote{{Host: "vpn.example.test", Port: "443"}},
	})
	if err == nil || !strings.Contains(err.Error(), "incomplete endpoint") {
		t.Fatalf("validateTransportIsolation() error = %v, want incomplete-endpoint error", err)
	}
}
