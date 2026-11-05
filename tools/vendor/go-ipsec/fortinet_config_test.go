package ipsec

import (
	"context"
	"github.com/n0madic/go-ipsec/internal/session"
	"strings"
	"testing"
	"time"
)

func TestFortinetSAMLConfig(t *testing.T) {
	valid := Config{Server: "vpn.test:500", FortinetSAML: true, ServerPSK: "private-psk", EAP: EAPMSCHAPv2{Username: "UID", Password: "private-token"}}
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	internal := toSessionConfig(valid)
	if !internal.FortinetSAML || string(internal.ServerPSK) != "private-psk" || internal.EAPUser != "UID" {
		t.Fatal("Fortinet mode not propagated")
	}
	if strings.Contains(valid.String(), "private") {
		t.Fatal("config exposed secrets")
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.FortinetSAML = false }, func(c *Config) { c.ServerPSK = "" }, func(c *Config) { c.EAP.Username = "" }, func(c *Config) { c.EAP.Password = "" }, func(c *Config) { c.PSK = "conflicting" }} {
		cfg := valid
		mutate(&cfg)
		if err := cfg.validate(); err == nil {
			t.Fatal("invalid Fortinet config accepted")
		}
	}
}

func TestFortinetOwnerNotifiedWhenWorkerFails(t *testing.T) {
	notified := make(chan struct{}, 1)
	reconnect := false
	c := newClient(Config{Logger: discardLogger(), AutoReconnect: &reconnect, OnDead: func() {
		select {
		case notified <- struct{}{}:
		default:
		}
	}})
	// A worker using an invalid transport panics. The worker manager must
	// cancel the owning lease through the same path as a dead IKE peer.
	sess := session.New(session.Config{Logger: discardLogger()})
	c.session.Store(sess)
	c.startWorkers(sess)
	select {
	case <-notified:
	case <-time.After(time.Second):
		t.Fatal("owner was not notified of worker failure")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { c.Close(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("worker failure deadlocked teardown")
	}
}
