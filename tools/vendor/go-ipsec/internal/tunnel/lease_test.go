package tunnel

import (
	"context"
	"github.com/n0madic/go-ipsec/internal/esp"
	tun2net "github.com/n0madic/go-tun2net"
	"net/netip"
	"testing"
)

func TestLeaseUpdatePreservesRekeyedSA(t *testing.T) {
	key := make([]byte, 32)
	old, err := esp.NewSA(0, 1, 2, key, key, key, key, 64)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := esp.NewSA(0, 3, 4, key, key, key, key, 64)
	if err != nil {
		t.Fatal(err)
	}
	tun := New(old, func(context.Context, []byte) error { return nil }, tun2net.TunConfig{})
	defer tun.Close()
	tun.SwapSA(fresh)
	cfg := tun2net.TunConfig{LocalIP: netip.MustParseAddr("10.42.0.9")}
	calls := 0
	detach := tun.OnReconfigure(func(got tun2net.TunConfig) {
		calls++
		if got.LocalIP != cfg.LocalIP {
			t.Error("lease update missing")
		}
	})
	defer detach()
	tun.UpdateConfig(cfg)
	if tun.conn.sa.load() != fresh || calls != 1 {
		t.Fatal("DHCP update restored superseded SA")
	}
	if _, err = tun.EncryptControl([]byte{0x45, 1}); err != nil {
		t.Fatal(err)
	}
	if tun.SABytes() == 0 || tun.SAExpired() {
		t.Fatal("live SA counters incorrect")
	}
}
