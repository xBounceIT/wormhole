package ipsec

import (
	"testing"
	"time"
)

func TestFortinetFullIKEv2Options(t *testing.T) {
	for e := 0; e < 4; e++ {
		for a := 0; a < 5; a++ {
			o := DefaultFortinetOptions()
			o.Phase1Encryption = e
			o.Phase2Encryption = e
			o.Phase1Authentication = a
			o.Phase2Authentication = a
			o.DhGroups = "1,2,5,14,15,16,17,18,19,20,21"
			o.Pfs = true
			o.PfsGroup = 21
			o.NatTraversal = false
			o.EnableLocalLan = true
			o.ReplayDetection = false
			o.Phase2TimeLifetime = false
			o.Phase2ByteLifetime = true
			o.AddressAssignment = 2
			c, err := ConfigureFortinet(Config{Server: "vpn.test:500", PSK: "key", LocalID: FQDN("client")}, o, "", "", "")
			if err != nil {
				t.Fatal(err)
			}
			if err = c.validate(); err != nil {
				t.Fatal(err)
			}
			if len(c.IKECipherSuites) == 0 || len(c.DHGroups) != 11 || !c.DisableNATT || !c.DisableReplay || c.RekeyLifetime != 0 || !c.DisableChildTimeLifetime || c.RekeyMaxBytes != 5120*1024 || c.AddressAssignment != 2 || c.ChildPFSGroup != 21 || c.IKERekeyLifetime != 14400*time.Second {
				t.Fatal("profile options were lost")
			}
			sc := toSessionConfig(c)
			if !sc.DisableNATT || sc.AddressAssignment != 2 || sc.ChildPFSGroup != 21 || sc.RekeyLifetime != 0 || sc.RekeyMaxBytes != c.RekeyMaxBytes {
				t.Fatal("session translation lost profile")
			}
			o.AddressAssignment = 1
			o.ManualAddress = "10.42.0.9"
			o.ManualDns = "10.42.0.53"
			c, err = ConfigureFortinet(c, o, "", "", "")
			if err != nil || c.ManualAddress != o.ManualAddress {
				t.Fatal(err)
			}
		}
	}
}

func TestFortinetLifetimeBounds(t *testing.T) {
	for _, mutate := range []func(*FortinetOptions){func(o *FortinetOptions) { o.Phase1Lifetime = 2147483648 }, func(o *FortinetOptions) { o.Phase2Lifetime = 2147483648 }, func(o *FortinetOptions) { o.Phase2LifetimeKb = 2147483648 }} {
		o := DefaultFortinetOptions()
		mutate(&o)
		if _, err := ConfigureFortinet(Config{}, o, "", "", ""); err == nil {
			t.Fatal("oversized lifetime accepted")
		}
	}
}
