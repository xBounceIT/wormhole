package ikev1

import (
	"net"
	"testing"
)

func TestFortinetWithoutNATTAndDHCPSelectors(t *testing.T) {
	for _, mode := range []Mode{ModeMain, ModeAggressive} {
		cfg := Config{Mode: mode, Phase2: Phase2RemoteAccess, PSK: []byte("fixture"), DisableNATT: true, DHCP: true, Groups: []uint16{14}, Proposals: []Proposal{{Encryption: 7, KeyBits: 256, Hash: 4}}, ESPProposals: []Proposal{{Encryption: 7, KeyBits: 256, Hash: 5}}, LocalIP: net.IPv4(192, 0, 2, 1), PeerIP: net.IPv4(192, 0, 2, 2)}
		other := cfg
		other.LocalIP, other.PeerIP = cfg.PeerIP, cfg.LocalIP
		p := newPair(t, cfg, other)
		defer p.initiator.Close()
		defer p.responder.Close()
		p.run(t)
		p.mu.Lock()
		if p.initErr != nil || p.respErr != nil || p.initRes == nil || p.respRes == nil {
			t.Fatal("raw ESP handshake failed", p.initErr, p.respErr)
		}
		p.mu.Unlock()
		for _, s := range []*Session{p.initiator, p.responder} {
			s.mu.Lock()
			if s.floated || s.peerNATT || len(s.natTVendorPayloads()) != 0 {
				t.Error("NAT-T re-enabled despite profile")
			}
			if proposals := s.defaultESPProposals(); len(proposals) != 1 || proposals[0].encap != encapTunnel {
				t.Error("plain ESP encapsulation not negotiated")
			}
			a, b, err := s.phase2Selectors()
			if err != nil || a.idType != anySubnetID().idType || b.idType != anySubnetID().idType {
				t.Error("DHCP selectors require an address before DHCP")
			}
			s.mu.Unlock()
		}
	}
}
