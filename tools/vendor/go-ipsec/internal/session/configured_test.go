package session

import (
	"github.com/n0madic/go-ipsec/internal/cryptosuite"
	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/ikemsg"
	"github.com/n0madic/go-ipsec/internal/ikesa"
	"testing"
)

func TestConfiguredIKEv2OfflineMatrix(t *testing.T) {
	for id := cryptosuite.FirstCBC; id < cryptosuite.FirstCBC+20; id++ {
		ike := mustIKESuite(t, ikesa.Suite(id))
		child := mustSuite(t, esp.Suite(id))
		t.Run(ike.name(), func(t *testing.T) {
			testOfflineHandshake(t, child, ike, true)
			offer := buildProposalForSuite(1, ike, nil, 2, 21)
			if !suiteMatches(ike, offer) || !proposalHasDHGroup(offer, 21) {
				t.Fatal("configured transforms not offered")
			}
			other := ike
			other.prfID = 65535
			if suiteMatches(other, offer) {
				t.Fatal("unoffered PRF selected")
			}
			for _, transform := range offer.Transforms {
				if transform.Type == ikemsg.TransformEncr && ike.encrID == 3 && transform.HasKeyLength {
					t.Fatal("fixed-size 3DES has key length attribute")
				}
			}
		})
	}
}
