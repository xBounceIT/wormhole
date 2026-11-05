package session

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/n0madic/go-ipsec/internal/ikemsg"
	"github.com/n0madic/go-ipsec/internal/ikesa"
)

// The first Child SA is keyed from the IKE SA. RFC 7296 section 1.2 excludes
// a separate key exchange and non-NONE DH transforms from IKE_AUTH.
func validateInitialChildSA(payloads ikemsg.Payloads) error {
	var sawSA bool
	for _, payload := range payloads {
		switch payload := payload.(type) {
		case *ikemsg.SAPayload:
			sawSA = len(payload.Proposals) > 0
			for _, proposal := range payload.Proposals {
				if len(proposal.ByType(ikemsg.TransformDH)) != 0 {
					return errors.New("initial Child SA must omit DH transforms")
				}
			}
		case *ikemsg.KEPayload:
			return errors.New("initial Child SA must not include a key exchange")
		}
	}
	if !sawSA {
		return errors.New("initial Child SA proposal missing")
	}
	return nil
}

func TestFortinetSAInitAdvertisesSupportedDHGroups(t *testing.T) {
	for _, group := range []uint16{31, 14, 19, 20} {
		for _, cookie := range [][]byte{nil, {1, 2, 3}} {
			t.Run(fmt.Sprintf("group-%d/cookie-%t", group, len(cookie) > 0), func(t *testing.T) {
				s, responder := newSAInitOnlySession(nil)
				defer s.conn.Close()
				defer responder.Close()
				var err error
				s.dh, err = ikesa.NewDH(group)
				if err != nil {
					t.Fatal(err)
				}
				s.nonceI = bytes.Repeat([]byte{1}, nonceLen)
				_, raw, err := s.buildSAInit(cookie)
				if err != nil {
					t.Fatal(err)
				}
				message, err := ikemsg.Parse(raw)
				if err != nil {
					t.Fatal(err)
				}
				var sawSA, sawKE bool
				for _, payload := range message.Payloads {
					switch payload := payload.(type) {
					case *ikemsg.SAPayload:
						sawSA = len(payload.Proposals) > 0
						for _, proposal := range payload.Proposals {
							for _, required := range []uint16{31, 14, 19, 20} {
								if !proposalHasDHGroup(proposal, required) {
									t.Errorf("proposal %d does not advertise DH group %d", proposal.Number, required)
								}
							}
						}
					case *ikemsg.KEPayload:
						sawKE = payload.Group == group && bytes.Equal(payload.Data, s.dh.Public)
					}
				}
				if !sawSA || !sawKE {
					t.Fatal("SA_INIT is missing its proposals or current key exchange")
				}
			})
		}
	}
}
