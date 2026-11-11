package session

import (
	"bytes"
	"context"
	"fmt"
	"github.com/n0madic/go-ipsec/internal/cryptosuite"
	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/ikemsg"
	"github.com/n0madic/go-ipsec/internal/ikesa"
	"testing"
)

func TestChildRekeyRejectsNonceOutsideNegotiatedPRFBounds(t *testing.T) {
	for _, length := range []int{1, 16, 257} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			s, r, peer := mirrorSessions(t)
			defer s.Close()
			defer r.Close()
			defer peer.Close()
			id, _ := cryptosuite.ID(2, 4)
			ni, nr := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
			if err := s.ikeSA.Derive(ikesa.Suite(id), ikesa.Initiator, s.initiatorSPI, s.responderSPI, ni, nr, []byte{3}); err != nil {
				t.Fatal(err)
			}
			if err := r.ikeSA.Derive(ikesa.Suite(id), ikesa.Responder, r.initiatorSPI, r.responderSPI, ni, nr, []byte{3}); err != nil {
				t.Fatal(err)
			}
			s.child = &ChildSA{InitiatorSPI: 1, ResponderSPI: 2}
			dp := &fakeDataPlane{}
			s.SetDataPlane(dp)
			request := serverChildRekey(t, r, 5, []byte{0, 0, 0, 2}, []byte{0, 0, 0, 3}, make([]byte, length))
			ctx, cancel := recvCtx(t)
			defer cancel()
			s.handleInbound(ctx, request, func() {})
			if len(dp.updates) != 0 {
				t.Fatal("invalid nonce installed a Child SA")
			}
			response := ikemsg.Payloads{&ikemsg.SAPayload{Proposals: buildProposals([]byte{0, 0, 0, 3}, []espSuite{mustSuite(t, esp.SuiteAESGCM256)})}, &ikemsg.NoncePayload{Data: make([]byte, length)}}
			p := &pendingExchange{child: &childRekeyCtx{newInSPI: 4, ni: ni}}
			if err := s.completeChildRekey(context.Background(), response, p); err == nil {
				t.Fatal("invalid response nonce accepted")
			}
		})
	}
}
