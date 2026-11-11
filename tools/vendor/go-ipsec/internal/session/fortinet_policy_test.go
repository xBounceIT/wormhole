package session

import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/n0madic/go-ipsec/internal/ikemsg"
	"github.com/n0madic/go-ipsec/internal/ikesa"
	"testing"
	"time"
)

type volumePolicyPlane struct {
	fakeDataPlane
	bytes   uint64
	expired bool
}

func (p *volumePolicyPlane) ChildSABytes() uint64 { return p.bytes }
func (p *volumePolicyPlane) ChildSAExpired() bool { return p.expired }
func TestFortinetLifecyclePolicies(t *testing.T) {
	for _, mode := range []string{"ike-time-with-child-disabled", "bytes-with-child-disabled", "hard-child-expiry", "hard-ike-expiry"} {
		t.Run(mode, func(t *testing.T) {
			s, r, peer := mirrorSessions(t)
			defer s.Close()
			defer r.Close()
			defer peer.Close()
			s.cfg.RekeyLifetime = 0
			s.cfg.IKERekeyLifetime = time.Hour
			s.ikeInstalledAt = time.Now()
			s.child = &ChildSA{InitiatorSPI: 1, ResponderSPI: 2}
			s.ikeDHGroup = 14
			dp := &volumePolicyPlane{}
			s.SetDataPlane(dp)
			switch mode {
			case "ike-time-with-child-disabled":
				s.nextIKERekey = time.Now().Add(-time.Second)
			case "bytes-with-child-disabled":
				s.cfg.RekeyMaxBytes = 1000
				dp.bytes = 900
			case "hard-child-expiry":
				dp.expired = true
			case "hard-ike-expiry":
				s.ikeInstalledAt = time.Now().Add(-2 * time.Hour)
			}
			dead := false
			exit := s.housekeeping(context.Background(), func() { dead = true })
			if mode == "hard-child-expiry" || mode == "hard-ike-expiry" {
				if !exit || !dead {
					t.Fatal("expired key was retained")
				}
				return
			}
			if exit || dead || s.pending == nil {
				t.Fatal("renewal was not initiated")
			}
			want := exChildRekey
			if mode == "ike-time-with-child-disabled" {
				want = exIKERekey
			}
			if s.pending.kind != want {
				t.Fatal("wrong renewal")
			}
		})
	}
}
func TestFortinetStrictPFS(t *testing.T) {
	for _, mode := range []string{"wrong-group", "disabled", "missing", "accepted"} {
		t.Run(mode, func(t *testing.T) {
			s, r, peer := mirrorSessions(t)
			defer s.Close()
			defer r.Close()
			defer peer.Close()
			s.child = &ChildSA{InitiatorSPI: 1, ResponderSPI: 2}
			s.cfg.StrictChildPFS = true
			s.cfg.ChildSAPFS = mode != "disabled"
			s.cfg.ChildPFSGroup = 21
			s.childPFSGroup = 21
			s.childPFS = s.cfg.ChildSAPFS
			dp := &fakeDataPlane{}
			s.SetDataPlane(dp)
			group := uint16(14)
			if mode == "accepted" {
				group = 21
			}
			dh, err := ikesa.NewDH(group)
			if err != nil {
				t.Fatal(err)
			}
			raw := buildServerChildPFSRekey(t, r, 5, bytes.Repeat([]byte{1}, 32), []byte{0, 0, 0, 3}, group, group, dh.Public)
			if mode == "missing" {
				raw = serverChildRekey(t, r, 5, []byte{0, 0, 0, 2}, []byte{0, 0, 0, 3}, bytes.Repeat([]byte{1}, 32))
			}
			ctx, cancel := recvCtx(t)
			defer cancel()
			s.handleInbound(ctx, raw, func() {})
			wire, err := peer.Recv(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, inner, _, err := r.decodeIKE(wire)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "accepted" {
				if len(dp.updates) != 1 || s.childRekeyGroup() != 21 {
					t.Fatal("configured PFS group rejected")
				}
				return
			}
			if len(dp.updates) != 0 {
				t.Fatal("PFS policy silently changed")
			}
			found := false
			for _, payload := range inner {
				if n, ok := payload.(*ikemsg.NotifyPayload); ok {
					if mode == "wrong-group" {
						found = n.Type == ikemsg.NotifyInvalidKEPayload && len(n.Data) == 2 && binary.BigEndian.Uint16(n.Data) == 21
					} else {
						found = n.Type == ikemsg.NotifyNoProposalChosen
					}
				}
			}
			if !found {
				t.Fatal("no actionable PFS rejection")
			}
		})
	}
}
