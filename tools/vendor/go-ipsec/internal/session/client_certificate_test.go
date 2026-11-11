package session

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"testing"
	"time"

	"github.com/n0madic/go-ipsec/internal/auth"
	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/ikemsg"
)

func TestClientCertificateExchange(t *testing.T) {
	leaf, key, roots := makeTestCert(t, "vpn.test")
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "trusted", true: "untrusted"}[reject], func(t *testing.T) {
			init, resp, peer := mirrorSessions(t)
			defer init.Close()
			defer resp.Close()
			init.cfg.ClientCertificate = &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}
			init.cfg.RootCAs = roots
			init.cfg.LocalID = WireID{Type: 2, Data: []byte("client.test")}
			init.cfg.RemoteID = WireID{Type: 2, Data: []byte("vpn.test")}
			init.initSAInitReq = []byte("request")
			init.initSAInitRsp = []byte("response")
			init.nonceI = make([]byte, 32)
			init.nonceR = make([]byte, 32)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				raw, err := peer.Recv(ctx)
				if err != nil {
					done <- err
					return
				}
				header, payloads, err := resp.decodeSK(raw)
				if err != nil {
					done <- err
					return
				}
				for _, p := range payloads {
					if proof, ok := p.(*ikemsg.AuthPayload); ok {
						if err := auth.VerifyCertAuth(proof.Method, proof.Data, init.initiatorSignedOctets(), leaf); err != nil {
							done <- err
							return
						}
					}
				}
				idr := &ikemsg.IDrPayload{IDType: 2, Data: []byte("vpn.test")}
				signature, err := signRFC7427(key, init.responderSignedOctets(ikemsg.MarshalIDBody(idr.IDType, idr.Data)))
				if err != nil {
					done <- err
					return
				}
				if reject {
					signature[len(signature)-1] ^= 1
				}
				response := ikemsg.Payloads{idr, &ikemsg.CertPayload{Encoding: 4, Data: leaf.Raw}, &ikemsg.AuthPayload{Method: 14, Data: signature}, &ikemsg.SAPayload{Proposals: buildProposals([]byte{1, 2, 3, 4}, []espSuite{mustSuite(t, esp.SuiteAESGCM256)})}}
				wire, err := resp.encodeSK(ikemsg.ExchangeIKEAuth, ikemsg.FlagResponse, header.MessageID, response)
				if err == nil {
					err = peer.Send(ctx, wire)
				}
				done <- err
			}()
			err := init.IKEAuth(ctx)
			if (err != nil) != reject {
				t.Fatalf("certificate authentication result: %v", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if init.Established() == reject {
				t.Fatal("incorrect certificate session state")
			}
		})
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	method, signature, err := signClientCertificate(ec, []byte("signed message"))
	if err != nil || method != 14 || len(signature) == 0 {
		t.Fatal("ECDSA signing failed", err)
	}
	if _, _, err := signClientCertificate(nil, nil); err == nil {
		t.Fatal("unsupported private key accepted")
	}
}

func TestFortinetCanDisableDPD(t *testing.T) {
	init, resp, peer := mirrorSessions(t)
	defer init.Close()
	defer resp.Close()
	init.cfg.DisableDPD = true
	if err := init.initiateDPD(context.Background(), true); err != nil || init.pending != nil {
		t.Fatal("disabled DPD created an exchange", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := peer.Recv(ctx); err == nil {
		t.Fatal("disabled DPD sent a packet")
	}
}
