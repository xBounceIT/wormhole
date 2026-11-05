package session

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/n0madic/go-ipsec/internal/auth"
	"github.com/n0madic/go-ipsec/internal/eap"
	"github.com/n0madic/go-ipsec/internal/ikemsg"
	"github.com/n0madic/go-ipsec/internal/transport"
	"layeh.com/radius/rfc2759"
)

func TestFortinetSAMLOfflineHandshake(t *testing.T) {
	for _, mode := range []string{"success", "success-mschap", "mschap-final-msk", "mschap-extended-success", "mschap-early-success", "mschap-bad-proof", "mschap-switch-to-gtc", "switch-to-mschap", "success-ecp256", "success-ecp384", "wrong-psk", "wrong-id", "no-auth", "bad-method", "missing-eap", "bad-token-method", "failure", "early-success", "missing-next-eap", "too-many-rounds", "bad-final-auth", "changed-final-id", "closed-first", "closed-eap", "closed-final"} {
		t.Run(mode, func(t *testing.T) {
			client, server := transport.MemoryPair()
			defer client.Close()
			defer server.Close()
			init := New(Config{Server: "mem:500", FortinetSAML: true, ServerPSK: []byte("gateway-psk"), LocalID: WireID{Type: 2, Data: []byte("vpn-client")}, RemoteID: WireID{Type: 2, Data: []byte("vpn.test")}, EAPUser: "UID", EAPPass: []byte("temporary-token"), Logger: slog.New(slog.DiscardHandler), RetransmitBase: 500 * time.Millisecond, RetransmitMax: time.Second, RetransmitTries: 1})
			init.conn = client
			done := make(chan error, 1)
			go func() { defer server.Close(); done <- fortinetTestResponder(server, mode) }()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := init.IKESAInit(ctx); err != nil {
				t.Fatal(err)
			}
			err := init.IKEAuth(ctx)
			if strings.HasPrefix(mode, "success") {
				if err != nil || !init.Established() || init.Child() == nil {
					t.Fatal("SAML IPsec handshake failed", err)
				}
			} else if err == nil || init.Established() {
				t.Fatal("invalid Fortinet authentication established a child SA")
			}
			client.Close()
			server.Close()
			responderErr := <-done
			if errors.Is(responderErr, errPrematureFortinetAUTH) {
				t.Fatal(responderErr)
			}
			if strings.HasPrefix(mode, "success") && responderErr != nil {
				t.Fatal(responderErr)
			}
		})
	}
}

var errPrematureFortinetAUTH = errors.New("final AUTH sent before advertised EAP continuation completed")

func TestFortinetNotificationAcknowledgement(t *testing.T) {
	request := eap.Packet{Code: eap.CodeRequest, Identifier: 9, Type: eap.TypeNotification, Data: []byte("Signing in")}
	response, token, err := fortinetEAPResponse(request, "UID", []byte("secret"))
	if err != nil || token || response.Code != eap.CodeResponse || response.Identifier != 9 || response.Type != eap.TypeNotification || len(response.Data) != 0 {
		t.Fatal("valid EAP Notification was not acknowledged safely", err)
	}
}

func fortinetTestResponder(conn transport.Conn, mode string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rs := New(Config{Logger: slog.New(slog.DiscardHandler)})
	nr := bytes.Repeat([]byte{0x42}, 32)
	if mode == "success-ecp256" || mode == "success-ecp384" {
		raw, err := conn.Recv(ctx)
		if err != nil {
			return err
		}
		message, err := ikemsg.Parse(raw)
		if err != nil {
			return err
		}
		group := uint16(19)
		if mode == "success-ecp384" {
			group = 20
		}
		data := make([]byte, 2)
		binary.BigEndian.PutUint16(data, group)
		retry := ikemsg.Message{InitiatorSPI: message.InitiatorSPI, Exchange: ikemsg.ExchangeIKESAInit, Flags: ikemsg.FlagResponse, Payloads: ikemsg.Payloads{&ikemsg.NotifyPayload{Type: ikemsg.NotifyInvalidKEPayload, Data: data}}}
		encoded, err := retry.Marshal()
		if err != nil {
			return err
		}
		if err := conn.Send(ctx, encoded); err != nil {
			return err
		}
	}
	raw1, raw2, ni, err := respondSAInit(ctx, conn, rs, nr, gcmIKESuite())
	if err != nil {
		return err
	}
	if mode == "closed-first" {
		return nil
	}
	raw, err := conn.Recv(ctx)
	if err != nil {
		return err
	}
	header, inner, err := rs.decodeSK(raw)
	if err != nil {
		return err
	}
	var idi *ikemsg.IDiPayload
	for _, p := range inner {
		if id, ok := p.(*ikemsg.IDiPayload); ok {
			idi = id
		}
	}
	if idi == nil {
		return errors.New("missing initiator identity")
	}
	id := []byte("vpn.test")
	if mode == "wrong-id" {
		id = []byte("other.test")
	}
	signed := auth.SignedOctets(rs.ikeSA.PRF, raw2, ni, ikemsg.MarshalIDBody(2, id), rs.ikeSA.SKpr)
	key := []byte("gateway-psk")
	if mode == "wrong-psk" {
		key = []byte("wrong")
	}
	authPayload := &ikemsg.AuthPayload{Method: auth.MethodSharedKeyMIC, Data: auth.SharedSecretAuth(rs.ikeSA.PRF, key, signed)}
	if mode == "bad-method" {
		authPayload.Method = auth.MethodDigitalSignature
	}
	payloads := ikemsg.Payloads{&ikemsg.IDrPayload{IDType: 2, Data: id}}
	if mode != "no-auth" {
		payloads = append(payloads, authPayload)
	}
	request := eap.Packet{Code: eap.CodeRequest, Identifier: 1, Type: eap.TypeIdentity}
	if mode == "early-success" {
		request.Code = eap.CodeSuccess
	}
	if mode != "missing-eap" {
		payloads = append(payloads, &ikemsg.EAPPayload{Data: request.Marshal()})
	}
	send := func(payloads ikemsg.Payloads) error {
		out, err := rs.encodeSK(ikemsg.ExchangeIKEAuth, ikemsg.FlagResponse, header.MessageID, payloads)
		if err != nil {
			return err
		}
		return conn.Send(ctx, out)
	}
	if err := send(payloads); err != nil {
		return err
	}
	mschapMode := mode == "success-mschap" || strings.HasPrefix(mode, "mschap-")
	challenge := bytes.Repeat([]byte{0x11}, 16)
	initiatorKey, responderKey := rs.ikeSA.SKpi, rs.ikeSA.SKpr
	for round := 0; round < maxEAPRounds+1; round++ {
		raw, err = conn.Recv(ctx)
		if err != nil {
			return err
		}
		header, inner, err = rs.decodeSK(raw)
		if err != nil {
			return err
		}
		response, ok, err := firstEAP(inner)
		if err != nil || !ok {
			return errors.New("missing EAP response")
		}
		if round == 0 {
			if response.Type != eap.TypeIdentity || string(response.Data) != "UID" {
				return errors.New("incorrect SAML EAP identity")
			}
			if mode == "closed-eap" {
				return nil
			}
			request = eap.Packet{Code: eap.CodeRequest, Identifier: 2, Type: 6, Data: []byte("Token")}
			if mschapMode {
				request = mschapChallenge(2, challenge)
			}
			if mode == "bad-token-method" {
				request.Type = 99
			}
			if mode == "failure" {
				request.Code = eap.CodeFailure
			}
		}
		if mode == "too-many-rounds" {
			request = eap.Packet{Code: eap.CodeRequest, Identifier: byte(round + 2), Type: eap.TypeIdentity}
		}
		if round == 1 && mode != "too-many-rounds" {
			if mschapMode {
				if response.Type != eap.TypeMSCHAPv2 || len(response.Data) < 54 {
					return errors.New("missing MSCHAPv2 response")
				}
				value := response.Data[5:54]
				ntResponse := value[24:48]
				proof, err := rfc2759.GenerateAuthenticatorResponse(challenge, value[:16], ntResponse, []byte("UID"), []byte("temporary-token"))
				if err != nil {
					return err
				}
				ucs2, _ := rfc2759.ToUTF16([]byte("temporary-token"))
				phh := rfc2759.NTPasswordHash(rfc2759.NTPasswordHash(ucs2))
				msk, err := eap.DeriveMSK(phh, ntResponse)
				if err != nil {
					return err
				}
				// Fortinet's PSK/EAP profile keys final AUTH with SK_pi/SK_pr,
				// even when MSCHAPv2 produces an MSK. Do not mirror the client.
				if mode == "mschap-final-msk" {
					responderKey = msk
				}
				if mode == "mschap-bad-proof" {
					if proof[0] == '0' {
						proof = "1" + proof[1:]
					} else {
						proof = "0" + proof[1:]
					}
				}
				request = mschapSuccessRequest(3, proof)
				if mode == "mschap-early-success" {
					request = eap.Packet{Code: eap.CodeSuccess, Identifier: 3}
				}
				if mode == "mschap-switch-to-gtc" {
					request = eap.Packet{Code: eap.CodeRequest, Identifier: 3, Type: 6}
				}
			} else {
				if response.Type != 6 || string(response.Data) != "temporary-token" {
					return errors.New("SAML token was not used as EAP-GTC secret")
				}
				request = eap.Packet{Code: eap.CodeSuccess, Identifier: 3}
				if mode == "switch-to-mschap" {
					request = mschapChallenge(3, challenge)
				}
			}
		}
		if round == 2 && mschapMode {
			request = eap.Packet{Code: eap.CodeSuccess, Identifier: 4}
		}
		payloads = ikemsg.Payloads{&ikemsg.EAPPayload{Data: request.Marshal()}}
		if round == 2 && mode == "mschap-extended-success" {
			payloads = ikemsg.Payloads{&ikemsg.EAPPayload{Data: []byte{eap.CodeSuccess, 4, 0, 5, 6}}}
		}
		if mode == "missing-next-eap" {
			payloads = nil
		}
		if err := send(payloads); err != nil {
			return err
		}
		if round == 2 && mode == "mschap-extended-success" {
			raw, err := conn.Recv(ctx)
			if err != nil {
				return err
			}
			_, inner, err := rs.decodeSK(raw)
			if err != nil {
				return err
			}
			for _, p := range inner {
				if _, ok := p.(*ikemsg.AuthPayload); ok {
					return errPrematureFortinetAUTH
				}
			}
			return errors.New("unsupported continuation was not stopped")
		}
		if request.Code == eap.CodeSuccess {
			break
		}
	}
	if mode == "closed-final" {
		return nil
	}
	raw, err = conn.Recv(ctx)
	if err != nil {
		return err
	}
	header, inner, err = rs.decodeSK(raw)
	if err != nil {
		return err
	}
	var clientAuth *ikemsg.AuthPayload
	for _, p := range inner {
		if a, ok := p.(*ikemsg.AuthPayload); ok {
			clientAuth = a
		}
	}
	clientSigned := auth.SignedOctets(rs.ikeSA.PRF, raw1, nr, ikemsg.MarshalIDBody(idi.IDType, idi.Data), rs.ikeSA.SKpi)
	want := auth.SharedSecretAuth(rs.ikeSA.PRF, initiatorKey, clientSigned)
	if clientAuth == nil || !bytes.Equal(clientAuth.Data, want) {
		return errors.New("EAP-GTC final AUTH is not bound to SK_pi")
	}
	responderAuth := auth.SharedSecretAuth(rs.ikeSA.PRF, responderKey, signed)
	if mode == "bad-final-auth" {
		responderAuth[0] ^= 1
	}
	spi := make([]byte, 4)
	binary.BigEndian.PutUint32(spi, 12345)
	payloads = ikemsg.Payloads{&ikemsg.AuthPayload{Method: auth.MethodSharedKeyMIC, Data: responderAuth}, &ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildProposalForSuite(1, cbcSuite(), spi)}}}
	if mode == "changed-final-id" {
		payloads = append(payloads, &ikemsg.IDrPayload{IDType: 2, Data: []byte("other.test")})
	}
	appendTrafficSelectors(&payloads, false)
	return send(payloads)
}
