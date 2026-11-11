package session

import (
	"context"
	"errors"

	"github.com/n0madic/go-ipsec/internal/auth"
	"github.com/n0madic/go-ipsec/internal/eap"
	"github.com/n0madic/go-ipsec/internal/ikemsg"
)

// Fortinet's PSK/EAP profile uses SK_pi/SK_pr for final AUTH, including when
// MSCHAPv2 produces an MSK. Authenticate the responder with the PSK
// before disclosing the temporary SAML token, and require a token exchange
// before accepting EAP-Success. Never weaken the standard MSCHAPv2 path.
func (s *Session) ikeAuthFortinetSAML(ctx context.Context) error {
	spi, err := s.allocChildSPI()
	if err != nil {
		return err
	}
	first := ikemsg.Payloads{
		&ikemsg.IDiPayload{IDType: ikemsg.IDType(s.cfg.LocalID.Type), Data: s.cfg.LocalID.Data},
		&ikemsg.SAPayload{Proposals: buildProposals(spi, s.enabledESPSuites())},
	}
	if s.cfg.ClientCertificate != nil {
		for _, cert := range s.cfg.ClientCertificate.Certificate {
			first = append(first, &ikemsg.CertPayload{Encoding: 4, Data: cert})
		}
	}
	appendTrafficSelectors(&first, s.cfg.RequestIPv6)
	if s.cfg.AddressAssignment == 0 {
		buildCPRequest(&first, s.cfg.RequestIPv6)
	}
	payloads, err := s.exchangeSK(ctx, ikemsg.ExchangeIKEAuth, s.messageID, first)
	if err != nil {
		return err
	}
	s.messageID++
	request, err := s.handleAuthResponse(payloads)
	if err != nil {
		return err
	}
	sentToken := false
	usedMSCHAP := false
	usedGTC := false
	mschap := eap.NewMSCHAPv2(s.cfg.EAPUser, s.cfg.EAPPass)
	defer mschap.Wipe()
	for round := 0; round < maxEAPRounds; round++ {
		if request.Code == eap.CodeSuccess {
			if !sentToken {
				return errors.New("session: Fortinet EAP succeeded without token authentication")
			}
			if usedMSCHAP && !mschap.Verified() {
				return errors.New("session: Fortinet MSCHAPv2 server proof is missing")
			}
			final, err := s.exchangeSK(ctx, ikemsg.ExchangeIKEAuth, s.messageID, ikemsg.Payloads{
				&ikemsg.AuthPayload{Method: auth.MethodSharedKeyMIC, Data: s.computeInitiatorAuth(s.ikeSA.SKpi)},
			})
			if err != nil {
				return err
			}
			s.messageID++
			return s.handleFinalAuthResponse(final, s.ikeSA.SKpr)
		}
		var response eap.Packet
		var token bool
		if request.Code == eap.CodeRequest && request.Type == eap.TypeMSCHAPv2 {
			if usedGTC {
				return errors.New("session: Fortinet changed EAP method during authentication")
			}
			usedMSCHAP = true
			response, err = buildEAPResponse(mschap, request)
			token = true
		} else {
			if usedMSCHAP && request.Type == 6 {
				return errors.New("session: Fortinet changed EAP method during authentication")
			}
			response, token, err = fortinetEAPResponse(request, s.cfg.EAPUser, s.cfg.EAPPass)
			usedGTC = usedGTC || token
		}
		if err != nil {
			return err
		}
		sentToken = sentToken || token
		payloads, err = s.exchangeSK(ctx, ikemsg.ExchangeIKEAuth, s.messageID, ikemsg.Payloads{&ikemsg.EAPPayload{Data: response.Marshal()}})
		if err != nil {
			return err
		}
		s.messageID++
		if err := firstNotifyError(payloads); err != nil {
			return err
		}
		var ok bool
		request, ok, err = firstEAP(payloads)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("session: Fortinet EAP response missing")
		}
	}
	return errors.New("session: Fortinet EAP round limit exceeded")
}

func fortinetEAPResponse(request eap.Packet, uid string, token []byte) (eap.Packet, bool, error) {
	response := eap.Packet{Code: eap.CodeResponse, Identifier: request.Identifier, Type: request.Type}
	if request.Code != eap.CodeRequest {
		return response, false, errors.New("session: Fortinet EAP authentication failed")
	}
	switch request.Type {
	case eap.TypeIdentity:
		response.Data = []byte(uid)
		return response, false, nil
	case eap.TypeNotification:
		return response, false, nil
	case 6: // EAP Generic Token Card, RFC 3748 section 5.6
		response.Data = append([]byte(nil), token...)
		return response, true, nil
	default:
		return response, false, errors.New("session: Fortinet requires an unsupported EAP method")
	}
}
