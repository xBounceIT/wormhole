package session

import (
	"errors"
	"fmt"
	"time"

	"github.com/n0madic/go-ipsec/internal/eap"
	"github.com/n0madic/go-ipsec/internal/ikemsg"
	"github.com/n0madic/go-ipsec/internal/ikesa"
)

// ikeRoleBit returns the IKEv2 header Initiator flag for an SA role: set when we
// are that SA's original initiator, cleared when we are its responder (RFC 7296
// §3.1). The Response bit is ORed in by the caller. After a server-initiated IKE
// rekey our new SA can have Role == Responder, so origination flags must follow
// the role rather than be hardcoded.
func ikeRoleBit(role ikesa.Role) ikemsg.Flags {
	if role == ikesa.Initiator {
		return ikemsg.FlagInitiator
	}
	return 0
}

// encodeSK encrypts the inner payloads into an SK{} message under the current
// IKE SA and returns the wire bytes.
func (s *Session) encodeSK(exchangeType ikemsg.ExchangeType, flags ikemsg.Flags, msgID uint32, inner ikemsg.Payloads) ([]byte, error) {
	return encodeSKWith(s.ikeSA, s.initiatorSPI, s.responderSPI, exchangeType, flags, msgID, inner)
}

// encodeSKWith encrypts under a specific IKE SA context. Rekey uses this to send
// the DELETE of an old IKE SA under that old SA.
func encodeSKWith(ike *ikesa.IKESA, spii, spir uint64, exchangeType ikemsg.ExchangeType, flags ikemsg.Flags, msgID uint32, inner ikemsg.Payloads) ([]byte, error) {
	firstType, plaintext, err := inner.Marshal()
	if err != nil {
		return nil, fmt.Errorf("session: encode inner payloads: %w", err)
	}
	skData, err := ike.EncryptToSK(plaintext)
	if err != nil {
		return nil, err
	}
	m := &ikemsg.Message{
		InitiatorSPI: spii,
		ResponderSPI: spir,
		Exchange:     exchangeType,
		Flags:        flags,
		MessageID:    msgID,
		Payloads:     ikemsg.Payloads{&ikemsg.EncryptedPayload{InnerFirst: firstType, Data: skData}},
	}
	raw, err := m.Marshal()
	if err != nil {
		return nil, fmt.Errorf("session: encode SK message: %w", err)
	}
	if err := ike.FinalizeSK(raw, len(skData)); err != nil {
		return nil, err
	}
	return raw, nil
}

// decodeSK decodes an inbound SK{} message (current-SA, with grace fallback).
func (s *Session) decodeSK(raw []byte) (*ikemsg.Message, ikemsg.Payloads, error) {
	m, inner, _, err := s.decodeIKE(raw)
	return m, inner, err
}

// decodeIKE decodes an inbound SK{} message under the current IKE SA, falling
// back to the superseded IKE SA during the rekey grace window. It also returns
// the IKE context that decoded the message so the caller can reply under the
// same SA and tell a current-SA DELETE (teardown) from an old-SA DELETE (rekey).
func (s *Session) decodeIKE(raw []byte) (*ikemsg.Message, ikemsg.Payloads, *ikeCtx, error) {
	cur := &ikeCtx{sa: s.ikeSA, spii: s.initiatorSPI, spir: s.responderSPI}
	m, inner, icvOK, err := decodeSKWith(cur.sa, raw)
	if err == nil {
		return m, inner, cur, nil
	}
	if !icvOK && s.oldIKE != nil && time.Now().Before(s.oldIKEUntil) {
		if m2, inner2, _, err2 := decodeSKWith(s.oldIKE.sa, raw); err2 == nil {
			return m2, inner2, s.oldIKE, nil
		}
	}
	return m, inner, cur, err
}

// decodeSKWith verifies+decrypts under one IKE SA. icvOK reports whether the
// integrity check passed (false → caller may retry under a different SA; a
// message with no SK payload also reports false, since retrying it under the
// old SA is harmless and yields the same error). ikemsg.Parse is fully
// bounds-checked, so a malformed or spoofed datagram returns an error here
// rather than panicking the process.
func decodeSKWith(ike *ikesa.IKESA, raw []byte) (*ikemsg.Message, ikemsg.Payloads, bool, error) {
	m, err := ikemsg.Parse(raw)
	if err != nil {
		return nil, nil, false, fmt.Errorf("session: decode SK message: %w", err)
	}
	var enc *ikemsg.EncryptedPayload
	for _, p := range m.Payloads {
		if e, ok := p.(*ikemsg.EncryptedPayload); ok {
			enc = e
			break
		}
	}
	if enc == nil {
		return m, nil, false, errors.New("session: message has no SK payload")
	}
	plaintext, icvOK, err := ike.OpenSK(raw, enc.Data)
	if err != nil {
		return m, nil, icvOK, err
	}
	inner, err := ikemsg.ParsePayloads(enc.InnerFirst, plaintext)
	if err != nil {
		return nil, nil, true, err
	}
	return m, inner, true, nil
}

// firstEAP returns the first EAP payload's parsed packet. The codec carries the
// raw EAP bytes (EAP method 26 / MSCHAPv2 included); internal/eap parses them here
// at the session boundary. found distinguishes an absent EAP payload (found=false)
// from one present but malformed (found=true, err set) so callers can report the
// precise parse failure rather than a generic "missing EAP".
func firstEAP(payloads ikemsg.Payloads) (pkt eap.Packet, found bool, err error) {
	for _, p := range payloads {
		e, ok := p.(*ikemsg.EAPPayload)
		if !ok {
			continue
		}
		pkt, err = eap.Parse(e.Data)
		if err != nil {
			return eap.Packet{}, true, fmt.Errorf("session: malformed EAP payload: %w", err)
		}
		return pkt, true, nil
	}
	return eap.Packet{}, false, nil
}
