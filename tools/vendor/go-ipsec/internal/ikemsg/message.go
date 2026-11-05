package ikemsg

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// headerLen is the fixed size of the IKE message header (RFC 7296 §3.1):
//
//	SPIi(8) | SPIr(8) | NextPayload(1) | Version(1) | Exchange(1) | Flags(1) |
//	MessageID(4) | Length(4)
const headerLen = 28

// version is the IKE major/minor version octet written into every outgoing
// message: major 2, minor 0 (RFC 7296 §3.1).
const version = 0x20

// genericHeaderLen is the size of the generic payload header that prefixes every
// payload body (RFC 7296 §3.2): NextPayload(1) | Critical+RESERVED(1) | Length(2).
const genericHeaderLen = 4

// criticalBit is the high bit of the second octet of a generic payload header
// (RFC 7296 §3.2). We never set it on output; on input it decides whether an
// unrecognized payload is skipped (clear) or fails the parse (set).
const criticalBit = 0x80

// Message is a decoded or to-be-encoded IKE message: the header fields plus its
// payload chain. The major/minor version octet is not modeled — Marshal always
// writes IKEv2 (0x20) and Parse ignores it.
type Message struct {
	InitiatorSPI uint64
	ResponderSPI uint64
	Exchange     ExchangeType
	Flags        Flags
	MessageID    uint32
	Payloads     Payloads
}

// Marshal encodes the message to wire bytes (RFC 7296 §3.1). The header's Next
// Payload field is taken from the first payload (or PayloadNone for an empty
// chain), the version octet is set to IKEv2, and the Length field is written last
// once the full size is known.
func (m *Message) Marshal() ([]byte, error) {
	first, body, err := m.Payloads.Marshal()
	if err != nil {
		return nil, err
	}

	out := make([]byte, headerLen, headerLen+len(body))
	binary.BigEndian.PutUint64(out[0:8], m.InitiatorSPI)
	binary.BigEndian.PutUint64(out[8:16], m.ResponderSPI)
	out[16] = byte(first)
	out[17] = version
	out[18] = byte(m.Exchange)
	out[19] = byte(m.Flags)
	binary.BigEndian.PutUint32(out[20:24], m.MessageID)
	out = append(out, body...)
	binary.BigEndian.PutUint32(out[24:28], uint32(len(out)))
	return out, nil
}

// Parse decodes an IKE message from a single datagram. It is fully bounds-checked
// — a malformed or hostile (pre-authentication) input returns an error and never
// panics, so callers need no recover() wrapper. The datagram length must equal the
// header's Length field exactly (RFC 7296 §3.1); UDP delivers whole messages, and
// recvMatching / the SA_INIT scanners rely on this exactness.
func Parse(raw []byte) (*Message, error) {
	if len(raw) < headerLen {
		return nil, errors.New("ikemsg: datagram shorter than 28-byte IKE header")
	}
	length := binary.BigEndian.Uint32(raw[24:28])
	if length < headerLen {
		return nil, fmt.Errorf("ikemsg: header length %d below the 28-byte minimum", length)
	}
	if len(raw) != int(length) {
		return nil, fmt.Errorf("ikemsg: datagram length %d does not match header length %d", len(raw), length)
	}

	m := &Message{
		InitiatorSPI: binary.BigEndian.Uint64(raw[0:8]),
		ResponderSPI: binary.BigEndian.Uint64(raw[8:16]),
		Exchange:     ExchangeType(raw[18]),
		Flags:        Flags(raw[19]),
		MessageID:    binary.BigEndian.Uint32(raw[20:24]),
	}
	payloads, err := parseChain(PayloadType(raw[16]), raw[headerLen:])
	if err != nil {
		return nil, err
	}
	m.Payloads = payloads
	return m, nil
}

// ParsePayloads decodes the inner payload chain recovered from a decrypted SK{}
// plaintext (RFC 7296 §3.14). first is the SK payload's Next Payload field (the
// type of the first inner payload); an empty body yields an empty chain with no
// error, which is legal for a DPD probe or a bare acknowledgement.
func ParsePayloads(first PayloadType, body []byte) (Payloads, error) {
	return parseChain(first, body)
}

// parseChain walks a generic-payload-header chain (RFC 7296 §3.2), shared by the
// outer message (seeded with the header's Next Payload) and the inner SK plaintext
// (seeded with the SK payload's Next Payload). It validates every length before
// slicing. An unrecognized payload is skipped when its Critical bit is clear and
// fails the parse when it is set (RFC 7296 §2.5).
func parseChain(first PayloadType, body []byte) (Payloads, error) {
	var out Payloads
	next := first
	for len(body) > 0 {
		if len(body) < genericHeaderLen {
			return nil, errors.New("ikemsg: truncated generic payload header")
		}
		following := PayloadType(body[0])
		critical := body[1]&criticalBit != 0
		plen := int(binary.BigEndian.Uint16(body[2:4]))
		if plen < genericHeaderLen {
			return nil, fmt.Errorf("ikemsg: payload length %d below the 4-byte minimum", plen)
		}
		if plen > len(body) {
			return nil, fmt.Errorf("ikemsg: payload length %d overruns the %d remaining bytes", plen, len(body))
		}

		p := newPayload(next)
		if p == nil {
			if critical {
				return nil, fmt.Errorf("ikemsg: unknown critical payload type %d", next)
			}
			next = following
			body = body[plen:]
			continue
		}
		// The SK payload's Next Payload field names the first inner payload type,
		// not a sibling; preserve it so re-encrypt and inner decode can recover it.
		if enc, ok := p.(*EncryptedPayload); ok {
			enc.InnerFirst = following
		}
		if err := p.unmarshalBody(body[genericHeaderLen:plen]); err != nil {
			return nil, fmt.Errorf("ikemsg: payload type %d: %w", next, err)
		}
		out = append(out, p)
		next = following
		body = body[plen:]
	}
	return out, nil
}

// newPayload returns a zero value of the concrete payload type for t, or nil for a
// type this codec does not model (the caller skips or rejects it per the Critical
// bit).
func newPayload(t PayloadType) Payload {
	switch t {
	case PayloadSA:
		return &SAPayload{}
	case PayloadKE:
		return &KEPayload{}
	case PayloadIDi:
		return &IDiPayload{}
	case PayloadIDr:
		return &IDrPayload{}
	case PayloadCert:
		return &CertPayload{}
	case PayloadCertReq:
		return &CertRequestPayload{}
	case PayloadAuth:
		return &AuthPayload{}
	case PayloadNonce:
		return &NoncePayload{}
	case PayloadNotify:
		return &NotifyPayload{}
	case PayloadDelete:
		return &DeletePayload{}
	case PayloadVendorID:
		return &VendorIDPayload{}
	case PayloadTSi:
		return &TSiPayload{}
	case PayloadTSr:
		return &TSrPayload{}
	case PayloadSK:
		return &EncryptedPayload{}
	case PayloadCP:
		return &ConfigPayload{}
	case PayloadEAP:
		return &EAPPayload{}
	default:
		return nil
	}
}
