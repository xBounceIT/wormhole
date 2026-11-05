package ikemsg

import (
	"encoding/binary"
	"fmt"
)

// Payload is one IKE payload. The body methods are unexported: every concrete
// payload lives in this package, and callers construct them as struct literals and
// inspect them with a type switch rather than through an interface body. marshalBody
// and unmarshalBody handle only the payload body — the 4-byte generic header
// (RFC 7296 §3.2) is owned by the chain codec in Payloads.Marshal and parseChain.
type Payload interface {
	// PayloadType reports the IANA payload type, used to thread the Next Payload
	// chain.
	PayloadType() PayloadType
	// marshalBody encodes the payload body (everything after the generic header).
	marshalBody() ([]byte, error)
	// unmarshalBody decodes the payload body. It must be bounds-safe: callers may
	// hand it hostile input, so it validates every length before slicing.
	unmarshalBody([]byte) error
}

// Payloads is an ordered payload chain. The same type models the outer message's
// payloads and a decrypted SK{} plaintext's inner payloads.
type Payloads []Payload

// Marshal encodes the chain (RFC 7296 §3.2) and returns the type of the first
// payload — the value the enclosing header's (or SK payload's) Next Payload field
// must carry. Each generic header's Next Payload field names the following
// payload, except the last, which is PayloadNone — or, for a trailing SK payload,
// the type of its first inner payload. An empty chain returns (PayloadNone, nil,
// nil) without error: an SK{} may legally wrap zero inner payloads (a DPD probe or
// bare ack).
func (ps Payloads) Marshal() (first PayloadType, body []byte, err error) {
	if len(ps) == 0 {
		return PayloadNone, nil, nil
	}

	var buf []byte
	for i, p := range ps {
		payloadBody, err := p.marshalBody()
		if err != nil {
			return PayloadNone, nil, err
		}
		// The generic-header length is a 16-bit field; a bare uint16 cast
		// below would silently wrap on an oversized body and corrupt the
		// outgoing message. No legitimate payload approaches the limit (a
		// whole datagram is ≤65535 bytes), so fail loudly instead. This also
		// transitively bounds every nested length field (proposal, transform,
		// selector, config attribute): each spans a subset of this body.
		if len(payloadBody) > 0xFFFF-genericHeaderLen {
			return PayloadNone, nil, fmt.Errorf("ikemsg: payload type %d body of %d bytes exceeds the 16-bit length field", p.PayloadType(), len(payloadBody))
		}

		var nextType PayloadType
		switch {
		case i+1 < len(ps):
			nextType = ps[i+1].PayloadType()
		default:
			// Last payload: PayloadNone, unless it is an SK whose Next Payload field
			// announces the first inner (encrypted) payload type.
			if enc, ok := p.(*EncryptedPayload); ok {
				nextType = enc.InnerFirst
			} else {
				nextType = PayloadNone
			}
		}

		var hdr [genericHeaderLen]byte
		hdr[0] = byte(nextType)
		// hdr[1] (Critical + RESERVED) stays zero: we never originate critical payloads.
		binary.BigEndian.PutUint16(hdr[2:4], uint16(genericHeaderLen+len(payloadBody)))
		buf = append(buf, hdr[:]...)
		buf = append(buf, payloadBody...)
	}
	return ps[0].PayloadType(), buf, nil
}
