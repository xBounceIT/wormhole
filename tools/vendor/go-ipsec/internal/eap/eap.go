// Package eap implements the EAP-MSCHAPv2 inner exchange carried inside IKEv2
// SK{} payloads (RFC 7296 §3.16). This package owns the EAP packet framing; the
// ikemsg codec carries an EAP payload's raw bytes verbatim (EAP-MSCHAPv2, method
// 26, included), and the session layer parses them into a Packet at the SK boundary.
package eap

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// EAP codes (RFC 3748 §4).
const (
	CodeRequest  uint8 = 1
	CodeResponse uint8 = 2
	CodeSuccess  uint8 = 3
	CodeFailure  uint8 = 4
)

// EAP method types (RFC 3748 §5, IANA).
const (
	TypeIdentity     uint8 = 1
	TypeNotification uint8 = 2
	TypeNak          uint8 = 3
	TypeMSCHAPv2     uint8 = 26
)

// Packet is a parsed EAP packet — the full body of an IKE EAP payload:
//
//	Code(1) | Identifier(1) | Length(2) | [Type(1) | Type-Data...]
//
// Success/Failure packets carry no Type or data.
type Packet struct {
	Code       uint8
	Identifier uint8
	Type       uint8  // 0 for Success/Failure
	Data       []byte // type-data (after the Type octet)
}

// Parse decodes an EAP packet from the body of an IKE EAP payload.
func Parse(raw []byte) (Packet, error) {
	if len(raw) < 4 {
		return Packet{}, errors.New("eap: packet shorter than 4 bytes")
	}
	length := int(binary.BigEndian.Uint16(raw[2:4]))
	if length < 4 || length != len(raw) {
		return Packet{}, fmt.Errorf("eap: bad length field %d (have %d)", length, len(raw))
	}
	p := Packet{Code: raw[0], Identifier: raw[1]}
	if (p.Code == CodeSuccess || p.Code == CodeFailure) && length != 4 {
		return Packet{}, errors.New("eap: unsupported data in terminal packet")
	}
	if length == 4 {
		return p, nil // Success / Failure
	}
	p.Type = raw[4]
	p.Data = append([]byte(nil), raw[5:length]...)
	return p, nil
}

// Marshal encodes the EAP packet (with its length field) for embedding in an
// IKE EAP payload.
func (p Packet) Marshal() []byte {
	if p.Code == CodeSuccess || p.Code == CodeFailure {
		out := make([]byte, 4)
		out[0] = p.Code
		out[1] = p.Identifier
		binary.BigEndian.PutUint16(out[2:4], 4)
		return out
	}
	out := make([]byte, 5+len(p.Data))
	out[0] = p.Code
	out[1] = p.Identifier
	out[4] = p.Type
	copy(out[5:], p.Data)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	return out
}
