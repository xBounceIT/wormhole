package ikemsg

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// SAPayload is a Security Association payload: an ordered list of proposals
// (RFC 7296 §3.3). On the wire its body is the bare concatenation of the proposal
// substructures, with no extra header.
type SAPayload struct {
	Proposals []Proposal
}

// Proposal is one SA proposal (RFC 7296 §3.3.1). Transforms is a single flat list
// rather than five per-type slices; byType filters it, and the suite builders are
// responsible for appending in the canonical emission order (Encr, PRF, Integ, DH,
// ESN) so the encoding is deterministic and interoperable.
type Proposal struct {
	Number     uint8
	Protocol   ProtocolID
	SPI        []byte
	Transforms []Transform
}

// Transform is one transform within a proposal (RFC 7296 §3.3.2). KeyLength carries
// the Key Length attribute (RFC 7296 §3.3.5) in bits when HasKeyLength is true.
// It is the only transform attribute this client models.
type Transform struct {
	Type         TransformType
	ID           uint16
	KeyLength    uint16
	HasKeyLength bool
}

// ByType returns the transforms of the given type, in order. Suite matching reads
// one type at a time (e.g. all offered D-H groups) from the flat list.
func (p Proposal) ByType(t TransformType) []Transform {
	var out []Transform
	for _, tr := range p.Transforms {
		if tr.Type == t {
			out = append(out, tr)
		}
	}
	return out
}

func (*SAPayload) PayloadType() PayloadType { return PayloadSA }

func (sa *SAPayload) marshalBody() ([]byte, error) {
	var out []byte
	for i := range sa.Proposals {
		pd, err := marshalProposal(&sa.Proposals[i], i+1 < len(sa.Proposals))
		if err != nil {
			return nil, err
		}
		out = append(out, pd...)
	}
	return out, nil
}

// marshalProposal encodes one proposal substructure (RFC 7296 §3.3.1). more is the
// first octet: 2 ("more proposals follow") for any but the last, 0 for the last.
func marshalProposal(p *Proposal, more bool) ([]byte, error) {
	// SPI Size and Num Transforms are single octets; reject anything that would
	// silently truncate into them rather than emitting a proposal a peer cannot
	// reconstruct. Unreachable with the current single-suite builders, but a guard
	// against a future suite addition.
	if len(p.SPI) > 255 {
		return nil, fmt.Errorf("proposal SPI is %d bytes, exceeds the 1-octet SPI Size field", len(p.SPI))
	}
	if len(p.Transforms) > 255 {
		return nil, fmt.Errorf("proposal has %d transforms, exceeds the 1-octet count field", len(p.Transforms))
	}

	// Header: more(1) | RESERVED(1) | Length(2) | Number(1) | Protocol(1) |
	// SPISize(1) | NumTransforms(1)
	out := make([]byte, 8)
	if more {
		out[0] = 2
	}
	out[4] = p.Number
	out[5] = byte(p.Protocol)
	out[6] = uint8(len(p.SPI))
	out[7] = uint8(len(p.Transforms))
	out = append(out, p.SPI...)

	for i := range p.Transforms {
		td, err := marshalTransform(p.Transforms[i], i+1 < len(p.Transforms))
		if err != nil {
			return nil, err
		}
		out = append(out, td...)
	}
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	return out, nil
}

// marshalTransform encodes one transform substructure (RFC 7296 §3.3.2). more is
// the first octet: 3 ("more transforms follow") for any but the last, 0 for the
// last. A present KeyLength attribute is appended as a 4-byte TV attribute
// (RFC 7296 §3.3.5). A non-zero KeyLength without HasKeyLength is rejected: it
// is an inconsistent struct (most likely a literal that forgot HasKeyLength) and
// emitting it would silently drop the key length from the wire.
func marshalTransform(t Transform, more bool) ([]byte, error) {
	if t.KeyLength != 0 && !t.HasKeyLength {
		return nil, fmt.Errorf("transform type %d id %d: KeyLength %d set without HasKeyLength", t.Type, t.ID, t.KeyLength)
	}
	// Header: more(1) | RESERVED(1) | Length(2) | Type(1) | RESERVED(1) | ID(2)
	out := make([]byte, 8)
	if more {
		out[0] = 3
	}
	out[4] = byte(t.Type)
	binary.BigEndian.PutUint16(out[6:8], t.ID)

	if t.HasKeyLength {
		// TV attribute: the high bit (0x8000) flags the TV format, OR'd with the
		// attribute type; the value is the 2-byte key length in bits. HasKeyLength
		// decides presence: a transform that must NOT carry the attribute
		// (ChaCha20-Poly1305, RFC 7634) leaves it false (and KeyLength zero), and
		// an explicit KEY_LENGTH=0 is still emitted when it is true.
		var attr [4]byte
		binary.BigEndian.PutUint16(attr[0:2], 0x8000|AttrKeyLength)
		binary.BigEndian.PutUint16(attr[2:4], t.KeyLength)
		out = append(out, attr[:]...)
	}
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	return out, nil
}

func (sa *SAPayload) unmarshalBody(body []byte) error {
	for len(body) > 0 {
		if len(body) < 8 {
			return errors.New("proposal header truncated")
		}
		plen := int(binary.BigEndian.Uint16(body[2:4]))
		if plen < 8 {
			return fmt.Errorf("proposal length %d below the 8-byte minimum", plen)
		}
		if plen > len(body) {
			return fmt.Errorf("proposal length %d overruns the %d remaining bytes", plen, len(body))
		}

		spiSize := int(body[6])
		if 8+spiSize > plen {
			return fmt.Errorf("proposal SPI size %d overruns proposal length %d", spiSize, plen)
		}
		prop := Proposal{
			Number:   body[4],
			Protocol: ProtocolID(body[5]),
		}
		if spiSize > 0 {
			prop.SPI = append([]byte(nil), body[8:8+spiSize]...)
		}
		transforms, err := parseTransforms(body[8+spiSize : plen])
		if err != nil {
			return err
		}
		prop.Transforms = transforms
		sa.Proposals = append(sa.Proposals, prop)
		body = body[plen:]
	}
	return nil
}

// parseTransforms decodes the transform substructures filling a proposal. Unknown
// transform types are kept in the flat list (suite matching filters by type), and
// a TLV attribute is tolerated but ignored — only the TV Key Length attribute is
// surfaced (RFC 7296 §3.3.5).
func parseTransforms(body []byte) ([]Transform, error) {
	var out []Transform
	for len(body) > 0 {
		if len(body) < 8 {
			return nil, errors.New("transform header truncated")
		}
		tlen := int(binary.BigEndian.Uint16(body[2:4]))
		if tlen < 8 {
			return nil, fmt.Errorf("transform length %d below the 8-byte minimum", tlen)
		}
		if tlen > len(body) {
			return nil, fmt.Errorf("transform length %d overruns the %d remaining bytes", tlen, len(body))
		}

		t := Transform{
			Type: TransformType(body[4]),
			ID:   binary.BigEndian.Uint16(body[6:8]),
		}
		// Walk ALL transform attributes (RFC 7296 §3.3.5 permits several, in any
		// order), surfacing the TV-form Key Length attribute wherever it appears. A
		// peer may legitimately place a different attribute before KEY_LENGTH, so
		// reading only the first attribute would miss it and fail suite matching.
		for attrs := body[8:tlen]; len(attrs) > 0; {
			if len(attrs) < 4 {
				return nil, fmt.Errorf("transform attribute truncated in transform length %d", tlen)
			}
			af := binary.BigEndian.Uint16(attrs[0:2])
			if af&0x8000 != 0 {
				// TV form: 2-byte type (high bit set) | 2-byte value.
				if af&0x7fff == AttrKeyLength {
					t.KeyLength = binary.BigEndian.Uint16(attrs[2:4])
					t.HasKeyLength = true
				}
				attrs = attrs[4:]
				continue
			}
			// TLV form: 2-byte type | 2-byte length | value. Not emitted by this
			// client; tolerate and skip it after bounds-checking its length.
			alen := int(binary.BigEndian.Uint16(attrs[2:4]))
			if 4+alen > len(attrs) {
				return nil, fmt.Errorf("transform TLV attribute length %d overruns the transform", alen)
			}
			attrs = attrs[4+alen:]
		}
		out = append(out, t)
		body = body[tlen:]
	}
	return out, nil
}
