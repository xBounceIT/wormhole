package ikemsg

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// TrafficSelector is one traffic selector (RFC 7296 §3.13.1): a protocol and port
// range over a start/end address range. The address width follows TSType — 4 bytes
// for an IPv4 range, 16 for IPv6.
type TrafficSelector struct {
	TSType    TSType
	Protocol  uint8
	StartPort uint16
	EndPort   uint16
	StartAddr []byte
	EndAddr   []byte
}

// addrLen returns the per-address byte width required for the selector's type, or
// 0 for an unsupported type.
func (ts TrafficSelector) addrLen() int {
	switch ts.TSType {
	case TSIPv4AddrRange:
		return 4
	case TSIPv6AddrRange:
		return 16
	default:
		return 0
	}
}

// marshalTSBody encodes a Traffic Selector payload body (RFC 7296 §3.13): a count
// of selectors followed by the selector substructures. Shared by TSi and TSr.
func marshalTSBody(selectors []TrafficSelector) ([]byte, error) {
	if len(selectors) == 0 {
		return nil, errors.New("traffic selector payload has no selectors")
	}
	// Number of TSs(1) | RESERVED(3) | selectors
	out := make([]byte, 4)
	out[0] = uint8(len(selectors))

	for _, ts := range selectors {
		alen := ts.addrLen()
		if alen == 0 {
			return nil, fmt.Errorf("unsupported traffic selector type %d", ts.TSType)
		}
		if len(ts.StartAddr) != alen || len(ts.EndAddr) != alen {
			return nil, fmt.Errorf("traffic selector type %d needs %d-byte addresses", ts.TSType, alen)
		}
		// TS Type(1) | IP Protocol(1) | Selector Length(2) | Start Port(2) |
		// End Port(2) | Start Address | End Address
		sel := make([]byte, 8, 8+2*alen)
		sel[0] = byte(ts.TSType)
		sel[1] = ts.Protocol
		binary.BigEndian.PutUint16(sel[4:6], ts.StartPort)
		binary.BigEndian.PutUint16(sel[6:8], ts.EndPort)
		sel = append(sel, ts.StartAddr...)
		sel = append(sel, ts.EndAddr...)
		binary.BigEndian.PutUint16(sel[2:4], uint16(len(sel)))
		out = append(out, sel...)
	}
	return out, nil
}

// parseTSBody decodes a Traffic Selector payload body. It honors the selector count
// in the header and validates each selector's length against its type.
func parseTSBody(body []byte) ([]TrafficSelector, error) {
	if len(body) < 4 {
		return nil, errors.New("traffic selector payload shorter than 4 bytes")
	}
	count := int(body[0])
	if count == 0 {
		return nil, errors.New("traffic selector payload declares zero selectors")
	}
	rest := body[4:]

	out := make([]TrafficSelector, 0, count)
	for range count {
		if len(rest) < 8 {
			return nil, errors.New("traffic selector header truncated")
		}
		ts := TrafficSelector{TSType: TSType(rest[0])}
		alen := ts.addrLen()
		if alen == 0 {
			return nil, fmt.Errorf("unsupported traffic selector type %d", ts.TSType)
		}
		selLen := int(binary.BigEndian.Uint16(rest[2:4]))
		if selLen != 8+2*alen {
			return nil, fmt.Errorf("traffic selector type %d has length %d, want %d", ts.TSType, selLen, 8+2*alen)
		}
		if selLen > len(rest) {
			return nil, fmt.Errorf("traffic selector length %d overruns the %d remaining bytes", selLen, len(rest))
		}
		ts.Protocol = rest[1]
		ts.StartPort = binary.BigEndian.Uint16(rest[4:6])
		ts.EndPort = binary.BigEndian.Uint16(rest[6:8])
		ts.StartAddr = append([]byte(nil), rest[8:8+alen]...)
		ts.EndAddr = append([]byte(nil), rest[8+alen:8+2*alen]...)
		out = append(out, ts)
		rest = rest[selLen:]
	}
	// The declared count must consume the whole body; trailing bytes mean a
	// malformed payload (or a count that disagrees with the substructures).
	if len(rest) != 0 {
		return nil, fmt.Errorf("traffic selector payload has %d trailing bytes after %d selectors", len(rest), count)
	}
	return out, nil
}

// TSiPayload is the initiator's Traffic Selector payload (RFC 7296 §3.13). TSi and
// TSr share a layout but are distinct payload types, modeled separately to keep the
// Next Payload chain unambiguous.
type TSiPayload struct {
	Selectors []TrafficSelector
}

func (*TSiPayload) PayloadType() PayloadType { return PayloadTSi }

func (ts *TSiPayload) marshalBody() ([]byte, error) { return marshalTSBody(ts.Selectors) }

func (ts *TSiPayload) unmarshalBody(body []byte) error {
	sel, err := parseTSBody(body)
	if err != nil {
		return err
	}
	ts.Selectors = sel
	return nil
}

// TSrPayload is the responder's Traffic Selector payload (RFC 7296 §3.13).
type TSrPayload struct {
	Selectors []TrafficSelector
}

func (*TSrPayload) PayloadType() PayloadType { return PayloadTSr }

func (ts *TSrPayload) marshalBody() ([]byte, error) { return marshalTSBody(ts.Selectors) }

func (ts *TSrPayload) unmarshalBody(body []byte) error {
	sel, err := parseTSBody(body)
	if err != nil {
		return err
	}
	ts.Selectors = sel
	return nil
}
