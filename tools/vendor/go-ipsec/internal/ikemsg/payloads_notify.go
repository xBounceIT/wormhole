package ikemsg

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// NotifyPayload is a Notify payload (RFC 7296 §3.10). REKEY_SA carries the SPI of
// the SA being rekeyed in Data with SPISize 0 in some peers' encodings, so callers
// read both SPI and Data.
type NotifyPayload struct {
	Protocol ProtocolID
	Type     NotifyType
	SPI      []byte
	Data     []byte
}

func (*NotifyPayload) PayloadType() PayloadType { return PayloadNotify }

func (n *NotifyPayload) marshalBody() ([]byte, error) {
	// Protocol ID(1) | SPI Size(1) | Notify Message Type(2) | SPI | Notification Data
	out := make([]byte, 4, 4+len(n.SPI)+len(n.Data))
	out[0] = byte(n.Protocol)
	out[1] = uint8(len(n.SPI))
	binary.BigEndian.PutUint16(out[2:4], uint16(n.Type))
	out = append(out, n.SPI...)
	out = append(out, n.Data...)
	return out, nil
}

func (n *NotifyPayload) unmarshalBody(body []byte) error {
	if len(body) < 4 {
		return errors.New("notify payload shorter than 4 bytes")
	}
	spiSize := int(body[1])
	if 4+spiSize > len(body) {
		return fmt.Errorf("notify SPI size %d overruns the %d-byte body", spiSize, len(body))
	}
	n.Protocol = ProtocolID(body[0])
	n.Type = NotifyType(binary.BigEndian.Uint16(body[2:4]))
	n.SPI = append([]byte(nil), body[4:4+spiSize]...)
	n.Data = append([]byte(nil), body[4+spiSize:]...)
	return nil
}

// DeletePayload is a Delete payload (RFC 7296 §3.11). SPIs is a list of equal-width
// SPIs: empty for an IKE-SA delete (Protocol IKE, SPI Size 0, count 0 — a legal
// 4-byte body), or four-byte ESP SPIs for a Child-SA delete.
type DeletePayload struct {
	Protocol ProtocolID
	SPIs     [][]byte
}

func (*DeletePayload) PayloadType() PayloadType { return PayloadDelete }

// SPISize reports the common SPI width: 0 when there are no SPIs (an IKE-SA
// delete), otherwise the length of the first SPI.
func (d *DeletePayload) SPISize() uint8 {
	if len(d.SPIs) == 0 {
		return 0
	}
	return uint8(len(d.SPIs[0]))
}

func (d *DeletePayload) marshalBody() ([]byte, error) {
	size := d.SPISize()
	for _, spi := range d.SPIs {
		if uint8(len(spi)) != size {
			return nil, errors.New("delete payload SPIs are not all the same width")
		}
	}

	// Protocol ID(1) | SPI Size(1) | Num of SPIs(2) | SPIs
	out := make([]byte, 4)
	out[0] = byte(d.Protocol)
	out[1] = size
	binary.BigEndian.PutUint16(out[2:4], uint16(len(d.SPIs)))
	for _, spi := range d.SPIs {
		out = append(out, spi...)
	}
	return out, nil
}

func (d *DeletePayload) unmarshalBody(body []byte) error {
	if len(body) < 4 {
		return errors.New("delete payload shorter than 4 bytes")
	}
	d.Protocol = ProtocolID(body[0])
	size := int(body[1])
	count := int(binary.BigEndian.Uint16(body[2:4]))
	// A zero SPI width with a non-zero count is malformed (RFC 7296 §3.11): the
	// count is unbounded by the body length, so honoring it would allocate one
	// empty SPI per declared count — a memory-amplification vector on a crafted
	// 4-byte body. An IKE-SA delete is the only legal zero-width form, and it
	// carries count 0.
	if size == 0 && count > 0 {
		return fmt.Errorf("delete payload declares %d SPIs of zero width", count)
	}
	if 4+size*count > len(body) {
		return fmt.Errorf("delete SPIs (%d × %d) overrun the %d-byte body", size, count, len(body))
	}
	d.SPIs = nil
	off := 4
	for range count {
		d.SPIs = append(d.SPIs, append([]byte(nil), body[off:off+size]...))
		off += size
	}
	return nil
}
