package ikemsg

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ConfigPayload is a Configuration payload (RFC 7296 §3.15): a configuration type
// and a list of attributes (e.g. a CFG_REQUEST for an internal address, or the
// CFG_REPLY carrying it).
type ConfigPayload struct {
	CfgType    ConfigType
	Attributes []ConfigAttr
}

// ConfigAttr is one configuration attribute (RFC 7296 §3.15.1). A CFG_REQUEST
// attribute carries an empty Value (length 0).
type ConfigAttr struct {
	Type  ConfigAttrType
	Value []byte
}

func (*ConfigPayload) PayloadType() PayloadType { return PayloadCP }

func (c *ConfigPayload) marshalBody() ([]byte, error) {
	// CFG Type(1) | RESERVED(3) | attributes
	out := make([]byte, 4)
	out[0] = byte(c.CfgType)
	for _, attr := range c.Attributes {
		// Reserved(1 bit) + Attribute Type(15 bits) | Length(2) | Value
		var hdr [4]byte
		binary.BigEndian.PutUint16(hdr[0:2], uint16(attr.Type)&0x7fff)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(attr.Value)))
		out = append(out, hdr[:]...)
		out = append(out, attr.Value...)
	}
	return out, nil
}

func (c *ConfigPayload) unmarshalBody(body []byte) error {
	if len(body) < 4 {
		return errors.New("configuration payload shorter than 4 bytes")
	}
	c.CfgType = ConfigType(body[0])

	rest := body[4:]
	for len(rest) > 0 {
		if len(rest) < 4 {
			return errors.New("configuration attribute header truncated")
		}
		attrType := binary.BigEndian.Uint16(rest[0:2]) & 0x7fff
		length := int(binary.BigEndian.Uint16(rest[2:4]))
		if 4+length > len(rest) {
			return fmt.Errorf("configuration attribute length %d overruns the %d remaining bytes", length, len(rest))
		}
		c.Attributes = append(c.Attributes, ConfigAttr{
			Type:  ConfigAttrType(attrType),
			Value: append([]byte(nil), rest[4:4+length]...),
		})
		rest = rest[4+length:]
	}
	return nil
}

// EncryptedPayload is an Encrypted and Authenticated (SK{}) payload (RFC 7296
// §3.14). InnerFirst is the type of the first inner payload (the SK header's Next
// Payload field). Data is the opaque IV | ciphertext | padding | ICV — this codec
// never touches the cryptography; encryption and the integrity checksum live in
// internal/ikesa.
type EncryptedPayload struct {
	InnerFirst PayloadType
	Data       []byte
}

func (*EncryptedPayload) PayloadType() PayloadType { return PayloadSK }

func (e *EncryptedPayload) marshalBody() ([]byte, error) {
	return append([]byte(nil), e.Data...), nil
}

func (e *EncryptedPayload) unmarshalBody(body []byte) error {
	e.Data = append([]byte(nil), body...)
	return nil
}

// EAPPayload is an EAP payload (RFC 7296 §3.16). Data is the raw EAP packet
// (Code | Identifier | Length | [Type | Type-Data]); the codec carries it verbatim,
// so EAP method 26 (MSCHAPv2) passes through untouched. internal/eap parses Data.
type EAPPayload struct {
	Data []byte
}

func (*EAPPayload) PayloadType() PayloadType { return PayloadEAP }

func (e *EAPPayload) marshalBody() ([]byte, error) {
	return append([]byte(nil), e.Data...), nil
}

func (e *EAPPayload) unmarshalBody(body []byte) error {
	e.Data = append([]byte(nil), body...)
	return nil
}
