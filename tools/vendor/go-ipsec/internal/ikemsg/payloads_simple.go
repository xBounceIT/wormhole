package ikemsg

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// minNonceLen / maxNonceLen are the bounds RFC 7296 §3.9 places on Nonce Data
// (16..256 octets). Both are enforced at the parse boundary so a peer cannot feed
// a low-entropy nonce into SKEYSEED / KEYMAT, nor an oversized one.
const (
	minNonceLen = 16
	maxNonceLen = 256
)

// KEPayload is a Key Exchange payload (RFC 7296 §3.4): the D-H group number
// followed by the public key exchange value.
type KEPayload struct {
	Group uint16
	Data  []byte
}

func (*KEPayload) PayloadType() PayloadType { return PayloadKE }

func (ke *KEPayload) marshalBody() ([]byte, error) {
	// Group(2) | RESERVED(2) | Key Exchange Data
	out := make([]byte, 4, 4+len(ke.Data))
	binary.BigEndian.PutUint16(out[0:2], ke.Group)
	return append(out, ke.Data...), nil
}

func (ke *KEPayload) unmarshalBody(body []byte) error {
	if len(body) < 4 {
		return errors.New("key exchange payload shorter than 4 bytes")
	}
	ke.Group = binary.BigEndian.Uint16(body[0:2])
	ke.Data = append([]byte(nil), body[4:]...)
	return nil
}

// NoncePayload is a Nonce payload (RFC 7296 §3.9): the body is the raw nonce.
type NoncePayload struct {
	Data []byte
}

func (*NoncePayload) PayloadType() PayloadType { return PayloadNonce }

func (n *NoncePayload) marshalBody() ([]byte, error) {
	return append([]byte(nil), n.Data...), nil
}

func (n *NoncePayload) unmarshalBody(body []byte) error {
	if len(body) < minNonceLen || len(body) > maxNonceLen {
		return fmt.Errorf("nonce payload %d bytes, outside the %d..%d-byte range", len(body), minNonceLen, maxNonceLen)
	}
	n.Data = append([]byte(nil), body...)
	return nil
}

// MarshalIDBody encodes an Identification payload body (RFC 7296 §3.5):
//
//	ID Type(1) | RESERVED(3) | Identification Data
//
// It is exported because the AUTH signed-octets computation (RFC 7296 §2.15) hashes
// this exact layout, so the session reuses it rather than re-deriving the bytes.
func MarshalIDBody(idType IDType, data []byte) []byte {
	out := make([]byte, 4, 4+len(data))
	out[0] = byte(idType)
	return append(out, data...)
}

// parseIDBody decodes the shared Identification body layout into its type and data.
func parseIDBody(body []byte) (IDType, []byte, error) {
	if len(body) < 4 {
		return 0, nil, errors.New("identification payload shorter than 4 bytes")
	}
	return IDType(body[0]), append([]byte(nil), body[4:]...), nil
}

// IDiPayload is the initiator's Identification payload (RFC 7296 §3.5). IDi and IDr
// share a wire layout but are distinct payload types, so they are modeled
// separately to keep the Next Payload chain unambiguous.
type IDiPayload struct {
	IDType IDType
	Data   []byte
}

func (*IDiPayload) PayloadType() PayloadType { return PayloadIDi }

func (id *IDiPayload) marshalBody() ([]byte, error) {
	return MarshalIDBody(id.IDType, id.Data), nil
}

func (id *IDiPayload) unmarshalBody(body []byte) error {
	t, data, err := parseIDBody(body)
	if err != nil {
		return err
	}
	id.IDType, id.Data = t, data
	return nil
}

// IDrPayload is the responder's Identification payload (RFC 7296 §3.5).
type IDrPayload struct {
	IDType IDType
	Data   []byte
}

func (*IDrPayload) PayloadType() PayloadType { return PayloadIDr }

func (id *IDrPayload) marshalBody() ([]byte, error) {
	return MarshalIDBody(id.IDType, id.Data), nil
}

func (id *IDrPayload) unmarshalBody(body []byte) error {
	t, data, err := parseIDBody(body)
	if err != nil {
		return err
	}
	id.IDType, id.Data = t, data
	return nil
}

// AuthPayload is an Authentication payload (RFC 7296 §3.8). Method is the IANA
// Auth Method byte; its values and verification live in internal/auth, so the
// codec carries the byte without interpreting it.
type AuthPayload struct {
	Method uint8
	Data   []byte
}

func (*AuthPayload) PayloadType() PayloadType { return PayloadAuth }

func (a *AuthPayload) marshalBody() ([]byte, error) {
	// Auth Method(1) | RESERVED(3) | Authentication Data
	out := make([]byte, 4, 4+len(a.Data))
	out[0] = a.Method
	return append(out, a.Data...), nil
}

func (a *AuthPayload) unmarshalBody(body []byte) error {
	if len(body) < 4 {
		return errors.New("authentication payload shorter than 4 bytes")
	}
	a.Method = body[0]
	a.Data = append([]byte(nil), body[4:]...)
	return nil
}

// CertPayload is a Certificate payload (RFC 7296 §3.6). Note the 1-byte header:
// the encoding octet is followed immediately by the certificate data, with no
// RESERVED padding.
type CertPayload struct {
	Encoding CertEncoding
	Data     []byte
}

func (*CertPayload) PayloadType() PayloadType { return PayloadCert }

func (c *CertPayload) marshalBody() ([]byte, error) {
	out := make([]byte, 1, 1+len(c.Data))
	out[0] = byte(c.Encoding)
	return append(out, c.Data...), nil
}

func (c *CertPayload) unmarshalBody(body []byte) error {
	if len(body) < 1 {
		return errors.New("certificate payload is empty")
	}
	c.Encoding = CertEncoding(body[0])
	c.Data = append([]byte(nil), body[1:]...)
	return nil
}

// CertRequestPayload is a Certificate Request payload (RFC 7296 §3.7). Like
// Certificate it has a 1-byte header: the encoding octet followed by the
// certification-authority data.
type CertRequestPayload struct {
	Encoding CertEncoding
	Data     []byte
}

func (*CertRequestPayload) PayloadType() PayloadType { return PayloadCertReq }

func (c *CertRequestPayload) marshalBody() ([]byte, error) {
	out := make([]byte, 1, 1+len(c.Data))
	out[0] = byte(c.Encoding)
	return append(out, c.Data...), nil
}

func (c *CertRequestPayload) unmarshalBody(body []byte) error {
	if len(body) < 1 {
		return errors.New("certificate request payload is empty")
	}
	c.Encoding = CertEncoding(body[0])
	c.Data = append([]byte(nil), body[1:]...)
	return nil
}

// VendorIDPayload is a Vendor ID payload (RFC 7296 §3.12): the body is the raw
// vendor identifier.
type VendorIDPayload struct {
	Data []byte
}

func (*VendorIDPayload) PayloadType() PayloadType { return PayloadVendorID }

func (v *VendorIDPayload) marshalBody() ([]byte, error) {
	return append([]byte(nil), v.Data...), nil
}

func (v *VendorIDPayload) unmarshalBody(body []byte) error {
	v.Data = append([]byte(nil), body...)
	return nil
}
