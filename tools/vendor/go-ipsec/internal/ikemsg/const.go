// Package ikemsg is a from-scratch IKEv2 message codec (RFC 7296 §3): it marshals
// and parses the on-the-wire framing of IKE messages and their payloads. It owns
// only the framing — never the cryptography. An SK{} payload's body is carried
// opaquely (IV | ciphertext | pad | ICV); encryption, decryption and the
// integrity checksum live in internal/ikesa.
//
// The wire format is dictated by the public standard (RFC 7296 §3), so the bytes
// are interoperable with any conformant peer (strongSwan, etc.). The Go API,
// however, is rethought for this client: typed constants with explicit IANA
// values, a flat per-proposal transform list, directional payload types, and a
// parser that is fully bounds-checked so untrusted (pre-authentication) input
// returns an error rather than panicking.
package ikemsg

// PayloadType identifies an IKE payload (RFC 7296 §3.2, IANA "IKEv2 Payload
// Types"). The "Next Payload" field of every generic payload header carries one
// of these.
type PayloadType uint8

const (
	PayloadNone     PayloadType = 0  // No Next Payload
	PayloadSA       PayloadType = 33 // Security Association
	PayloadKE       PayloadType = 34 // Key Exchange
	PayloadIDi      PayloadType = 35 // Identification - Initiator
	PayloadIDr      PayloadType = 36 // Identification - Responder
	PayloadCert     PayloadType = 37 // Certificate
	PayloadCertReq  PayloadType = 38 // Certificate Request
	PayloadAuth     PayloadType = 39 // Authentication
	PayloadNonce    PayloadType = 40 // Nonce
	PayloadNotify   PayloadType = 41 // Notify
	PayloadDelete   PayloadType = 42 // Delete
	PayloadVendorID PayloadType = 43 // Vendor ID
	PayloadTSi      PayloadType = 44 // Traffic Selector - Initiator
	PayloadTSr      PayloadType = 45 // Traffic Selector - Responder
	PayloadSK       PayloadType = 46 // Encrypted and Authenticated
	PayloadCP       PayloadType = 47 // Configuration
	PayloadEAP      PayloadType = 48 // Extensible Authentication
)

// ExchangeType identifies the IKE exchange (RFC 7296 §3.1, IANA "IKEv2 Exchange
// Types").
type ExchangeType uint8

const (
	ExchangeIKESAInit     ExchangeType = 34 // IKE_SA_INIT
	ExchangeIKEAuth       ExchangeType = 35 // IKE_AUTH
	ExchangeCreateChildSA ExchangeType = 36 // CREATE_CHILD_SA
	ExchangeInformational ExchangeType = 37 // INFORMATIONAL
)

// ProtocolID identifies the security protocol a Proposal, Notify or Delete
// refers to (RFC 7296 §3.3.1).
type ProtocolID uint8

const (
	ProtocolNone ProtocolID = 0 // unspecified (most notifies, IKE delete)
	ProtocolIKE  ProtocolID = 1 // IKE SA
	ProtocolAH   ProtocolID = 2 // Authentication Header
	ProtocolESP  ProtocolID = 3 // Encapsulating Security Payload
)

// TransformType identifies the kind of cryptographic transform within a Proposal
// (RFC 7296 §3.3.2).
type TransformType uint8

const (
	TransformEncr  TransformType = 1 // Encryption Algorithm (ENCR)
	TransformPRF   TransformType = 2 // Pseudorandom Function (PRF)
	TransformInteg TransformType = 3 // Integrity Algorithm (INTEG)
	TransformDH    TransformType = 4 // Diffie-Hellman Group (D-H)
	TransformESN   TransformType = 5 // Extended Sequence Numbers (ESN)
)

// Transform IDs for the algorithm suites this client implements, taken directly
// from the IANA "IKEv2 Transform Type Values" registries (RFC 7296 §3.3.2,
// RFC 8247). Each is scoped to its TransformType, so the numeric spaces overlap
// (ENCR_AES_CBC and AUTH_HMAC_SHA2_256_128 are both 12 under different types).
// internal/ikesa (IKE) and internal/esp (ESP) implement exactly these.
const (
	ENCR_AES_CBC           uint16 = 12 // ENCR, with a Key Length attribute
	ENCR_AES_GCM_16        uint16 = 20 // ENCR, AEAD with a 16-octet ICV (RFC 4106)
	ENCR_CHACHA20_POLY1305 uint16 = 28 // ENCR, AEAD, no Key Length attribute (RFC 7634)
	PRF_HMAC_SHA2_256      uint16 = 5  // PRF
	AUTH_NONE              uint16 = 0  // INTEG: no integrity (AEAD proposals)
	AUTH_HMAC_SHA2_256_128 uint16 = 12 // INTEG (RFC 4868)
	DH_MODP2048            uint16 = 14 // D-H group 14, 2048-bit MODP
	DH_X25519              uint16 = 31 // D-H group 31, Curve25519 (RFC 8031)
	ESN_NONE               uint16 = 0  // ESN: no extended sequence numbers
)

// AttrKeyLength is the IANA "Transform Attribute Type" for Key Length, encoded in
// the TV (Type/Value) format (RFC 7296 §3.3.5). It is the only transform
// attribute this client emits, carrying the AES key size in bits.
const AttrKeyLength uint16 = 14

// NotifyType is an IKE Notify Message Type (RFC 7296 §3.10.1, IANA registry).
// Types below NotifyError are error classes; types at or above NotifyStatus are
// status classes.
type NotifyType uint16

// NotifyStatus is the boundary between error and status notify types: a value in
// [1, NotifyStatus) (and non-zero) is an error notify (RFC 7296 §3.10.1).
const NotifyStatus uint16 = 16384

const (
	NotifyInvalidSyntax             NotifyType = 7     // error
	NotifyNoProposalChosen          NotifyType = 14    // error
	NotifyInvalidKEPayload          NotifyType = 17    // error, data = wanted D-H group
	NotifyAuthenticationFailed      NotifyType = 24    // error
	NotifyTemporaryFailure          NotifyType = 43    // error
	NotifyChildSANotFound           NotifyType = 44    // error
	NotifyInitialContact            NotifyType = 16384 // status
	NotifyNATDetectionSourceIP      NotifyType = 16388 // status
	NotifyNATDetectionDestinationIP NotifyType = 16389 // status
	NotifyCookie                    NotifyType = 16390 // status
	NotifyRekeySA                   NotifyType = 16393 // status, REKEY_SA
)

// IsError reports whether a notify type belongs to the error class (RFC 7296
// §3.10.1: types in 1..16383).
func (t NotifyType) IsError() bool { return t != 0 && uint16(t) < NotifyStatus }

// IDType is an Identification payload type (RFC 7296 §3.5, IANA "IKEv2
// Identification Payload ID Types").
type IDType uint8

const (
	IDTypeIPv4      IDType = 1  // ID_IPV4_ADDR
	IDTypeFQDN      IDType = 2  // ID_FQDN
	IDTypeRFC822    IDType = 3  // ID_RFC822_ADDR (email)
	IDTypeIPv6      IDType = 5  // ID_IPV6_ADDR
	IDTypeDERASN1DN IDType = 9  // ID_DER_ASN1_DN
	IDTypeKeyID     IDType = 11 // ID_KEY_ID
)

// ConfigType is a Configuration payload type (RFC 7296 §3.15, CFG_*).
type ConfigType uint8

const (
	ConfigRequest ConfigType = 1 // CFG_REQUEST
	ConfigReply   ConfigType = 2 // CFG_REPLY
	ConfigSet     ConfigType = 3 // CFG_SET
	ConfigAck     ConfigType = 4 // CFG_ACK
)

// ConfigAttrType is a Configuration Attribute type (RFC 7296 §3.15.1).
type ConfigAttrType uint16

const (
	ConfigAttrInternalIP4Address ConfigAttrType = 1  // INTERNAL_IP4_ADDRESS
	ConfigAttrInternalIP4Netmask ConfigAttrType = 2  // INTERNAL_IP4_NETMASK
	ConfigAttrInternalIP4DNS     ConfigAttrType = 3  // INTERNAL_IP4_DNS
	ConfigAttrInternalIP6Address ConfigAttrType = 8  // INTERNAL_IP6_ADDRESS (16-byte addr + 1-byte prefixlen)
	ConfigAttrInternalIP6DNS     ConfigAttrType = 10 // INTERNAL_IP6_DNS (16-byte addr)
)

// TSType is a Traffic Selector type (RFC 7296 §3.13.1).
type TSType uint8

const (
	TSIPv4AddrRange TSType = 7 // TS_IPV4_ADDR_RANGE
	TSIPv6AddrRange TSType = 8 // TS_IPV6_ADDR_RANGE
)

// CertEncoding is a Certificate / Certificate Request encoding (RFC 7296 §3.6).
type CertEncoding uint8

const (
	CertX509Signature CertEncoding = 4 // X.509 Certificate - Signature
)

// Flags is the IKE header flags octet (RFC 7296 §3.1). The Version flag (bit 4)
// signals support for a higher major version and is independent of the message's
// own major/minor version field, which Marshal always writes as 0x20 (IKEv2).
type Flags uint8

const (
	FlagInitiator Flags = 0x08 // 'I': message originated by the SA's original initiator
	FlagVersion   Flags = 0x10 // 'V': sender can speak a higher major version
	FlagResponse  Flags = 0x20 // 'R': message is a response to an earlier request
)

// IsInitiator reports whether the Initiator ('I') flag is set.
func (f Flags) IsInitiator() bool { return f&FlagInitiator != 0 }

// IsResponse reports whether the Response ('R') flag is set.
func (f Flags) IsResponse() bool { return f&FlagResponse != 0 }
