package ipsec

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/n0madic/go-ipsec/internal/ikemsg"
)

// IDKind is an IKEv2 Identification payload type (RFC 7296 §3.5).
type IDKind uint8

const (
	IDKindNone  IDKind = 0
	IDKindIPv4  IDKind = IDKind(ikemsg.IDTypeIPv4)
	IDKindFQDN  IDKind = IDKind(ikemsg.IDTypeFQDN)
	IDKindEmail IDKind = IDKind(ikemsg.IDTypeRFC822)
	IDKindIPv6  IDKind = IDKind(ikemsg.IDTypeIPv6)
	IDKindKeyID IDKind = IDKind(ikemsg.IDTypeKeyID)

	// idKindInvalid marks an identity a constructor could not build (e.g.
	// IPv4() fed a v6 address). It is distinguishable from the unset zero
	// Identity so validate() rejects it instead of silently defaulting.
	// The value sits in the RFC 7296 private-use ID-type range and never
	// reaches the wire.
	idKindInvalid IDKind = 255
)

// Identity is an IKE identity (IDi or IDr). The zero value is "unset"; for IDr
// that means accept whatever the server presents (subject to certificate trust).
type Identity struct {
	Kind IDKind
	Data []byte
}

// FQDN builds an ID_FQDN identity.
func FQDN(name string) Identity { return Identity{Kind: IDKindFQDN, Data: []byte(name)} }

// Email builds an ID_RFC822_ADDR identity.
func Email(addr string) Identity { return Identity{Kind: IDKindEmail, Data: []byte(addr)} }

// KeyID builds an ID_KEY_ID identity from opaque bytes.
func KeyID(id []byte) Identity { return Identity{Kind: IDKindKeyID, Data: append([]byte(nil), id...)} }

// IPv4 builds an ID_IPV4_ADDR identity. A non-IPv4 (or zero) addr yields an
// invalid Identity rather than panicking; validate() then rejects it with a
// clear config-time error.
func IPv4(addr netip.Addr) Identity {
	addr = addr.Unmap()
	if !addr.Is4() {
		return Identity{Kind: idKindInvalid}
	}
	a4 := addr.As4()
	return Identity{Kind: IDKindIPv4, Data: a4[:]}
}

// IPv6 builds an ID_IPV6_ADDR identity. A non-IPv6 (zero, or 4-mapped) addr
// yields an invalid Identity rather than panicking; validate() then rejects it
// with a clear config-time error.
func IPv6(addr netip.Addr) Identity {
	if !addr.Is6() || addr.Is4In6() {
		return Identity{Kind: idKindInvalid}
	}
	a16 := addr.As16()
	return Identity{Kind: IDKindIPv6, Data: a16[:]}
}

// IsZero reports whether the identity is unset.
func (id Identity) IsZero() bool { return id.Kind == IDKindNone }

// check verifies a set identity is well-formed enough to marshal into an
// Identification payload. The zero (unset) identity passes; the caller decides
// whether unset is allowed in its context.
func (id Identity) check() error {
	switch id.Kind {
	case IDKindNone:
		return nil
	case IDKindIPv4:
		if len(id.Data) != 4 {
			return fmt.Errorf("ID_IPV4_ADDR needs 4 data bytes, got %d", len(id.Data))
		}
	case IDKindIPv6:
		if len(id.Data) != 16 {
			return fmt.Errorf("ID_IPV6_ADDR needs 16 data bytes, got %d", len(id.Data))
		}
	case IDKindFQDN, IDKindEmail, IDKindKeyID:
		if len(id.Data) == 0 {
			return errors.New("empty identity data")
		}
	default:
		return fmt.Errorf("invalid identity kind %d (bad constructor input?)", id.Kind)
	}
	return nil
}

// defaultEAPIdentity derives the wire IDi from the EAP username when LocalID is
// unset: usernames containing "@" become ID_RFC822_ADDR, anything else ID_FQDN
// (the convention strongSwan clients follow).
func defaultEAPIdentity(username string) Identity {
	if strings.Contains(username, "@") {
		return Email(username)
	}
	return FQDN(username)
}

// String renders the identity for logging.
func (id Identity) String() string {
	switch id.Kind {
	case IDKindNone:
		return "<unset>"
	case idKindInvalid:
		return "<invalid>"
	case IDKindIPv4, IDKindIPv6:
		if a, ok := netip.AddrFromSlice(id.Data); ok {
			return a.String()
		}
		return fmt.Sprintf("ip:%x", id.Data)
	case IDKindKeyID:
		return fmt.Sprintf("keyid:%x", id.Data)
	default:
		return string(id.Data)
	}
}

// idType / idData expose the wire fields for building Identification payloads.
func (id Identity) idType() uint8  { return uint8(id.Kind) }
func (id Identity) idData() []byte { return id.Data }

// identityFromWire reconstructs an Identity from a decoded Identification
// payload's type and data.
func identityFromWire(idType uint8, data []byte) Identity {
	return Identity{Kind: IDKind(idType), Data: append([]byte(nil), data...)}
}
