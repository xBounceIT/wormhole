package eap

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"layeh.com/radius/rfc2759"

	"github.com/n0madic/go-ipsec/internal/secretmem"
)

// MSCHAPv2 opcodes (draft-kamath-pppext-eap-mschapv2 §2).
const (
	opChallenge uint8 = 1
	opResponse  uint8 = 2
	opSuccess   uint8 = 3
	opFailure   uint8 = 4
)

const (
	authChallengeLen = 16
	peerChallengeLen = 16
	// responseValueLen = PeerChallenge(16) | Reserved(8) | NT-Response(24) | Flags(1).
	responseValueLen = 49
)

// MSCHAPv2 carries the state of one EAP-MSCHAPv2 conversation from the peer
// (initiator) side and the material the MSK derivation later needs.
//
// Password is bytes, not a string: a string is unwipeable and would pin the
// secret for the process lifetime, while a byte copy can be zeroed by Wipe
// once the conversation is done.
type MSCHAPv2 struct {
	Username string
	Password []byte

	peerChallenge    []byte
	ntResponse       []byte
	authChallenge    []byte
	passwordHashHash []byte
	authResponse     []byte // expected "S=..." from the server (password-derived)
	authChecked      bool   // set once the server's AuthenticatorResponse verified
}

// NewMSCHAPv2 builds the conversation state with its own copy of the password,
// allocated inside secretmem.Do so it is runtime-tracked, and safe for Wipe to
// zero without touching a buffer the caller still owns.
func NewMSCHAPv2(username string, password []byte) *MSCHAPv2 {
	m := &MSCHAPv2{Username: username}
	secretmem.Do(func() { m.Password = append([]byte(nil), password...) })
	return m
}

// Wipe zeroes the password copy and every password-derived buffer. The
// conversation state is unusable afterwards; call it once the MSK has been
// derived (or the handshake failed).
func (m *MSCHAPv2) Wipe() {
	for _, b := range [][]byte{m.Password, m.peerChallenge, m.ntResponse, m.authChallenge, m.passwordHashHash, m.authResponse} {
		secretmem.Wipe(b)
	}
	m.Password, m.peerChallenge, m.ntResponse = nil, nil, nil
	m.authChallenge, m.passwordHashHash, m.authResponse = nil, nil, nil
}

// HandleChallenge consumes a Request/MSCHAPv2-Challenge and produces the
// Response/MSCHAPv2-Response packet to send. It records the NT-Response and the
// password-hash-hash for the MSK derivation.
func (m *MSCHAPv2) HandleChallenge(req Packet) (Packet, error) {
	if req.Type != TypeMSCHAPv2 {
		return Packet{}, fmt.Errorf("eap: expected MSCHAPv2 type, got %d", req.Type)
	}
	d := req.Data
	if len(d) < 5 || d[0] != opChallenge {
		return Packet{}, errors.New("eap: malformed MSCHAPv2 Challenge")
	}
	msChapID := d[1]
	valueSize := int(d[4])
	if valueSize != authChallengeLen || len(d) < 5+authChallengeLen {
		return Packet{}, fmt.Errorf("eap: bad Challenge value size %d", valueSize)
	}
	// A proof authenticates one challenge, not all later exchanges on this object.
	m.authChecked = false
	m.authChallenge = append([]byte(nil), d[5:5+authChallengeLen]...)

	peerChal := make([]byte, peerChallengeLen)
	if _, err := rand.Read(peerChal); err != nil {
		return Packet{}, err
	}
	m.peerChallenge = peerChal

	// Compute the password-derived material inside secretmem.Do: the stored
	// NT-Response / password-hash-hash / expected AuthenticatorResponse (and
	// the DES/MD4 intermediates rfc2759 allocates) are then runtime-tracked
	// and erased once the EAP state is dropped after the handshake.
	var cerr error
	secretmem.Do(func() {
		username := []byte(m.Username)
		ntResp, err := rfc2759.GenerateNTResponse(m.authChallenge, peerChal, username, m.Password)
		if err != nil {
			cerr = fmt.Errorf("eap: NT-Response: %w", err)
			return
		}
		m.ntResponse = ntResp

		// password-hash-hash = NtPasswordHash(NtPasswordHash(unicode(password))).
		ucs2, err := rfc2759.ToUTF16(m.Password)
		if err != nil {
			cerr = err
			return
		}
		m.passwordHashHash = rfc2759.NTPasswordHash(rfc2759.NTPasswordHash(ucs2))

		// Pre-compute the AuthenticatorResponse we expect the server to send back.
		authResp, err := rfc2759.GenerateAuthenticatorResponse(m.authChallenge, peerChal, ntResp, username, m.Password)
		if err != nil {
			cerr = fmt.Errorf("eap: AuthenticatorResponse: %w", err)
			return
		}
		m.authResponse = []byte(authResp)
	})
	if cerr != nil {
		return Packet{}, cerr
	}

	// Response value: PeerChallenge(16) | Reserved(8 zero) | NT-Response(24) | Flags(1).
	// The NT-Response is wire data (it is sent to the server), so building the
	// packet outside the secretmem.Do block above is fine.
	value := make([]byte, responseValueLen)
	copy(value[0:16], peerChal)
	copy(value[24:48], m.ntResponse)
	// value[48] (Flags) stays 0.

	// MSCHAPv2 Response type-data: OpCode | ID | MS-Length(2) | Value-Size | Value | Name.
	name := []byte(m.Username)
	data := make([]byte, 0, 5+responseValueLen+len(name))
	data = append(data, opResponse, msChapID, 0, 0, byte(responseValueLen))
	data = append(data, value...)
	data = append(data, name...)
	// MS-Length spans the whole MSCHAPv2 content (OpCode..Name).
	putUint16(data[2:4], uint16(len(data)))

	return Packet{
		Code:       CodeResponse,
		Identifier: req.Identifier,
		Type:       TypeMSCHAPv2,
		Data:       data,
	}, nil
}

// HandleSuccess consumes a Request/MSCHAPv2-Success, verifies the server's
// AuthenticatorResponse, and produces the Success Response packet.
func (m *MSCHAPv2) HandleSuccess(req Packet) (Packet, error) {
	if req.Type != TypeMSCHAPv2 {
		return Packet{}, fmt.Errorf("eap: expected MSCHAPv2 type, got %d", req.Type)
	}
	d := req.Data
	if len(d) < 1 {
		return Packet{}, errors.New("eap: empty MSCHAPv2 Success")
	}
	if d[0] == opFailure {
		return Packet{}, fmt.Errorf("eap: server reported MSCHAPv2 failure: %q", trimMessage(d))
	}
	if d[0] != opSuccess {
		return Packet{}, fmt.Errorf("eap: expected MSCHAPv2 Success opcode, got %d", d[0])
	}
	// Message is ASCII "S=<40 hex>[ M=...]" starting after OpCode|ID|MS-Length.
	// Compare the expected "S=..." prefix in constant time (it is derived from
	// the password hash) instead of a short-circuiting strings.HasPrefix.
	msg := messageBody(d)
	exp := m.authResponse
	if len(exp) == 0 {
		// No Challenge was processed, so there is no expected AuthenticatorResponse.
		// An empty expectation makes the constant-time compare below trivially pass,
		// which would accept an unsolicited Success as verified — reject it instead.
		return Packet{}, errors.New("eap: unexpected MSCHAPv2 Success before Challenge")
	}
	if len(msg) < len(exp) || subtle.ConstantTimeCompare([]byte(msg[:len(exp)]), exp) != 1 {
		return Packet{}, errors.New("eap: server AuthenticatorResponse mismatch")
	}
	m.authChecked = true
	// Success Response: a single OpCode octet.
	return Packet{
		Code:       CodeResponse,
		Identifier: req.Identifier,
		Type:       TypeMSCHAPv2,
		Data:       []byte{opSuccess},
	}, nil
}

// IdentityResponse builds an EAP Response/Identity carrying the username, for
// servers that send an EAP Request/Identity before the MSCHAPv2 challenge.
func (m *MSCHAPv2) IdentityResponse(req Packet) Packet {
	return Packet{
		Code:       CodeResponse,
		Identifier: req.Identifier,
		Type:       TypeIdentity,
		Data:       []byte(m.Username),
	}
}

// MSKInputs returns the values consumed by the RFC 3079 MSK derivation.
func (m *MSCHAPv2) MSKInputs() (passwordHashHash, ntResponse []byte) {
	return m.passwordHashHash, m.ntResponse
}

// Verified reports whether the server's MSCHAPv2 AuthenticatorResponse has been
// checked (a successful HandleSuccess). The IKE layer gates MSK derivation on it
// so a server that jumps straight to EAP-Success — skipping the MSCHAPv2-Success
// step — cannot complete IKE_AUTH without proving it knows the password.
func (m *MSCHAPv2) Verified() bool { return m.authChecked }

// messageBody returns the ASCII message of a Success/Failure type-data,
// skipping OpCode|MS-CHAPv2-ID|MS-Length when present.
func messageBody(d []byte) string {
	if len(d) >= 4 {
		// Skip OpCode|ID|MS-Length(2) when the buffer is long enough to hold them.
		return string(d[4:])
	}
	return string(d[1:])
}

func trimMessage(d []byte) string { return strings.TrimSpace(messageBody(d)) }

func putUint16(b []byte, v uint16) {
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}
