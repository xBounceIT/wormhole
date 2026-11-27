package vault

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"unicode/utf8"

	"github.com/google/uuid"
)

const MaxTunnelAuthenticationField = 4096
const MaxTunnelAuthenticationCiphertext = 10 + 2*MaxTunnelAuthenticationField + 16

// The challenge belongs to one native route attempt, not a saved credential.
// Its purpose and input shape cannot be changed by the transport or document.
type TunnelAuthenticationBinding struct {
	Route            TunnelBundleBinding
	ChallengeID      string
	UsernameRequired bool
}

func (b TunnelAuthenticationBinding) info() ([]byte, error) {
	if _, err := b.Route.info(); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(b.ChallengeID)
	if err != nil || id == uuid.Nil || id.String() != b.ChallengeID || b.Route.Kind != 9 {
		return nil, ErrFormat
	}
	r := b.Route
	return canonical("wormhole/v1/tunnel-authentication", []byte(r.WorkspaceID), []byte(r.FileID), []byte(r.NodeID), []byte(r.SessionID), []byte(r.RequestID), []byte(r.Protocol), []byte(r.Host), []byte(strconv.Itoa(int(r.Port))), []byte(strconv.FormatUint(r.Epoch, 10)), []byte(r.TunnelConfigID), []byte(strconv.Itoa(int(r.Kind))), []byte(strconv.FormatUint(r.RowVersion, 10)), []byte(strconv.FormatUint(r.ConfigurationVersion, 10)), []byte(b.ChallengeID), []byte(strconv.FormatBool(b.UsernameRequired))), nil
}

type TunnelAuthenticationPayload struct{ Username, Password []byte }

// Payload views borrow raw; the caller owns wiping the complete encoded frame.
func DecodeTunnelAuthentication(raw []byte, usernameRequired bool) (TunnelAuthenticationPayload, error) {
	if len(raw) < 11 || len(raw) > MaxTunnelAuthenticationCiphertext-16 || raw[0] != 1 || raw[1] != 1 {
		return TunnelAuthenticationPayload{}, ErrFormat
	}
	u, p := binary.BigEndian.Uint32(raw[2:6]), binary.BigEndian.Uint32(raw[6:10])
	if u > MaxTunnelAuthenticationField || p == 0 || p > MaxTunnelAuthenticationField || uint64(u)+uint64(p)+10 != uint64(len(raw)) || (u > 0) != usernameRequired {
		return TunnelAuthenticationPayload{}, ErrFormat
	}
	result := TunnelAuthenticationPayload{raw[10 : 10+u], raw[10+u:]}
	for _, value := range [][]byte{result.Username, result.Password} {
		if !utf8.Valid(value) {
			return TunnelAuthenticationPayload{}, ErrFormat
		}
		for _, b := range value {
			if b < 32 || b == 127 {
				return TunnelAuthenticationPayload{}, ErrFormat
			}
		}
	}
	if usernameRequired && len(bytes.TrimSpace(result.Username)) == 0 {
		return TunnelAuthenticationPayload{}, ErrFormat
	}
	return result, nil
}

func EncodeTunnelAuthentication(username, password []byte, usernameRequired bool) ([]byte, error) {
	if len(username) > MaxTunnelAuthenticationField || len(password) > MaxTunnelAuthenticationField {
		return nil, ErrFormat
	}
	raw := make([]byte, 10+len(username)+len(password))
	raw[0] = 1
	raw[1] = 1
	binary.BigEndian.PutUint32(raw[2:6], uint32(len(username)))
	binary.BigEndian.PutUint32(raw[6:10], uint32(len(password)))
	copy(raw[10:], username)
	copy(raw[10+len(username):], password)
	if _, err := DecodeTunnelAuthentication(raw, usernameRequired); err != nil {
		Wipe(raw)
		return nil, err
	}
	return raw, nil
}

func SealTunnelAuthentication(public []byte, b TunnelAuthenticationBinding, username, password []byte) (SealedBundle, error) {
	info, err := b.info()
	if err != nil {
		return SealedBundle{}, err
	}
	raw, err := EncodeTunnelAuthentication(username, password, b.UsernameRequired)
	if err != nil {
		return SealedBundle{}, err
	}
	defer Wipe(raw)
	return sealBundlePayload(public, info, raw)
}

func OpenTunnelAuthentication(private []byte, b TunnelAuthenticationBinding, sealed SealedBundle) ([]byte, error) {
	if validateSealedBundle(sealed) != nil || len(sealed.Ciphertext) < 27 || len(sealed.Ciphertext) > MaxTunnelAuthenticationCiphertext {
		return nil, ErrFormat
	}
	info, err := b.info()
	if err != nil {
		return nil, err
	}
	raw, err := openBundlePayload(private, info, sealed)
	if err != nil {
		return nil, err
	}
	if _, err := DecodeTunnelAuthentication(raw, b.UsernameRequired); err != nil {
		Wipe(raw)
		return nil, err
	}
	return raw, nil
}
