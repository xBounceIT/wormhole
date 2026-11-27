package vault

import (
	"encoding/binary"
	"unicode/utf8"
)

// CredentialDisplayPayload contains only the selected reveal identity and its
// password/passphrase. It never exports a private key or protocol authority.
type CredentialDisplayPayload struct {
	Username, Domain string
	Passphrase       bool
	Secret           []byte
}

func EncodeCredentialDisplay(p CredentialDisplayPayload) ([]byte, error) {
	if len(p.Username) > 2048 || len(p.Domain) > 2048 || len(p.Secret) > 16384 || !utf8.ValidString(p.Username) || !utf8.ValidString(p.Domain) || !utf8.Valid(p.Secret) {
		return nil, ErrFormat
	}
	out := make([]byte, 2, 14+len(p.Username)+len(p.Domain)+len(p.Secret))
	out[0] = 1
	if p.Passphrase {
		out[1] = 1
	}
	for _, field := range [][]byte{[]byte(p.Username), []byte(p.Domain), p.Secret} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(field)))
		out = append(out, field...)
	}
	return out, nil
}

func SealCredentialDisplay(publicKey []byte, workspace, node, request string, revision uint64, payload []byte) (SealedBundle, error) {
	return sealEditorDisplay(publicKey, workspace, node, request, revision, payload, "wormhole/v1/credential-display", 65536)
}
