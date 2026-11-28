package vault

import "encoding/binary"

const MaxVNCPasswordBytes = 16 * 1024

// VNC authentication consumes bytes, including empty passwords. Presence is
// authenticated separately so an absent secret cannot become an explicit one.
type VNCBundlePayload struct {
	Password         []byte
	PasswordProvided bool
}

func EncodeVNCBundle(p VNCBundlePayload) ([]byte, error) {
	if len(p.Password) > MaxVNCPasswordBytes || (!p.PasswordProvided && len(p.Password) != 0) {
		return nil, ErrFormat
	}
	out := make([]byte, 6, 6+len(p.Password))
	out[0] = 1
	if p.PasswordProvided {
		out[1] = 1
	}
	binary.BigEndian.PutUint32(out[2:], uint32(len(p.Password)))
	return append(out, p.Password...), nil
}

// Password borrows the decrypted frame. Its owner must wipe the frame after use.
func DecodeVNCBundle(raw []byte) (VNCBundlePayload, error) {
	if len(raw) < 6 || len(raw) > 6+MaxVNCPasswordBytes || raw[0] != 1 || raw[1] > 1 || uint64(binary.BigEndian.Uint32(raw[2:6])) != uint64(len(raw)-6) || (raw[1] == 0 && len(raw) != 6) {
		return VNCBundlePayload{}, ErrFormat
	}
	return VNCBundlePayload{Password: raw[6:], PasswordProvided: raw[1] == 1}, nil
}
