package vault

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SSHBundlePayload is confined to the vault and the owning SSH child. Its byte
// fields borrow the decrypted frame; callers wipe that frame after dialing.
// Identity and host-key pin are encrypted along with credentials, so relaying
// metadata cannot change the account or weaken host verification.
type SSHBundlePayload struct {
	Username, Fingerprint                         string
	AutoSudo                                      bool
	SFTPOnly                                      bool
	Password, PrivateKey, Passphrase, Certificate []byte
}

// ValidSSHFingerprint accepts only the canonical SHA256 form used by native SSH.
func ValidSSHFingerprint(value string) bool {
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "SHA256:"))
	return err == nil && len(raw) == 32 && value == "SHA256:"+base64.RawStdEncoding.EncodeToString(raw)
}

func (p SSHBundlePayload) validate() error {
	if p.SFTPOnly && p.AutoSudo {
		return ErrPolicy
	}
	if p.Username == "" || len(p.Username) > 2048 || !utf8.ValidString(p.Username) || strings.IndexFunc(p.Username, unicode.IsControl) >= 0 {
		return ErrFormat
	}
	if !ValidSSHFingerprint(p.Fingerprint) {
		return ErrPolicy
	}
	if len(p.Password) == 0 && len(p.PrivateKey) == 0 {
		return ErrPolicy
	}
	return nil
}

// EncodeSSHBundle uses a fixed-order, length-prefixed binary format. It avoids
// immutable base64 secret strings and bounds the complete frame before allocating.
// Version 1 retains the original terminal/auto-sudo format. Version 2 with flag 2
// explicitly requests only SFTP while preserving the binding's credential path.
func EncodeSSHBundle(p SSHBundlePayload) ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	fields := [][]byte{[]byte(p.Username), []byte(p.Fingerprint), p.Password, p.PrivateKey, p.Passphrase, p.Certificate}
	size := 2 + 4*len(fields)
	for _, field := range fields {
		if len(field) > MaxSecretBytes-size {
			return nil, ErrFormat
		}
		size += len(field)
	}
	out := make([]byte, 2, size)
	out[0] = 1
	if p.SFTPOnly {
		out[0], out[1] = 2, 2
	} else if p.AutoSudo {
		out[1] = 1
	}
	for _, field := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(field)))
		out = append(out, field...)
	}
	return out, nil
}

func DecodeSSHBundle(raw []byte) (SSHBundlePayload, error) {
	if len(raw) < 26 || len(raw) > MaxSecretBytes || !((raw[0] == 1 && raw[1] <= 1) || (raw[0] == 2 && raw[1] == 2)) {
		return SSHBundlePayload{}, ErrFormat
	}
	var fields [6][]byte
	rest := raw[2:]
	for i := range fields {
		if len(rest) < 4 {
			return SSHBundlePayload{}, ErrFormat
		}
		size := uint64(binary.BigEndian.Uint32(rest))
		rest = rest[4:]
		if size > uint64(len(rest)) {
			return SSHBundlePayload{}, ErrFormat
		}
		fields[i], rest = rest[:int(size)], rest[int(size):]
	}
	if len(rest) != 0 {
		return SSHBundlePayload{}, ErrFormat
	}
	p := SSHBundlePayload{Username: string(fields[0]), Fingerprint: string(fields[1]), AutoSudo: raw[1] == 1, SFTPOnly: raw[0] == 2,
		Password: fields[2], PrivateKey: fields[3], Passphrase: fields[4], Certificate: fields[5]}
	if err := p.validate(); err != nil {
		return SSHBundlePayload{}, err
	}
	return p, nil
}
