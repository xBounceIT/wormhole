package vault

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"unicode/utf8"
)

const MaxRDPBundleBytes = 64 * 1024

// RDPBundlePayload lives only in the vault and the native session process.
// Passwords borrow the decoded frame; its owner wipes it after native handoff.
// Settings and both identities are encrypted to prevent a relay changing them.
type RDPBundlePayload struct {
	Settings                                  RDPSettings
	Username, GatewayUsername, GatewayDomain  string
	Password, GatewayPassword                 []byte
	PasswordProvided, GatewayPasswordProvided bool
}

func (p RDPBundlePayload) validate() error {
	normalized, err := NormalizeRDPSettings(&p.Settings)
	if err != nil || normalized != p.Settings {
		return ErrFormat
	}
	if p.Settings.UseExternalClient {
		return ErrPolicy
	}
	for _, value := range []string{p.Settings.Domain, p.Settings.ScreenSize, p.Settings.GatewayHostname, p.Settings.RedirectDrives} {
		if !utf8.ValidString(value) {
			return ErrFormat
		}
	}
	for _, value := range []string{p.Username, p.GatewayUsername, p.GatewayDomain} {
		if !validRDPBundleIdentity(value) {
			return ErrFormat
		}
	}
	for _, secret := range []struct {
		value   []byte
		present bool
	}{{p.Password, p.PasswordProvided}, {p.GatewayPassword, p.GatewayPasswordProvided}} {
		if !validRDPBundlePassword(secret.value) || (!secret.present && len(secret.value) != 0) {
			return ErrFormat
		}
	}
	if (p.Settings.GatewayUsageMethod == 0 || p.Settings.GatewayUseSameCreds) && (p.GatewayPasswordProvided || p.GatewayUsername != "" || p.GatewayDomain != "") {
		return ErrPolicy
	}
	return nil
}

func validRDPBundleIdentity(value string) bool {
	return utf8.ValidString(value) && len(value) <= 2048 && ValidRDPText(value, 513)
}

func validRDPBundlePassword(value []byte) bool {
	return len(value) <= 16384 && utf8.Valid(value) && utf8.RuneCount(value) <= 4096 && bytes.IndexAny(value, "\r\n\x00") < 0
}

func EncodeRDPBundle(p RDPBundlePayload) ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	public, err := json.Marshal(p.Settings)
	if err != nil {
		return nil, ErrFormat
	}
	fields := [][]byte{[]byte(p.Username), []byte(p.GatewayUsername), []byte(p.GatewayDomain), public, p.Password, p.GatewayPassword}
	size := 2 + 4*len(fields)
	for _, value := range fields {
		if len(value) > MaxRDPBundleBytes-size {
			return nil, ErrFormat
		}
		size += len(value)
	}
	raw := make([]byte, 2, size)
	raw[0] = 1
	if p.PasswordProvided {
		raw[1] |= 1
	}
	if p.GatewayPasswordProvided {
		raw[1] |= 2
	}
	for _, value := range fields {
		raw = binary.BigEndian.AppendUint32(raw, uint32(len(value)))
		raw = append(raw, value...)
	}
	return raw, nil
}

func DecodeRDPBundle(raw []byte) (RDPBundlePayload, error) {
	var p RDPBundlePayload
	if len(raw) < 26 || len(raw) > MaxRDPBundleBytes || raw[0] != 1 || raw[1] > 3 {
		return p, ErrFormat
	}
	var fields [6][]byte
	rest := raw[2:]
	for i := range fields {
		if len(rest) < 4 {
			return p, ErrFormat
		}
		size := uint64(binary.BigEndian.Uint32(rest))
		rest = rest[4:]
		if size > uint64(len(rest)) {
			return p, ErrFormat
		}
		fields[i], rest = rest[:int(size)], rest[int(size):]
	}
	if len(rest) != 0 || json.Unmarshal(fields[3], &p.Settings) != nil {
		return p, ErrFormat
	}
	// Only our complete canonical public settings object is accepted: duplicate,
	// missing and unknown keys cannot create a second interpretation of policy.
	public, err := json.Marshal(p.Settings)
	if err != nil || !bytes.Equal(public, fields[3]) {
		return p, ErrFormat
	}
	p.Username, p.GatewayUsername, p.GatewayDomain = string(fields[0]), string(fields[1]), string(fields[2])
	p.Password, p.GatewayPassword = fields[4], fields[5]
	p.PasswordProvided, p.GatewayPasswordProvided = raw[1]&1 != 0, raw[1]&2 != 0
	if err := p.validate(); err != nil {
		return RDPBundlePayload{}, err
	}
	return p, nil
}

// The embedded clients use a loopback forwarder for SOCKS routes. Preserve the
// existing restriction instead of silently weakening gateway/certificate policy.
func ValidateRDPRoute(settings RDPSettings, routed bool) error {
	if settings.UseExternalClient || (routed && (settings.GatewayUsageMethod != 0 || settings.ServerAuthentication == 1)) {
		return ErrPolicy
	}
	return nil
}
