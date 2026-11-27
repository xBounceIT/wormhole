package vault

import (
	"encoding/binary"
	"github.com/google/uuid"
	"net/url"
	"strconv"
	"strings"
)

const MaxTunnelCookieBytes = 16 * 1024

type TunnelCookieBinding struct {
	Route                   TunnelBundleBinding
	ChallengeID, StartURL   string
	IgnoreCertificateErrors bool
	UseSamlCallback         bool
}

func (b TunnelCookieBinding) info() ([]byte, error) {
	if _, err := b.Route.info(); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(b.ChallengeID)
	if err != nil || id == uuid.Nil || id.String() != b.ChallengeID || b.Route.Kind != 2 {
		return nil, ErrFormat
	}
	u, err := url.Parse(b.StartURL)
	if err != nil || len(b.StartURL) > 4096 || strings.IndexFunc(b.StartURL, func(r rune) bool { return r <= 32 || r == 127 }) >= 0 || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "/remote/saml/start" || u.Fragment != "" {
		return nil, ErrFormat
	}
	mode := "SVPNCOOKIE"
	if b.UseSamlCallback {
		if u.RawQuery != "redirect=1" {
			return nil, ErrFormat
		}
		mode = "fortinet-ssl"
	} else if u.Query().Has("redirect") {
		return nil, ErrFormat
	}
	r := b.Route
	return canonical("wormhole/v1/tunnel-cookie-authentication", []byte(r.WorkspaceID), []byte(r.FileID), []byte(r.NodeID), []byte(r.SessionID), []byte(r.RequestID), []byte(r.Protocol), []byte(r.Host), []byte(strconv.Itoa(int(r.Port))), []byte(strconv.FormatUint(r.Epoch, 10)), []byte(r.TunnelConfigID), []byte(strconv.Itoa(int(r.Kind))), []byte(strconv.FormatUint(r.RowVersion, 10)), []byte(strconv.FormatUint(r.ConfigurationVersion, 10)), []byte(b.ChallengeID), []byte(b.StartURL), []byte(strconv.FormatBool(b.IgnoreCertificateErrors)), []byte(mode)), nil
}

// RFC6265 cookie-octet. Keep the opaque value unchanged; no header delimiters,
// controls, whitespace, quoting or non-ASCII can cross the native handoff.
func ValidTunnelCookie(value []byte) bool {
	if len(value) == 0 || len(value) > MaxTunnelCookieBytes {
		return false
	}
	for _, b := range value {
		if !(b == 0x21 || (b >= 0x23 && b <= 0x2b) || (b >= 0x2d && b <= 0x3a) || (b >= 0x3c && b <= 0x5b) || (b >= 0x5d && b <= 0x7e)) {
			return false
		}
	}
	return true
}
func ValidFortinetAuthID(value []byte) bool {
	if len(value) == 0 || len(value) > 4096 {
		return false
	}
	for _, b := range value {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}

func (b TunnelCookieBinding) validCredential(value []byte) bool {
	if b.UseSamlCallback {
		return ValidFortinetAuthID(value)
	}
	return ValidTunnelCookie(value)
}

func SealTunnelCookie(public []byte, b TunnelCookieBinding, cookie []byte) (SealedBundle, error) {
	info, err := b.info()
	if err != nil {
		return SealedBundle{}, err
	}
	if !b.validCredential(cookie) {
		return SealedBundle{}, ErrFormat
	}
	raw := make([]byte, 6+len(cookie))
	raw[0] = 1
	raw[1] = 1
	binary.BigEndian.PutUint32(raw[2:6], uint32(len(cookie)))
	copy(raw[6:], cookie)
	defer Wipe(raw)
	return sealBundlePayload(public, info, raw)
}
func OpenTunnelCookie(private []byte, b TunnelCookieBinding, sealed SealedBundle) ([]byte, error) {
	if validateSealedBundle(sealed) != nil || len(sealed.Ciphertext) < 23 || len(sealed.Ciphertext) > 6+MaxTunnelCookieBytes+16 {
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
	if len(raw) < 7 || raw[0] != 1 || raw[1] != 1 || uint64(binary.BigEndian.Uint32(raw[2:6]))+6 != uint64(len(raw)) || !b.validCredential(raw[6:]) {
		Wipe(raw)
		return nil, ErrFormat
	}
	return raw, nil
}
