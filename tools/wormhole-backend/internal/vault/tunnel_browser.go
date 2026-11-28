package vault

import (
	"github.com/google/uuid"
	"net/url"
	"strconv"
	"strings"
)

// The native recipient also owns the UID and reserved callback listener. This
// public context cannot select another account, callback, route or TLS policy.
type TunnelBrowserBinding struct {
	Route                              TunnelBundleBinding
	ChallengeID, StartURL, CallbackURL string
	IgnoreCertificateErrors            bool
}

func (b TunnelBrowserBinding) info() ([]byte, error) {
	if _, err := b.Route.info(); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(b.ChallengeID)
	if err != nil || id == uuid.Nil || id.String() != b.ChallengeID || b.Route.Kind != 9 {
		return nil, ErrFormat
	}
	start, err := url.Parse(b.StartURL)
	if err != nil || len(b.StartURL) > 4096 || strings.IndexFunc(b.StartURL, func(r rune) bool { return r <= 32 || r == 127 }) >= 0 || start.Scheme != "https" || start.Host == "" || start.User != nil || start.Path != "/saml" || start.Fragment != "" {
		return nil, ErrFormat
	}
	callback, err := url.Parse(b.CallbackURL)
	if err != nil || callback.Scheme != "http" || callback.Hostname() != "127.0.0.1" || callback.User != nil || callback.Path != "/" || callback.RawQuery != "" || callback.ForceQuery || callback.Fragment != "" {
		return nil, ErrFormat
	}
	port, err := strconv.Atoi(callback.Port())
	if err != nil || port < 1 || port > 65535 || b.CallbackURL != "http://127.0.0.1:"+strconv.Itoa(port)+"/" {
		return nil, ErrFormat
	}
	r := b.Route
	return canonical("wormhole/v1/tunnel-browser-authentication", []byte(r.WorkspaceID), []byte(r.FileID), []byte(r.NodeID), []byte(r.SessionID), []byte(r.RequestID), []byte(r.Protocol), []byte(r.Host), []byte(strconv.Itoa(int(r.Port))), []byte(strconv.FormatUint(r.Epoch, 10)), []byte(r.TunnelConfigID), []byte(strconv.Itoa(int(r.Kind))), []byte(strconv.FormatUint(r.RowVersion, 10)), []byte(strconv.FormatUint(r.ConfigurationVersion, 10)), []byte(b.ChallengeID), []byte(b.StartURL), []byte(b.CallbackURL), []byte(strconv.FormatBool(b.IgnoreCertificateErrors))), nil
}
func SealTunnelBrowserToken(public []byte, b TunnelBrowserBinding, token []byte) (SealedBundle, error) {
	info, err := b.info()
	if err != nil {
		return SealedBundle{}, err
	}
	if !validTunnelBrowserToken(token) {
		return SealedBundle{}, ErrFormat
	}
	raw := append([]byte{1, 1}, token...)
	defer Wipe(raw)
	return sealBundlePayload(public, info, raw)
}
func OpenTunnelBrowserToken(private []byte, b TunnelBrowserBinding, sealed SealedBundle) ([]byte, error) {
	if validateSealedBundle(sealed) != nil || len(sealed.Ciphertext) != 50 {
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
	if len(raw) != 34 || raw[0] != 1 || raw[1] != 1 || !validTunnelBrowserToken(raw[2:]) {
		Wipe(raw)
		return nil, ErrFormat
	}
	return raw, nil
}

// Keep the hexadecimal spelling: it is an opaque EAP password, not a number.
func validTunnelBrowserToken(token []byte) bool {
	if len(token) != 32 {
		return false
	}
	for _, b := range token {
		if !((b >= 48 && b <= 57) || (b >= 65 && b <= 70) || (b >= 97 && b <= 102)) {
			return false
		}
	}
	return true
}
