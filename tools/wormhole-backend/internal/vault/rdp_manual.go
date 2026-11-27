package vault

import (
	"bytes"
	"encoding/binary"
	"unicode/utf8"
)

const MaxRDPManualCiphertext = 14 + 2048 + 2048 + 16384 + 16

// Only the protected document and native recipient handle this primary account.
// Password borrows the decoded frame; the owner must wipe it after handoff.
type RDPManualCredentials struct {
	Username, Domain string
	Password         []byte
}

func (p RDPManualCredentials) validate() error {
	if p.Username == "" {
		return ErrFormat
	}
	for _, value := range []string{p.Username, p.Domain} {
		if !utf8.ValidString(value) || len(value) > 2048 || !ValidRDPText(value, 513) {
			return ErrFormat
		}
	}
	if len(p.Password) > 16384 || !utf8.Valid(p.Password) || utf8.RuneCount(p.Password) > 4096 || bytes.IndexAny(p.Password, "\r\n\x00") >= 0 {
		return ErrFormat
	}
	return nil
}
func EncodeRDPManualCredentials(p RDPManualCredentials) ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	fields := [][]byte{[]byte(p.Username), []byte(p.Domain), p.Password}
	raw := make([]byte, 2, 14+len(p.Username)+len(p.Domain)+len(p.Password))
	raw[0], raw[1] = 1, 1
	for _, field := range fields {
		raw = binary.BigEndian.AppendUint32(raw, uint32(len(field)))
		raw = append(raw, field...)
	}
	return raw, nil
}
func DecodeRDPManualCredentials(raw []byte) (RDPManualCredentials, error) {
	var p RDPManualCredentials
	if len(raw) < 14 || len(raw) > MaxRDPManualCiphertext-16 || raw[0] != 1 || raw[1] != 1 {
		return p, ErrFormat
	}
	var fields [3][]byte
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
	if len(rest) != 0 {
		return p, ErrFormat
	}
	p = RDPManualCredentials{Username: string(fields[0]), Domain: string(fields[1]), Password: fields[2]}
	if err := p.validate(); err != nil {
		return RDPManualCredentials{}, err
	}
	return p, nil
}
func manualRDPInfo(b BundleBinding, route *TunnelBundleBinding, endpoint string) ([]byte, error) {
	if !ValidRDPHost(b.Host) {
		return nil, ErrFormat
	}
	return manualCredentialInfo(b, route, endpoint, "rdp", "wormhole/v1/rdp-manual-credentials")
}
func SealManualRDPCredentials(public []byte, b BundleBinding, route *TunnelBundleBinding, endpoint string, p RDPManualCredentials) (SealedBundle, error) {
	info, err := manualRDPInfo(b, route, endpoint)
	if err != nil {
		return SealedBundle{}, err
	}
	raw, err := EncodeRDPManualCredentials(p)
	if err != nil {
		return SealedBundle{}, err
	}
	defer Wipe(raw)
	return sealBundlePayload(public, info, raw)
}
func ValidateRDPManualEnvelope(s SealedBundle) error {
	if err := validateSealedBundle(s); err != nil {
		return err
	}
	if len(s.Ciphertext) < 30 || len(s.Ciphertext) > MaxRDPManualCiphertext {
		return ErrFormat
	}
	return nil
}
func OpenManualRDPCredentials(private []byte, b BundleBinding, route *TunnelBundleBinding, endpoint string, s SealedBundle) ([]byte, error) {
	if err := ValidateRDPManualEnvelope(s); err != nil {
		return nil, err
	}
	info, err := manualRDPInfo(b, route, endpoint)
	if err != nil {
		return nil, err
	}
	raw, err := openBundlePayload(private, info, s)
	if err != nil {
		return nil, err
	}
	if _, err = DecodeRDPManualCredentials(raw); err != nil {
		Wipe(raw)
		return nil, err
	}
	return raw, nil
}
func validRDPManualBase(p RDPBundlePayload) error {
	if p.Username != "" || p.Settings.Domain != "" || p.PasswordProvided || len(p.Password) != 0 {
		return ErrPolicy
	}
	return p.validate()
}

// Version 2 contains an authenticated native options/gateway frame and the
// opaque primary credential envelope. It can never authorize saved fallback.
func EncodeRDPManualAuthorization(base RDPBundlePayload, inner SealedBundle) ([]byte, error) {
	if err := validRDPManualBase(base); err != nil {
		return nil, err
	}
	if err := ValidateRDPManualEnvelope(inner); err != nil {
		return nil, err
	}
	frame, err := EncodeRDPBundle(base)
	if err != nil {
		return nil, err
	}
	defer Wipe(frame)
	size := 5 + len(frame) + 36 + len(inner.Ciphertext)
	if size > MaxRDPBundleBytes {
		return nil, ErrFormat
	}
	raw := make([]byte, 1, size)
	raw[0] = 2
	raw = binary.BigEndian.AppendUint32(raw, uint32(len(frame)))
	raw = append(raw, frame...)
	raw = append(raw, inner.Enc...)
	raw = binary.BigEndian.AppendUint32(raw, uint32(len(inner.Ciphertext)))
	raw = append(raw, inner.Ciphertext...)
	return raw, nil
}

// Both returned password/envelope fields borrow raw. Wipe after native handoff.
func DecodeRDPManualAuthorization(raw []byte) (RDPBundlePayload, SealedBundle, error) {
	var base RDPBundlePayload
	var inner SealedBundle
	if len(raw) < 97 || len(raw) > MaxRDPBundleBytes || raw[0] != 2 {
		return base, inner, ErrFormat
	}
	size := uint64(binary.BigEndian.Uint32(raw[1:5]))
	if size > uint64(len(raw)-5) || size < 26 {
		return base, inner, ErrFormat
	}
	var err error
	base, err = DecodeRDPBundle(raw[5 : 5+int(size)])
	if err != nil {
		return RDPBundlePayload{}, inner, err
	}
	if err = validRDPManualBase(base); err != nil {
		return RDPBundlePayload{}, inner, err
	}
	rest := raw[5+int(size):]
	if len(rest) < 37 || uint64(binary.BigEndian.Uint32(rest[32:36])) != uint64(len(rest)-36) {
		return RDPBundlePayload{}, inner, ErrFormat
	}
	// Envelope has 32 encapsulation bytes and a 4-byte length (no version byte).
	inner = SealedBundle{FormatVersion: FormatVersion, SuiteID: SuiteX25519HKDFSHA256AES256GCM, Enc: rest[:32], Ciphertext: rest[36:]}
	if err = ValidateRDPManualEnvelope(inner); err != nil {
		return RDPBundlePayload{}, SealedBundle{}, err
	}
	return base, inner, nil
}
