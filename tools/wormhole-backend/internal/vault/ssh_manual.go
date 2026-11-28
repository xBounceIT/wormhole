package vault

import (
	"encoding/binary"
	"encoding/hex"
	"strconv"

	"github.com/google/uuid"
)

const MaxSSHManualCiphertext = 2*1024*1024 + 40*1024 + 256

// The context is supplied by the owning native session after host verification.
// The authenticated vault snapshot must still match before the opaque document
// envelope can be authorized. It never grants saved-passphrase fallback.
type SSHManualContext struct {
	Binding                                       BundleBinding
	Route                                         *TunnelBundleBinding
	Endpoint, Mode, FileID, Revision, Fingerprint string
	AutoSudo, SFTPOnly                            bool
}

func (c SSHManualContext) info() ([]byte, error) {
	if (c.Mode != "account" && c.Mode != "passphrase") || (c.Binding.Protocol != "ssh" && c.Binding.Protocol != "sftp") || !ValidSSHFingerprint(c.Fingerprint) || ((c.SFTPOnly || c.Binding.Protocol == "sftp") && c.AutoSudo) {
		return nil, ErrFormat
	}
	id, err := uuid.Parse(c.FileID)
	if err != nil || id == uuid.Nil || id.String() != c.FileID {
		return nil, ErrFormat
	}
	revision, err := hex.DecodeString(c.Revision)
	if err != nil || len(revision) != 32 || hex.EncodeToString(revision) != c.Revision {
		return nil, ErrFormat
	}
	info, err := manualCredentialInfo(c.Binding, c.Route, c.Endpoint, c.Binding.Protocol, "wormhole/v1/ssh-manual-credentials")
	if err != nil {
		return nil, err
	}
	return append(info, canonical("", []byte(c.Mode), []byte(c.FileID), []byte(c.Revision), []byte(c.Fingerprint), []byte(strconv.FormatBool(c.AutoSudo)), []byte(strconv.FormatBool(c.SFTPOnly)))...), nil
}

// Account input uses the existing bounded SSH frame with the verified pin, and
// has no transport flags. Passphrase-only input explicitly accepts an empty
// value; it cannot contain an account or a replacement key/certificate.
func encodeSSHManualCredentials(c SSHManualContext, p SSHBundlePayload) ([]byte, error) {
	if c.Mode == "passphrase" {
		if p.Username != "" || p.Fingerprint != "" || p.AutoSudo || p.SFTPOnly || len(p.Password)+len(p.PrivateKey)+len(p.Certificate) != 0 || len(p.Passphrase) > 16384 {
			return nil, ErrFormat
		}
		raw := make([]byte, 6+len(p.Passphrase))
		raw[0], raw[1] = 1, 2
		binary.BigEndian.PutUint32(raw[2:6], uint32(len(p.Passphrase)))
		copy(raw[6:], p.Passphrase)
		return raw, nil
	}
	if !validSSHManualAccount(c, p) {
		return nil, ErrFormat
	}
	return EncodeSSHBundle(p)
}

func validSSHManualAccount(c SSHManualContext, p SSHBundlePayload) bool {
	return c.Mode == "account" && p.Fingerprint == c.Fingerprint && !p.AutoSudo && !p.SFTPOnly && len(p.Password) <= 16384 && len(p.Passphrase) <= 16384 && len(p.PrivateKey) <= 1024*1024 && len(p.Certificate) <= 1024*1024 && (len(p.PrivateKey) != 0 || len(p.Passphrase)+len(p.Certificate) == 0) && (len(p.PrivateKey) == 0 || len(p.Password) == 0)
}

func DecodeSSHManualCredentials(c SSHManualContext, raw []byte) (SSHBundlePayload, error) {
	if c.Mode == "passphrase" {
		if len(raw) < 6 || len(raw) > 6+16384 || raw[0] != 1 || raw[1] != 2 || uint64(binary.BigEndian.Uint32(raw[2:6])) != uint64(len(raw)-6) {
			return SSHBundlePayload{}, ErrFormat
		}
		return SSHBundlePayload{Passphrase: raw[6:]}, nil
	}
	p, err := DecodeSSHBundle(raw)
	if err != nil {
		return SSHBundlePayload{}, err
	}
	// Validate without allocating/copying the decoded secret frame.
	if !validSSHManualAccount(c, p) {
		return SSHBundlePayload{}, ErrFormat
	}
	return p, nil
}

func SealManualSSHCredentials(public []byte, c SSHManualContext, p SSHBundlePayload) (SealedBundle, error) {
	info, err := c.info()
	if err != nil {
		return SealedBundle{}, err
	}
	raw, err := encodeSSHManualCredentials(c, p)
	if err != nil {
		return SealedBundle{}, err
	}
	defer Wipe(raw)
	return sealBundlePayload(public, info, raw)
}

func validSSHManualEnvelope(s SealedBundle) error {
	if err := validateSealedBundle(s); err != nil {
		return err
	}
	if len(s.Ciphertext) < 22 || len(s.Ciphertext) > MaxSSHManualCiphertext {
		return ErrFormat
	}
	return nil
}

func OpenManualSSHCredentials(private []byte, c SSHManualContext, s SealedBundle) ([]byte, error) {
	if err := validSSHManualEnvelope(s); err != nil {
		return nil, err
	}
	info, err := c.info()
	if err != nil {
		return nil, err
	}
	raw, err := openBundlePayload(private, info, s)
	if err != nil {
		return nil, err
	}
	if _, err = DecodeSSHManualCredentials(c, raw); err != nil {
		Wipe(raw)
		return nil, err
	}
	return raw, nil
}

type SSHManualAuthorization struct {
	Mode, FileID, Revision string
	Base                   SSHBundlePayload
	Manual                 SealedBundle
}

func (a SSHManualAuthorization) validate() error {
	base := a.Base
	if !ValidSSHFingerprint(base.Fingerprint) || (base.SFTPOnly && base.AutoSudo) || len(base.Password)+len(base.Passphrase) != 0 {
		return ErrPolicy
	}
	switch a.Mode {
	case "account":
		if base.Username != "" || len(base.PrivateKey)+len(base.Certificate) != 0 {
			return ErrPolicy
		}
	case "passphrase":
		if len(base.PrivateKey) == 0 || base.validate() != nil {
			return ErrPolicy
		}
	default:
		return ErrFormat
	}
	id, err := uuid.Parse(a.FileID)
	if err != nil || id == uuid.Nil || id.String() != a.FileID {
		return ErrFormat
	}
	revision, err := hex.DecodeString(a.Revision)
	if err != nil || len(revision) != 32 || hex.EncodeToString(revision) != a.Revision {
		return ErrFormat
	}
	return validSSHManualEnvelope(a.Manual)
}

// Version 3 is distinct from both saved terminal and file-only SSH frames.
// There is deliberately no stored password or passphrase field in this format.
func EncodeSSHManualAuthorization(a SSHManualAuthorization) ([]byte, error) {
	if err := a.validate(); err != nil {
		return nil, err
	}
	fields := [][]byte{[]byte(a.Base.Username), []byte(a.Base.Fingerprint), a.Base.PrivateKey, a.Base.Certificate, []byte(a.FileID), []byte(a.Revision), a.Manual.Enc, a.Manual.Ciphertext}
	size := 3 + 4*len(fields)
	for _, field := range fields {
		if len(field) > MaxSecretBytes-size {
			return nil, ErrFormat
		}
		size += len(field)
	}
	raw := make([]byte, 3, size)
	raw[0], raw[1] = 3, 1
	if a.Mode == "passphrase" {
		raw[1] = 2
	}
	if a.Base.AutoSudo {
		raw[2] = 1
	}
	if a.Base.SFTPOnly {
		raw[2] = 2
	}
	for _, field := range fields {
		raw = binary.BigEndian.AppendUint32(raw, uint32(len(field)))
		raw = append(raw, field...)
	}
	return raw, nil
}

// Byte fields borrow raw; the native recipient wipes it after dialing.
func DecodeSSHManualAuthorization(raw []byte) (SSHManualAuthorization, error) {
	if len(raw) < 35 || len(raw) > MaxSecretBytes || raw[0] != 3 || raw[1] < 1 || raw[1] > 2 || raw[2] > 2 {
		return SSHManualAuthorization{}, ErrFormat
	}
	var fields [8][]byte
	rest := raw[3:]
	for i := range fields {
		if len(rest) < 4 {
			return SSHManualAuthorization{}, ErrFormat
		}
		size := uint64(binary.BigEndian.Uint32(rest))
		rest = rest[4:]
		if size > uint64(len(rest)) {
			return SSHManualAuthorization{}, ErrFormat
		}
		fields[i], rest = rest[:int(size)], rest[int(size):]
	}
	if len(rest) != 0 {
		return SSHManualAuthorization{}, ErrFormat
	}
	a := SSHManualAuthorization{Mode: "account", FileID: string(fields[4]), Revision: string(fields[5]), Base: SSHBundlePayload{Username: string(fields[0]), Fingerprint: string(fields[1]), PrivateKey: fields[2], Certificate: fields[3], AutoSudo: raw[2] == 1, SFTPOnly: raw[2] == 2}, Manual: SealedBundle{FormatVersion: FormatVersion, SuiteID: SuiteX25519HKDFSHA256AES256GCM, Enc: fields[6], Ciphertext: fields[7]}}
	if raw[1] == 2 {
		a.Mode = "passphrase"
	}
	if err := a.validate(); err != nil {
		return SSHManualAuthorization{}, err
	}
	return a, nil
}
