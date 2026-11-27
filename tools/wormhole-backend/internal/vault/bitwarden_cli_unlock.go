package vault

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	BitwardenCLIUnlockLifetime = 5 * time.Minute
	MaxBitwardenCLIPassword    = 4096
)

type BitwardenCLIUnlockBinding struct {
	WorkspaceID   string `json:"workspaceId"`
	RequestID     string `json:"requestId"`
	Configuration string `json:"configuration"`
	VaultKey      []byte `json:"vaultKey"`
	ExpiresAt     int64  `json:"expiresAt"`
}

func (b BitwardenCLIUnlockBinding) Validate(now time.Time) error {
	for _, value := range []string{b.WorkspaceID, b.RequestID} {
		id, err := uuid.Parse(value)
		if err != nil || id == uuid.Nil || id.String() != value {
			return ErrFormat
		}
	}
	digest, err := hex.DecodeString(b.Configuration)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != b.Configuration ||
		validateX25519Public(b.VaultKey) != nil || b.ExpiresAt <= now.UnixMilli() ||
		b.ExpiresAt > now.Add(BitwardenCLIUnlockLifetime).UnixMilli() {
		return ErrFormat
	}
	return nil
}

func (b BitwardenCLIUnlockBinding) info(domain string) []byte {
	return canonical(domain, []byte(b.WorkspaceID), []byte(b.RequestID), []byte(b.Configuration),
		b.VaultKey, strconv.AppendInt(nil, b.ExpiresAt, 10))
}

func validBitwardenCLIPassword(value []byte) bool {
	return len(value) > 0 && len(value) <= MaxBitwardenCLIPassword &&
		utf8.Valid(value) && bytes.IndexAny(value, "\x00\r\n") < 0
}

func SealBitwardenCLIPassword(recipient []byte, b BitwardenCLIUnlockBinding, raw []byte, now time.Time) (SealedBundle, error) {
	if b.Validate(now) != nil || !validBitwardenCLIPassword(raw) || validateX25519Public(recipient) != nil ||
		bytes.Equal(recipient, b.VaultKey) {
		return SealedBundle{}, ErrFormat
	}
	return sealBundlePayload(recipient, b.info("wormhole/v1/bitwarden-cli-password"), raw)
}

func OpenBitwardenCLIPassword(private []byte, b BitwardenCLIUnlockBinding, sealed SealedBundle, now time.Time) ([]byte, error) {
	if b.Validate(now) != nil || validateSealedBundle(sealed) != nil || len(sealed.Ciphertext) > MaxBitwardenCLIPassword+16 {
		return nil, ErrFormat
	}
	raw, err := openBundlePayload(private, b.info("wormhole/v1/bitwarden-cli-password"), sealed)
	if err != nil {
		return nil, err
	}
	if !validBitwardenCLIPassword(raw) {
		Wipe(raw)
		return nil, ErrFormat
	}
	return raw, nil
}

func SealBitwardenCLISession(b BitwardenCLIUnlockBinding, raw []byte, now time.Time) (SealedBundle, error) {
	if b.Validate(now) != nil || len(raw) == 0 || len(raw) > MaxBitwardenSession {
		return SealedBundle{}, ErrFormat
	}
	return sealBundlePayload(b.VaultKey, b.info("wormhole/v1/bitwarden-cli-session"), raw)
}

func OpenBitwardenCLISession(private []byte, b BitwardenCLIUnlockBinding, sealed SealedBundle, now time.Time) ([]byte, error) {
	if b.Validate(now) != nil || validateSealedBundle(sealed) != nil || len(sealed.Ciphertext) <= 16 ||
		len(sealed.Ciphertext) > MaxBitwardenSession+16 {
		return nil, ErrFormat
	}
	return openBundlePayload(private, b.info("wormhole/v1/bitwarden-cli-session"), sealed)
}
