package vault

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/text/unicode/norm"
)

type KDFPreset string

const (
	KDFLow KDFPreset = "kdf-low"
	KDFV1  KDFPreset = "kdf-v1"
	KDFV2  KDFPreset = "kdf-v2"
	KDFV3  KDFPreset = "kdf-v3"
)

type KDFParameters struct {
	MemoryKiB, Iterations uint32
	Parallelism           uint8
}

func Parameters(preset KDFPreset) (KDFParameters, error) {
	switch preset {
	case KDFLow:
		return KDFParameters{64 * 1024, 3, 4}, nil
	case KDFV1:
		return KDFParameters{256 * 1024, 3, 4}, nil
	case KDFV2:
		return KDFParameters{512 * 1024, 3, 4}, nil
	case KDFV3:
		return KDFParameters{1024 * 1024, 4, 4}, nil
	default:
		return KDFParameters{}, ErrFormat
	}
}

// One Argon2 allocation at a time, including simultaneous requests to different
// vaults in tests. Cancellation never starts a second derivation while the first
// still owns its memory. Argon2 itself cannot be interrupted safely.
var derivationGate = make(chan struct{}, 1)

func DerivePassword(ctx context.Context, password, salt []byte, preset KDFPreset) ([]byte, error) {
	params, err := Parameters(preset)
	if err != nil || len(password) == 0 || len(password) > 1024 || len(salt) < 16 || len(salt) > 64 {
		return nil, ErrFormat
	}
	select {
	case derivationGate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { debug.FreeOSMemory(); <-derivationGate }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, err := passwordKey(password, salt, params)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		Wipe(key)
		return nil, err
	}
	return key, nil
}

// Wipe is best effort for temporary buffers. The lifetime of persistent keys
// must be owned by securemem, and process termination is the lock boundary.
func Wipe(value []byte) { clear(value); runtime.KeepAlive(value) }

type KeyPurpose string

const (
	PurposeLogin             KeyPurpose = "wormhole/v1/login"
	PurposeUnlock            KeyPurpose = "wormhole/v1/unlock"
	PurposeLocalSeal         KeyPurpose = "wormhole/v1/local-seal"
	PurposeLocalBackup       KeyPurpose = "wormhole/v1/local-backup"
	PurposeKCV               KeyPurpose = "wormhole/v1/kcv"
	PurposeSQLite            KeyPurpose = "wormhole/sqlite/adiantum/v1"
	PurposeBrowserState      KeyPurpose = "wormhole/v1/browser-state-stage"
	PurposeTunnelImport      KeyPurpose = "wormhole/v1/tunnel-import-stage"
	PurposeHello             KeyPurpose = "wormhole/v1/hello"
	PurposeTouchID           KeyPurpose = "wormhole/v1/touch-id"
	PurposeSharedTrust       KeyPurpose = "wormhole/v1/shared-trust"
	PurposeSharedDeviceRoot  KeyPurpose = "wormhole/v1/shared-device-root"
	PurposeSharedDeviceSetup KeyPurpose = "wormhole/v1/shared-device-setup"
)

func DeriveKey(key, salt []byte, purpose KeyPurpose) ([]byte, error) {
	if len(key) != 32 || len(salt) > MaxContextBytes {
		return nil, ErrFormat
	}
	switch purpose {
	case PurposeLogin, PurposeUnlock, PurposeLocalSeal, PurposeLocalBackup, PurposeKCV, PurposeSQLite, PurposeHello, PurposeTouchID, PurposeTunnelImport, PurposeBrowserState, PurposeSharedTrust, PurposeSharedDeviceRoot, PurposeSharedDeviceSetup:
		return hkdf.Key(sha256.New, key, salt, string(purpose), 32)
	default:
		return nil, ErrFormat
	}
}

// ASK is required to be either absent or 256 random bits. Its presence must be
// authenticated by the caller's slot/profile, never inferred from login input.
func MixAccountSecret(master, ask []byte, required bool) ([]byte, error) {
	if len(master) != 32 || (required && len(ask) != 32) || (!required && len(ask) != 0) {
		return nil, ErrFormat
	}
	return hkdf.Key(sha256.New, master, ask, "wormhole/v1/account-master", 32)
}

func SharedSalt(workspaceID, loginName string) ([]byte, error) {
	id, err := uuid.Parse(workspaceID)
	if err != nil || id == uuid.Nil || id.String() != workspaceID || !validText(loginName, 256, false) {
		return nil, ErrFormat
	}
	canonicalName := norm.NFC.String(strings.ToLower(norm.NFC.String(loginName)))
	if loginName != canonicalName {
		return nil, ErrFormat
	}
	// The workspace ID is a fixed-width canonical UUID, so concatenation cannot
	// create an ambiguous boundary with the immutable, normalized LoginName.
	salt := sha256.Sum256([]byte("wormhole/v1/salt" + workspaceID + loginName))
	return salt[:], nil
}

func KeyCheck(key []byte, vaultID, fileID string) ([]byte, error) {
	if !validText(vaultID, MaxContextBytes, false) || !validText(fileID, MaxContextBytes, false) {
		return nil, ErrFormat
	}
	subkey, err := DeriveKey(key, nil, PurposeKCV)
	if err != nil {
		return nil, err
	}
	defer Wipe(subkey)
	mac := hmac.New(sha256.New, subkey)
	mac.Write(canonical("wormhole/v1/key-check", []byte(vaultID), []byte(fileID)))
	return mac.Sum(nil), nil
}

func VerifyKeyCheck(key []byte, vaultID, fileID string, expected []byte) error {
	actual, err := KeyCheck(key, vaultID, fileID)
	if err != nil {
		return err
	}
	if !hmac.Equal(actual, expected) {
		return ErrAuthentication
	}
	return nil
}
