package sharedpg

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

var ErrDeviceTrustRootCleanup = errors.New("shared device trust root cleanup is unconfirmed")

// DeviceTrustRoot owns a password/ASK-derived device root, independent of the
// master owner's lifetime. It is not an enrollment certificate or a key slot.
// Binding must come from independently authenticated native enrollment.
// Use borrows the slice; callbacks must not reenter this owner or retain it.
type DeviceTrustRoot struct {
	memory  accountMasterMemory
	binding TrustBinding
}

func (r *DeviceTrustRoot) Use(use func([]byte) error) error {
	if r == nil || r.memory == nil || use == nil {
		return securemem.ErrClosed
	}
	return r.memory.With(use)
}

func (r *DeviceTrustRoot) Close() error {
	if r == nil || r.memory == nil {
		return nil
	}
	return r.memory.Close()
}

func (r *DeviceTrustRoot) Locked() bool { return r != nil && r.memory != nil && r.memory.Locked() }

func (r *DeviceTrustRoot) Binding() TrustBinding {
	if r == nil {
		return TrustBinding{}
	}
	return r.binding
}

// DeriveTrustRoot separates device metadata keys from login and account capsule
// keys. Repeating the same password/ASK derivation and binding recovers the same
// root without persisting it. A password/ASK change requires the existing root
// transition protocol. Always Close a nonnil result, even alongside an error.
func (m *AccountMaster) DeriveTrustRoot(ctx context.Context, b TrustBinding) (*DeviceTrustRoot, error) {
	return m.deriveTrustRoot(ctx, b, func(required bool) (accountMasterMemory, error) { return securemem.New(32, required) })
}

func (m *AccountMaster) deriveTrustRoot(ctx context.Context, b TrustBinding, allocate func(bool) (accountMasterMemory, error)) (result *DeviceTrustRoot, err error) {
	if ctx == nil || m == nil || m.WorkspaceID() != b.WorkspaceID {
		return nil, ErrConfiguration
	}
	if _, err := b.binding(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Fixed-width UUIDs followed by a big-endian version make the salt
	// unambiguous and stable across platforms; no mutable policy enters it.
	var salt [68]byte
	copy(salt[0:16], b.WorkspaceID[:])
	copy(salt[16:32], b.UserID[:])
	copy(salt[32:48], b.DeviceID[:])
	copy(salt[48:64], b.KeyID[:])
	binary.BigEndian.PutUint32(salt[64:], b.KeyVersion)
	err = m.Use(func(master []byte, _ vault.KDFPreset, _ bool) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		key, err := vault.DeriveKey(master, salt[:], vault.PurposeSharedDeviceRoot)
		if err != nil {
			return err
		}
		defer vault.Wipe(key)
		memory, err := allocate(m.requireLocked)
		if err != nil {
			return err
		}
		result = &DeviceTrustRoot{memory: memory, binding: b}
		if err := memory.With(func(value []byte) error { copy(value, key); return nil }); err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil && result != nil {
		if result.Close() != nil {
			err = errors.Join(err, ErrDeviceTrustRootCleanup)
		} else {
			result = nil
		}
	}
	return result, err
}
