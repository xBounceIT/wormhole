package sharedpg

import (
	"context"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// TakeDeviceAccount moves the prepared native owners into the ordinary local
// device owner without retaining/re-entering factors or copying key material.
// This proves neither remote commit nor admission: the caller must independently
// confirm enrollment and persist current trust before activating the account.
// Serialize this operation with every preparation borrow and Close. On failure
// preparation still owns everything and must be closed, including cleanup retries.
func (p *PreparedInitialEnrollment) TakeDeviceAccount(ctx context.Context) (*UnlockedDeviceAccount, error) {
	if ctx == nil || p == nil || p.closed || p.master == nil || p.root == nil || p.commit == nil || p.storage == nil || len(p.deviceFile) == 0 {
		return nil, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	slots, envelope, err := DecodeDeviceEnrollmentFile(p.deviceFile)
	if err != nil {
		return nil, err
	}
	err = p.storage.With(func(key []byte) error {
		metadata, err := OpenDeviceEnrollment(key, slots, slots.VaultID, slots.FileID, slots.Sequence, envelope)
		if err != nil {
			return err
		}
		if metadata.Binding() != p.root.Binding() || metadata.record.Binding.WorkspaceID != p.master.WorkspaceID() || metadata.record.LoginName != p.master.LoginName() {
			return ErrTrustState
		}
		return p.master.Use(func(_ []byte, preset vault.KDFPreset, ask bool) error {
			if preset != metadata.record.KDF || ask != metadata.record.ASKRequired {
				return ErrAccountRevision
			}
			return p.root.Use(func([]byte) error { return ctx.Err() })
		})
	})
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	account := &UnlockedDeviceAccount{master: p.master, root: p.root, storage: p.storage, file: p.deviceFile}
	p.commit.Wipe()
	p.master, p.root, p.storage, p.deviceFile, p.commit = nil, nil, nil, nil, nil
	p.closed = true
	return account, nil
}
