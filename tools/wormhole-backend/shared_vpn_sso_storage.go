package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// Admission-gate-owned personal cache. Its random storage root is independent
// of workspace/account keys and survives password rewraps. No ordinary workspace
// IPC receives this owner or a local tree backed by this database.
type sharedVPNSSOStorage struct {
	owner           *localvault.Owner
	vaultID, fileID string
	protection      sharedStartupProtection
	transfers       map[string]sharedVPNSSOSource
}

type sharedVPNSSOReceiptKey struct{}
type sharedVPNSSOReceipt struct {
	storage  *sharedVPNSSOStorage
	security localvault.SecurityProfile
	binding  localvault.VPNSSOBinding
	active   bool // valid only during the synchronous admitted callback
}

func (p *sharedVPNSSOStorage) security(ctx context.Context) (localvault.SecurityProfile, error) {
	if ctx == nil {
		return localvault.SecurityProfile{}, vault.ErrPolicy
	}
	r, _ := ctx.Value(sharedVPNSSOReceiptKey{}).(*sharedVPNSSOReceipt)
	if r == nil || !r.active || r.storage != p {
		return localvault.SecurityProfile{}, vault.ErrPolicy
	}
	return r.security, nil
}

func sharedVPNSSOPath(path string) string { return path + ".vpn-sso.db" }

// Adopt before closing the native account selection, under the same lifetime
// gate as protocol keys. A remote revocation then closes both owners together.
func (c *sharedAdmissionController) adoptVPNSSOStorage(ctx context.Context, account *sharedpg.UnlockedDeviceAccount, protection sharedStartupProtection) error {
	if ctx == nil || account == nil || protection.protect == nil || protection.unprotect == nil {
		return sharedpg.ErrConfiguration
	}
	if err := takeSharedAdmissionGate(ctx, c.gate); err != nil {
		return err
	}
	defer func() { <-c.gate }()
	if !c.Unlocked() || c.vpnSSO != nil {
		return sharedpg.ErrSessionClosed
	}
	anchor, err := readSharedStartupAnchor(c.trustPath, protection)
	if err != nil {
		return err
	}
	if anchor.Binding != c.trustBinding {
		return vault.ErrAuthentication
	}
	p := &sharedVPNSSOStorage{vaultID: anchor.VaultID, fileID: anchor.FileID, protection: protection}
	err = account.BorrowDeviceStorage(func(key, file []byte) error {
		actual, err := readSharedTrustBytes(sharedDeviceEnrollmentPath(c.trustPath), sharedpg.MaxDeviceEnrollmentFileBytes)
		if err != nil {
			return err
		}
		if !bytes.Equal(actual, file) {
			return errSharedTrustConflict
		}
		slots, envelope, err := sharedpg.DecodeDeviceEnrollmentFile(file)
		if err != nil {
			return err
		}
		metadata, err := sharedpg.OpenDeviceEnrollment(key, slots, anchor.VaultID, anchor.FileID, anchor.MinimumSequence, envelope)
		if err != nil {
			return err
		}
		if metadata.Binding() != c.trustBinding {
			return vault.ErrAuthentication
		}
		_, err = os.Lstat(sharedVPNSSOPath(c.trustPath))
		create := errors.Is(err, os.ErrNotExist)
		if err != nil && !create {
			return err
		}
		// Losing an already-observed cache is an error, never an empty new login.
		if create && len(slots.VPNSSO) != 0 {
			return vault.ErrRollback
		}
		identity := vaultstore.Identity{WorkspaceID: slots.VaultID, FileID: slots.FileID, Root: vaultstore.KeyRef{ID: slots.RootKeyID, Version: slots.RootKeyVersion}}
		p.owner, err = localvault.OpenPersonalVPNSSO(ctx, sharedVPNSSOPath(c.trustPath), identity, slots, bytes.Clone(key), create, false, p.security)
		return err
	})
	if err != nil {
		return err
	}
	c.vpnSSO = p
	if !p.owner.LockedMemory() {
		c.memoryLockWarning.Store(true)
	}
	return nil
}

type sharedVPNSSOSource struct {
	request nativeVPNSSOBegin
	binding localvault.VPNSSOBinding
	context vault.VPNSSOTransferContext
	expires time.Time
}

// Caller holds the admission gate. Persist all observations before returning
// transfer data, even when the source operation was denied. The only slot file
// is the original enrollment; the independently protected startup anchor follows.
func (c *sharedAdmissionController) checkpointVPNSSOLocked(ctx context.Context) error {
	p := c.vpnSSO
	if p == nil || p.owner == nil {
		return sharedpg.ErrSessionClosed
	}
	release, err := tryAcquireExclusiveFileLock(c.trustPath + ".lock")
	if err != nil {
		return errSharedTrustConflict
	}
	defer release()
	if err := requireNoSharedPendingEnrollment(c.trustPath); err != nil {
		return err
	}
	if err := requireNoSharedTrustTransition(c.trustPath); err != nil {
		return err
	}
	anchor, err := readSharedStartupAnchor(c.trustPath, p.protection)
	if err != nil {
		return err
	}
	if anchor.Binding != c.trustBinding || anchor.VaultID != p.vaultID || anchor.FileID != p.fileID {
		return vault.ErrAuthentication
	}
	previous, err := readSharedTrustBytes(sharedDeviceEnrollmentPath(c.trustPath), sharedpg.MaxDeviceEnrollmentFileBytes)
	if err != nil {
		return err
	}
	document, _, err := sharedpg.DecodeDeviceEnrollmentFile(previous)
	if err != nil {
		return err
	}
	if document.Sequence < anchor.MinimumSequence {
		return vault.ErrRollback
	}
	sequence := document.Sequence
	err = p.owner.PersistVPNSSOCheckpoints(ctx, document, func(next vault.SlotFile, key []byte) error {
		raw, err := sharedpg.AdvanceDeviceStorageCheckpoints(ctx, key, previous, p.vaultID, p.fileID, anchor.MinimumSequence, next)
		if err != nil {
			return err
		}
		err = persistSharedTransitionBytes(sharedDeviceEnrollmentPath(c.trustPath), raw)
		if errors.Is(err, errSharedTrustCommitUncertain) {
			err = persistSharedTransitionBytes(sharedDeviceEnrollmentPath(c.trustPath), raw)
		}
		if err == nil {
			sequence = next.Sequence
		}
		return err
	})
	if err != nil {
		return err
	}
	if sequence == anchor.MinimumSequence {
		return nil
	}
	if anchor.Revision == math.MaxInt64 {
		return vault.ErrPolicy
	}
	next := anchor
	next.Revision++
	next.MinimumSequence = sequence
	if !startupAnchorAdvances(anchor, next) || !next.valid(c.trustPath) {
		return errSharedTrustConflict
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	defer vault.Wipe(raw)
	protected, err := p.protection.protect(sharedStartupAnchorPath(c.trustPath), raw)
	if err != nil || len(protected) == 0 || len(protected) > maxSharedStartupAnchorBytes*2 {
		return errSharedTrustStorage
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err = persistSharedTransitionBytes(sharedStartupAnchorPath(c.trustPath), protected)
	if errors.Is(err, errSharedTrustCommitUncertain) {
		err = persistSharedTransitionBytes(sharedStartupAnchorPath(c.trustPath), protected)
	}
	return err
}
