package localvault

import (
	"bytes"
	"context"
	"crypto/hmac"
	"errors"
	"math"
	"sync"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// A purpose-limited admission and its cleanup obligations. The old Owner is
// never returned. Partial allocations remain reachable even if opening fails.
type unprotectedUpgradeAdmission struct {
	target vault.SlotFile
	root   *securemem.Buffer
	store  vaultstore.Store
	owner  *Owner
}

// UnprotectedRootUpgrade can only prepare a protected root-rotation stage. A
// native caller must own the workspace and confirm the new password/recovery
// groups first. Keep this scope until Close positively acknowledges cleanup;
// neither a wire field nor an ordinary Open option can construct its admission.
type UnprotectedRootUpgrade struct {
	mu              sync.Mutex
	started, closed bool
	admission       unprotectedUpgradeAdmission
	stage           *RootRotationStage
}

func NewUnprotectedRootUpgrade() *UnprotectedRootUpgrade { return &UnprotectedRootUpgrade{} }

func (*UnprotectedRootUpgrade) MarshalJSON() ([]byte, error) { return nil, vault.ErrPolicy }

// Stage consumes both keys on every return, authenticates the OS-only source
// before SQLite, and validates its stored policy against the protected target.
// It never grants ordinary source use under a stronger machine/user floor.
func (u *UnprotectedRootUpgrade) Stage(ctx context.Context, source, destination string, options OpenOptions, slots []vault.Slot, oldKey, nextKey []byte) (*RootRotationStage, error) {
	u.mu.Lock()
	defer func() {
		vault.Wipe(oldKey)
		vault.Wipe(nextKey)
		u.mu.Unlock()
	}()
	if u.started || u.closed {
		return nil, vault.ErrPolicy
	}
	u.started = true
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	doc := options.Slots
	if options.Create || options.AllowImport || !options.RequireLocked || doc.Initializing || doc.Encrypted || doc.Migration != nil || doc.Rotation != nil || len(doc.Slots) != 1 || doc.Slots[0].Kind != vault.SlotUnprotected || doc.RootKeyVersion == math.MaxUint32 || doc.Sequence > math.MaxUint64-vault.RootRotationSequenceSpan || doc.FileEpoch == math.MaxUint64 || len(oldKey) != 32 || len(nextKey) != 32 || hmac.Equal(oldKey, nextKey) {
		return nil, vault.ErrPolicy
	}
	// Snapshot before either consuming helper can erase an aliased input.
	previous, next := bytes.Clone(oldKey), bytes.Clone(nextKey)
	// In particular, the original OS-root input need not survive the possibly
	// long graph rewrite once the scope owns its snapshots/locked source root.
	vault.Wipe(oldKey)
	vault.Wipe(nextKey)
	defer vault.Wipe(previous)
	defer vault.Wipe(next)
	target := doc
	target.FormatVersion = vault.SlotFileFormatVersion
	target.RootKeyVersion++
	target.Sequence += vault.RootRotationSequenceSpan
	target.FileEpoch++
	target.Slots = slots
	password, recovery := false, false
	for _, slot := range slots {
		if slot.WrappedKey.KeyVersion != target.RootKeyVersion {
			return nil, vault.ErrFormat
		}
		switch slot.Kind {
		case vault.SlotPassword:
			password = true
		case vault.SlotRecovery:
			recovery = true
		default:
			return nil, vault.ErrPolicy
		}
	}
	if !password || !recovery {
		return nil, vault.ErrPolicy
	}
	encoded, err := vault.EncodeSlotFile(next, target)
	if err != nil {
		return nil, err
	}
	u.admission.target, err = vault.DecodeSlotFile(encoded)
	if err != nil {
		return nil, err
	}
	owner, err := openNativeOwner(ctx, source, options, previous, &u.admission)
	if err != nil {
		return nil, err
	}
	// StageRootRotation re-authenticates source identity/floors/catalog and checks
	// the current target policy before and after rewriting the entire graph.
	u.stage, err = owner.StageRootRotation(ctx, destination, doc, u.admission.target.Slots, next)
	return u.stage, err
}

// Close also retires an unpublished temporary source. It does not delete files
// or release the caller's workspace lease. Failed resources remain for retry.
func (u *UnprotectedRootUpgrade) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.closed = true
	var result error
	if u.stage != nil {
		result = errors.Join(result, u.stage.Close())
	}
	if u.admission.owner != nil {
		result = errors.Join(result, u.admission.owner.Close())
	} else {
		if u.admission.store != nil {
			result = errors.Join(result, u.admission.store.Close())
		}
		if u.admission.root != nil {
			result = errors.Join(result, u.admission.root.Close())
		}
	}
	if result == nil {
		u.stage = nil
		u.admission = unprotectedUpgradeAdmission{}
	}
	return result
}
