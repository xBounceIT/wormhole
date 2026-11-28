// Package localvault owns the local key graph and its native-memory root key.
// It is used only inside the vault process, never by protocol subprocesses or
// the renderer. Resolver authorization must precede every secret operation.
package localvault

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"sync"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type OpenOptions struct {
	Identity        vaultstore.Identity
	Slots           vault.SlotFile
	MinimumSequence uint64
	RequireLocked   bool
	Create          bool
	// Native staging only; never set by ordinary unlock or editor handlers.
	AllowImport bool
}

type Owner struct {
	quickTargets               map[string]*quickTargetStage
	bitwardenInstallationFloor uint64
	bitwardenIntentFloor       uint64
	bitwardenTransfers         map[string]*bitwardenTransferStage
	bitwardenTransferFailure   bool
	bitwarden                  *bitwardenBrowserRuntime
	vpnSSOProfiles             map[string]vpnSSOProfile
	vpnSSOFloors               map[string]VPNSSOFloor
	vpnSSOTransfers            map[string]*vpnSSOTransferStage
	vpnSSOTransferFailure      bool
	vpnSSONodeFloors           map[string]uint64
	vpnSSOObservingNodes       bool
	vpnSSONativeSecurity       func(context.Context) (SecurityProfile, error)
	tunnelFloors               map[string]uint64
	tunnelImports              map[string]tunnelImportStage
	mu                         sync.Mutex
	store                      vaultstore.Store
	root                       *securemem.Buffer
	closed                     bool
	encrypted                  bool
	nodeFloors                 map[string]uint64
	profileFloor               uint64
	sessionSecurity            SecurityProfile
	slotFloor                  uint64
	securitySlots              []vault.Slot
}

// Open consumes and wipes key on every return path. Trusted identity and sequence
// come from the workspace selection/checkpoint, not from an unverified database.
// Authentication finishes before opening SQLite, including on the create path.
func Open(ctx context.Context, path string, options OpenOptions, key []byte) (*Owner, error) {
	return openNativeOwner(ctx, path, options, key, nil)
}

// Only the native upgrade scope can supply target admission. Public Open always
// validates the source; no caller-visible option can relax that policy.
func openNativeOwner(ctx context.Context, path string, options OpenOptions, key []byte, upgrade *unprotectedUpgradeAdmission) (*Owner, error) {
	defer vault.Wipe(key)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	i := options.Identity
	if err := vault.VerifySlotFile(key, options.Slots, i.WorkspaceID, i.FileID, options.MinimumSequence); err != nil {
		return nil, err
	}
	if i.Root.ID != options.Slots.RootKeyID || i.Root.Version != options.Slots.RootKeyVersion {
		return nil, vaultstore.ErrIdentity
	}
	if options.Slots.Rotation != nil || (options.Slots.Migration != nil && !options.AllowImport) {
		return nil, vault.ErrPolicy
	}
	osFloor, err := ospolicy.ReadFloor(ctx)
	if err != nil {
		return nil, err
	}
	if osFloor == vault.Hardened || osFloor == vault.Paranoid {
		return nil, vault.ErrPolicy
	}
	root, err := securemem.New(32, options.RequireLocked || options.Slots.Encrypted)
	if err != nil {
		return nil, err
	}
	if upgrade != nil {
		upgrade.root = root
	}
	if err := root.With(func(dst []byte) error { copy(dst, key); return nil }); err != nil {
		return nil, errors.Join(err, root.Close())
	}
	// Once locked native memory owns it, the caller's root copy must not wait
	// in the Go heap for SQLite/profile IO to finish.
	vault.Wipe(key)
	var store *vaultstore.SQLite
	if options.Slots.Encrypted {
		err = root.With(func(borrowed []byte) error {
			var openErr error
			store, openErr = vaultstore.OpenSQLiteEncrypted(ctx, path, i, options.Create, borrowed)
			return openErr
		})
	} else {
		store, err = vaultstore.OpenSQLite(ctx, path, i, options.Create)
	}
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	if upgrade != nil {
		upgrade.store = store
	}
	if options.Slots.Initializing {
		if err := store.ValidateInitialization(ctx); err != nil {
			return nil, errors.Join(err, store.Close(), root.Close())
		}
	}
	floors := make(map[string]uint64, len(options.Slots.Nodes))
	for _, mark := range options.Slots.Nodes {
		floors[mark.NodeID] = mark.Revision
	}
	owner := &Owner{store: store, root: root, encrypted: options.Slots.Encrypted, nodeFloors: floors, profileFloor: options.Slots.ProfileSequence, slotFloor: options.Slots.Sequence}
	if upgrade != nil {
		upgrade.owner = owner
	}
	owner.tunnelFloors = make(map[string]uint64, len(options.Slots.Tunnels))
	for _, mark := range options.Slots.Tunnels {
		owner.tunnelFloors[mark.TunnelID] = mark.Revision
	}
	if len(options.Slots.VPNSSO) != 0 {
		owner.vpnSSOFloors = make(map[string]VPNSSOFloor, len(options.Slots.VPNSSO))
		for _, mark := range options.Slots.VPNSSO {
			owner.vpnSSOFloors[mark.ScopeID] = vpnSSOFloorFromMark(mark)
		}
	}
	if options.Create || options.Slots.Initializing {
		if err := owner.seedLocalPolicy(ctx, options.Slots); err != nil {
			return nil, errors.Join(err, owner.Close())
		}
	}
	policy, err := owner.ReadLocalPolicy(ctx)
	if err != nil {
		return nil, errors.Join(err, owner.Close())
	}
	securitySlots := options.Slots
	if upgrade != nil {
		securitySlots = upgrade.target
	}
	if _, err := owner.applySecurityProfile(policy, securitySlots, osFloor); err != nil {
		return nil, errors.Join(err, owner.Close())
	}
	owner.rememberSecuritySlots(securitySlots.Slots)
	return owner, nil
}

// WorkspaceID returns the immutable identity authenticated when this owner opened.
func (o *Owner) WorkspaceID(ctx context.Context) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return "", vaultstore.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return o.store.Identity().WorkspaceID, nil
}

func (o *Owner) LockedMemory() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return !o.closed && o.root.Locked()
}

// Close retires the owner even if native release fails; another call retries
// cleanup. The process must exit after Close instead of unlocking in place.
func (o *Owner) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.closeLocked()
}

func (o *Owner) closeLocked() error {
	o.closed = true
	o.quickTargets = nil
	o.vpnSSOProfiles = nil
	o.vpnSSOFloors = nil
	o.clearBitwardenBrowser()
	for id := range o.tunnelImports {
		o.discardTunnelImport(id)
	}
	return errors.Join(o.closeBitwardenTransfers(), o.closeVPNSSOTransfers(), o.store.Close(), o.root.Close())
}

func valueBinding(identity vaultstore.Identity, value vaultstore.Secret) vault.Binding {
	return vault.Binding{WorkspaceID: identity.WorkspaceID, Table: "SecretValues/" + value.Ref.OwnerKind, OwnerID: value.Ref.OwnerID, Field: identity.FileID + ":" + strconv.FormatUint(value.RowVersion, 10) + ":" + value.Ref.Field, KeyID: value.DEK.ID, KeyVersion: value.DEK.Version}
}

func copyBinding(identity vaultstore.Identity, value vaultstore.Secret) vault.Binding {
	// Fixed UUIDs and length-delimited AEAD fields keep this destination unique.
	return vault.Binding{WorkspaceID: identity.WorkspaceID, Table: "KeyCopies", OwnerID: value.DEK.ID, Field: identity.FileID + ":" + strconv.FormatUint(uint64(value.DEK.Version), 10), KeyID: identity.Root.ID, KeyVersion: identity.Root.Version}
}

func recordMAC(key []byte, identity vaultstore.Identity, value vaultstore.Secret) ([]byte, error) {
	subkey, err := vault.DeriveKey(key, []byte(identity.WorkspaceID), vault.PurposeLocalSeal)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(subkey)
	value.Copy.Signature = nil
	body, err := json.Marshal(struct {
		Identity vaultstore.Identity `json:"identity"`
		Value    vaultstore.Secret   `json:"value"`
	}{identity, value})
	if err != nil {
		return nil, vault.ErrFormat
	}
	mac := hmac.New(sha256.New, subkey)
	mac.Write([]byte("wormhole/v1/local-secret-record\x00"))
	mac.Write(body)
	return mac.Sum(nil), nil
}

func verifyRecord(key []byte, identity vaultstore.Identity, value vaultstore.Secret) error {
	mac, err := recordMAC(key, identity, value)
	if err != nil {
		return err
	}
	if !hmac.Equal(mac, value.Copy.Signature) {
		return vault.ErrAuthentication
	}
	return nil
}

// Put rotates this field's independent DEK on every successful write. The input
// is borrowed; its caller remains responsible for wiping it. A stale expected
// revision never overwrites a newer row, even across concurrent domain calls.
func (o *Owner) Put(ctx context.Context, ref vaultstore.SecretRef, plaintext []byte, expected uint64) (uint64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return 0, vaultstore.ErrClosed
	}
	if ref.OwnerKind == "local-state" {
		return 0, vault.ErrPolicy
	}
	value, err := o.prepareSecret(ctx, ref, plaintext, expected)
	if err != nil {
		return 0, err
	}
	if err := o.store.WriteSecret(ctx, value, expected); err != nil {
		return 0, err
	}
	return value.RowVersion, nil
}

// Called only while the owner mutex is held. Does not publish or mutate storage.
func (o *Owner) prepareSecret(ctx context.Context, ref vaultstore.SecretRef, plaintext []byte, expected uint64) (vaultstore.Secret, error) {
	return o.prepareSecretWithReader(ctx, ref, plaintext, expected, o.store.ReadSecret)
}

func (o *Owner) prepareSecretWithReader(ctx context.Context, ref vaultstore.SecretRef, plaintext []byte, expected uint64, read vaultstore.SecretReader) (vaultstore.Secret, error) {
	if !ref.Valid() || len(plaintext) > vault.MaxSecretBytes || expected >= math.MaxInt64 {
		return vaultstore.Secret{}, vault.ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return vaultstore.Secret{}, err
	}
	value := vaultstore.Secret{Ref: ref, DEK: vaultstore.KeyRef{ID: uuid.NewString(), Version: 1}, RowVersion: expected + 1}
	previous, err := read(ctx, ref)
	if errors.Is(err, vaultstore.ErrMissing) {
		if expected != 0 {
			return vaultstore.Secret{}, vaultstore.ErrConflict
		}
	} else if err != nil {
		return vaultstore.Secret{}, err
	} else {
		if previous.Ref != ref {
			return vaultstore.Secret{}, vault.ErrAuthentication
		}
		if previous.RowVersion != expected || previous.DEK.Version == math.MaxUint32 {
			return vaultstore.Secret{}, vaultstore.ErrConflict
		}
		if err := o.root.With(func(key []byte) error { return verifyRecord(key, o.store.Identity(), previous) }); err != nil {
			return vaultstore.Secret{}, err
		}
		value.DEK = previous.DEK
		value.DEK.Version++
	}
	dek := make([]byte, 32)
	rand.Read(dek)
	defer vault.Wipe(dek)
	value.Envelope, err = vault.Seal(dek, valueBinding(o.store.Identity(), value), plaintext)
	if err != nil {
		return vaultstore.Secret{}, err
	}
	err = o.root.With(func(key []byte) error {
		id := o.store.Identity()
		value.Copy = vaultstore.KeyCopy{Key: value.DEK, Holder: id.Root, Issuer: id.Root}
		wrapped, err := vault.Seal(key, copyBinding(id, value), dek)
		if err != nil {
			return err
		}
		value.Copy.Envelope = wrapped
		value.Copy.Signature, err = recordMAC(key, id, value)
		return err
	})
	if err != nil {
		return vaultstore.Secret{}, err
	}
	return value, nil
}

// WithSecret lends plaintext only for a synchronous callback and wipes it even
// when the callback fails or panics. Callbacks must not reenter Owner, retain the
// slice or convert it to a string. Minimum revision comes from the resolver's
// authenticated checkpoint; zero provides authenticity but no rollback floor.
func (o *Owner) WithSecret(ctx context.Context, ref vaultstore.SecretRef, minimum uint64, use func([]byte) error) error {
	if ref.OwnerKind == "local-state" {
		return vault.ErrPolicy
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return vaultstore.ErrClosed
	}
	return o.withSecret(ctx, ref, minimum, false, use)
}

func (o *Owner) withSecret(ctx context.Context, ref vaultstore.SecretRef, minimum uint64, exact bool, use func([]byte) error) error {
	if use == nil || !ref.Valid() {
		return vault.ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	value, err := o.store.ReadSecret(ctx, ref)
	if err != nil {
		return err
	}
	if value.Ref != ref {
		return vault.ErrAuthentication
	}
	if value.RowVersion < minimum {
		return vault.ErrRollback
	}
	if exact && value.RowVersion != minimum {
		return vault.ErrAuthentication
	}
	return o.root.With(func(key []byte) error {
		id := o.store.Identity()
		if err := verifyRecord(key, id, value); err != nil {
			return err
		}
		dek, err := vault.Open(key, copyBinding(id, value), value.Copy.Envelope)
		if err != nil {
			return err
		}
		defer vault.Wipe(dek)
		plaintext, err := vault.Open(dek, valueBinding(id, value), value.Envelope)
		if err != nil {
			return err
		}
		defer vault.Wipe(plaintext)
		if err := ctx.Err(); err != nil {
			return err
		}
		return use(plaintext)
	})
}
