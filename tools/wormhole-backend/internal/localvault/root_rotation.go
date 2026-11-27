package localvault

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"sync"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// RootRotationStage retains the source owner's mutex until Close. The native
// controller must defer Close before using any other owner API, including Close.
// This freezes writes between snapshot verification and publication; no renderer
// receives a stage, key, callback or authority to publish its path.
type RootRotationStage struct {
	mu                   sync.Mutex
	owner                *Owner
	target               *vaultstore.RootRotationTarget
	ctx                  context.Context
	source               vault.SlotFile
	next                 vault.SlotFile
	policy               vault.LocalPolicy
	counts               vaultstore.RootRotationCounts
	closed               bool
	closeErr             error
	sourceDatabaseClosed bool
}

func (*RootRotationStage) MarshalJSON() ([]byte, error) { return nil, vault.ErrPolicy }

// StageRootRotation consumes and wipes nextKey on every return. A native caller
// must first confirm the new password/recovery slots and quiesce protocol/browser
// resources. Staging alone neither retires OS custody nor publishes protection.
func (o *Owner) StageRootRotation(ctx context.Context, path string, current vault.SlotFile, slots []vault.Slot, nextKey []byte) (*RootRotationStage, error) {
	return o.stageRootRotation(ctx, path, current, slots, nextKey, RootRotationPreparation{})
}

// StageEncryptedRootRotation also upgrades a protected plaintext SQLite source.
func (o *Owner) StageEncryptedRootRotation(ctx context.Context, path string, current vault.SlotFile, slots []vault.Slot, nextKey []byte) (*RootRotationStage, error) {
	return o.stageRootRotation(ctx, path, current, slots, nextKey, RootRotationPreparation{Encrypt: true})
}

type RootRotationPreparation struct {
	Encrypt bool
	Pending *vault.SlotFile
	Record  func(vault.SlotFile, vault.Envelope) error
}

// StageRootRotationWithIntent records the authenticated next slot document
// before opening the encrypted destination. The callback must not reenter Owner.
func (o *Owner) StageRootRotationWithIntent(ctx context.Context, path string, current vault.SlotFile, slots []vault.Slot, nextKey []byte, prep RootRotationPreparation) (*RootRotationStage, error) {
	return o.stageRootRotation(ctx, path, current, slots, nextKey, prep)
}

func (o *Owner) stageRootRotation(ctx context.Context, path string, current vault.SlotFile, slots []vault.Slot, nextKey []byte, prep RootRotationPreparation) (_ *RootRotationStage, resultErr error) {
	defer vault.Wipe(nextKey)
	o.mu.Lock()
	retained := false
	defer func() {
		if !retained {
			o.mu.Unlock()
		}
	}()
	if o.closed {
		return nil, vaultstore.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sourceRaw, err := json.Marshal(current)
	if err != nil {
		return nil, vault.ErrFormat
	}
	current, err = vault.DecodeSlotFile(sourceRaw)
	if err != nil {
		return nil, err
	}
	if len(nextKey) != 32 || current.Initializing || current.Encrypted != o.encrypted || current.Migration != nil || current.Rotation != nil || current.Sequence > math.MaxUint64-vault.RootRotationSequenceSpan || current.FileEpoch == math.MaxUint64 || current.RootKeyVersion == math.MaxUint32 {
		return nil, vault.ErrFormat
	}
	if o.bitwardenTransferFailure || o.vpnSSOTransferFailure || o.bitwarden != nil || len(o.bitwardenTransfers) != 0 || len(o.vpnSSOTransfers) != 0 || len(o.vpnSSOProfiles) != 0 || len(o.tunnelImports) != 0 || len(o.quickTargets) != 0 {
		return nil, vault.ErrPolicy
	}
	i := o.store.Identity()
	if current.RootKeyID != i.Root.ID || current.RootKeyVersion != i.Root.Version {
		return nil, vault.ErrAuthentication
	}
	err = o.root.With(func(key []byte) error {
		if hmac.Equal(key, nextKey) {
			return vault.ErrPolicy
		}
		return vault.VerifySlotFile(key, current, i.WorkspaceID, i.FileID, o.slotFloor)
	})
	if err != nil {
		return nil, err
	}
	if err := o.importRootRotationFloors(current); err != nil {
		return nil, err
	}
	if prep.Pending != nil {
		pending := *prep.Pending
		if !pending.Encrypted || pending.RootKeyID != i.Root.ID || pending.RootKeyVersion != i.Root.Version+1 ||
			pending.Sequence != current.Sequence+vault.RootRotationSequenceSpan || pending.FileEpoch != current.FileEpoch+1 ||
			pending.Initializing || pending.Rotation != nil || pending.Migration != nil {
			return nil, vault.ErrAuthentication
		}
		if err := vault.VerifySlotFile(nextKey, pending, i.WorkspaceID, i.FileID, pending.Sequence); err != nil {
			return nil, err
		}
		if err := o.importRootRotationRecordFloors(pending); err != nil {
			return nil, err
		}
	}
	if _, err := o.readCatalog(ctx, 8*1024*1024); err != nil {
		return nil, err
	}
	policy, _, err := o.readLocalPolicy(ctx)
	if err != nil {
		return nil, err
	}
	next, err := o.rootRotationSlots(current, slots, prep.Encrypt)
	if err != nil {
		return nil, err
	}
	if _, err := o.checkSecurityProfile(ctx, policy, next); err != nil {
		return nil, err
	}
	if err := o.checkRootRotationFloors(ctx, next); err != nil {
		return nil, err
	}
	// Floor checks can authenticate a newer stored row. Capture those facts before
	// cloning, and validate/detach every proposed slot before writing any stage.
	next, err = o.rootRotationSlots(current, slots, prep.Encrypt)
	if err != nil {
		return nil, err
	}
	raw, err := vault.EncodeSlotFile(nextKey, next)
	if err != nil {
		return nil, err
	}
	next, err = vault.DecodeSlotFile(raw)
	if err != nil {
		return nil, err
	}
	store, ok := o.store.(vaultstore.RootRotationStore)
	if !ok {
		return nil, vaultstore.ErrStorage
	}
	var target *vaultstore.RootRotationTarget
	if next.Encrypted {
		if prep.Record != nil {
			_, recovery, err := o.sealRootRotationSource(current, next, nextKey)
			if err != nil {
				return nil, err
			}
			if err := prep.Record(next, recovery); err != nil {
				return nil, err
			}
		}
		if prep.Pending != nil {
			if err := store.SettleRootRotationSource(ctx); err != nil {
				return nil, err
			}
		}
		pageKey, err := vault.DeriveKey(nextKey, []byte(i.WorkspaceID), vault.PurposeSQLite)
		if err != nil {
			return nil, err
		}
		target, err = store.BeginEncryptedRootRotation(ctx, path, pageKey)
		if err != nil {
			return nil, err
		}
	} else {
		target, err = store.BeginRootRotation(ctx, path)
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		if !retained {
			resultErr = errors.Join(resultErr, target.Close())
		}
	}()
	nextIdentity := i
	nextIdentity.Root.Version++
	var counts vaultstore.RootRotationCounts
	err = o.root.With(func(oldKey []byte) error {
		var err error
		counts, err = target.Rotate(ctx, nextIdentity, o.rootRotationTransforms(ctx, i, nextIdentity, oldKey, nextKey, true))
		if err != nil {
			return err
		}
		verified, err := target.Audit(ctx, o.rootRotationTransforms(ctx, nextIdentity, nextIdentity, nextKey, nextKey, false))
		if err != nil {
			return err
		}
		if verified != counts {
			return vault.ErrAuthentication
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if _, err := o.checkSecurityProfile(ctx, policy, next); err != nil {
		return nil, err
	}
	raw, err = vault.EncodeSlotFile(nextKey, next)
	if err != nil {
		return nil, err
	}
	next, err = vault.DecodeSlotFile(raw)
	if err != nil {
		return nil, err
	}
	retained = true
	return &RootRotationStage{owner: o, target: target, ctx: ctx, source: current, next: next, policy: policy, counts: counts}, nil
}

// The slot document was authenticated with the live root. Preserve all of its
// observations before any later policy, source, cancellation or transform denial.
func (o *Owner) importRootRotationFloors(doc vault.SlotFile) error {
	o.slotFloor = max(o.slotFloor, doc.Sequence)
	return o.importRootRotationRecordFloors(doc)
}

func (o *Owner) importRootRotationRecordFloors(doc vault.SlotFile) error {
	o.profileFloor = max(o.profileFloor, doc.ProfileSequence)
	if o.nodeFloors == nil {
		o.nodeFloors = make(map[string]uint64)
	}
	if o.tunnelFloors == nil {
		o.tunnelFloors = make(map[string]uint64)
	}
	for _, mark := range doc.Nodes {
		o.nodeFloors[mark.NodeID] = max(o.nodeFloors[mark.NodeID], mark.Revision)
	}
	for _, mark := range doc.Tunnels {
		o.tunnelFloors[mark.TunnelID] = max(o.tunnelFloors[mark.TunnelID], mark.Revision)
	}
	var result error
	for _, mark := range doc.VPNSSO {
		_, err := o.importVPNSSOFloor(mark.ScopeID, vpnSSOFloorFromMark(mark))
		result = errors.Join(result, err)
	}
	return result
}

func (o *Owner) rootRotationSlots(current vault.SlotFile, slots []vault.Slot, encrypt bool) (vault.SlotFile, error) {
	next := current
	next.FormatVersion = vault.SlotFileFormatVersion
	next.RootKeyVersion++
	next.Sequence += vault.RootRotationSequenceSpan
	next.FileEpoch++
	next.Encrypted = current.Encrypted || encrypt
	next.ProfileSequence = max(current.ProfileSequence, o.profileFloor)
	next.Slots = slots
	password, recovery := false, false
	for _, slot := range slots {
		if slot.WrappedKey.KeyVersion != next.RootKeyVersion {
			return vault.SlotFile{}, vault.ErrFormat
		}
		switch slot.Kind {
		case vault.SlotPassword:
			password = true
		case vault.SlotRecovery:
			recovery = true
		default:
			return vault.SlotFile{}, vault.ErrPolicy
		}
	}
	if !password || !recovery {
		return vault.SlotFile{}, vault.ErrPolicy
	}
	nodes, tunnels := map[string]uint64{}, map[string]uint64{}
	for id, revision := range o.nodeFloors {
		nodes[id] = revision
	}
	for id, revision := range o.vpnSSONodeFloors {
		nodes[id] = max(nodes[id], revision)
	}
	for _, mark := range current.Nodes {
		nodes[mark.NodeID] = max(nodes[mark.NodeID], mark.Revision)
	}
	for id, revision := range o.tunnelFloors {
		tunnels[id] = revision
	}
	for _, mark := range current.Tunnels {
		tunnels[mark.TunnelID] = max(tunnels[mark.TunnelID], mark.Revision)
	}
	next.Nodes, next.Tunnels = nil, nil
	for id, revision := range nodes {
		next.Nodes = append(next.Nodes, vault.NodeHighWater{NodeID: id, Revision: revision})
	}
	for id, revision := range tunnels {
		next.Tunnels = append(next.Tunnels, vault.TunnelHighWater{TunnelID: id, Revision: revision})
	}
	sort.Slice(next.Nodes, func(i, j int) bool { return next.Nodes[i].NodeID < next.Nodes[j].NodeID })
	sort.Slice(next.Tunnels, func(i, j int) bool { return next.Tunnels[i].TunnelID < next.Tunnels[j].TunnelID })
	next.VPNSSO = nil
	for scope, floor := range o.vpnSSOFloors {
		if floor.RowVersion != 0 {
			next.VPNSSO = append(next.VPNSSO, vault.VPNSSOHighWater{ScopeID: scope, RowVersion: floor.RowVersion, Revision: floor.Checkpoint.Revision, Deleted: floor.Checkpoint.Deleted, Digest: bytes.Clone(floor.Checkpoint.Digest[:])})
		}
	}
	sort.Slice(next.VPNSSO, func(i, j int) bool { return next.VPNSSO[i].ScopeID < next.VPNSSO[j].ScopeID })
	return next, nil
}

func (o *Owner) checkRootRotationFloors(ctx context.Context, doc vault.SlotFile) error {
	nodes, no := o.store.(vaultstore.NodeStore)
	tunnels, to := o.store.(vaultstore.TunnelStore)
	states, so := o.store.(vaultstore.LocalStateStore)
	if !no || !to || !so {
		return vaultstore.ErrStorage
	}
	for _, mark := range doc.Nodes {
		n, err := nodes.ReadNode(ctx, mark.NodeID)
		if errors.Is(err, vaultstore.ErrMissing) || (err == nil && n.RowVersion < mark.Revision) {
			return vault.ErrRollback
		}
		if err != nil {
			return err
		}
		if err := o.verifyNode(n); err != nil {
			return err
		}
	}
	for _, mark := range doc.Tunnels {
		v, err := tunnels.ReadTunnel(ctx, mark.TunnelID)
		if errors.Is(err, vaultstore.ErrMissing) || (err == nil && v.RowVersion < mark.Revision) {
			return vault.ErrRollback
		}
		if err != nil {
			return err
		}
		if err := o.verifyTunnel(v); err != nil {
			return err
		}
	}
	for _, mark := range doc.VPNSSO {
		v, err := states.ReadLocalState(ctx, "vpn-sso", mark.ScopeID)
		if errors.Is(err, vaultstore.ErrMissing) || (err == nil && v.RowVersion < mark.RowVersion) {
			return vault.ErrRollback
		}
		if err != nil {
			return err
		}
		if err := o.verifyLocalState(v); err != nil {
			return err
		}
		floor := o.vpnSSOFloors[mark.ScopeID]
		floor.RowVersion = max(floor.RowVersion, v.RowVersion)
		o.vpnSSOFloors[mark.ScopeID] = floor
		if v.Deleted {
			if floor.Checkpoint.Revision == v.RowVersion && !floor.Checkpoint.Deleted {
				return vault.ErrRollback
			}
			continue
		}
		if err := o.withLocalStateChunks(ctx, v, func(raw []byte) error {
			if len(raw) <= vpnSSOHeaderBytes || string(raw[:4]) != "VSS1" || binary.BigEndian.Uint64(raw[36:44]) != v.RowVersion || uint64(binary.BigEndian.Uint32(raw[44:48])) != uint64(len(raw)-vpnSSOHeaderBytes) {
				return vault.ErrAuthentication
			}
			var digest [32]byte
			copy(digest[:], raw[4:36])
			if vpnSSOScope(digest) != v.ScopeID {
				return vault.ErrAuthentication
			}
			return o.observeVPNSSO(v.ScopeID, VPNSSOCheckpoint{Revision: v.RowVersion, Digest: sha256.Sum256(raw)})
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *RootRotationStage) Document() (vault.SlotFile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return vault.SlotFile{}, vaultstore.ErrClosed
	}
	raw, err := json.Marshal(s.next)
	if err != nil {
		return vault.SlotFile{}, vault.ErrFormat
	}
	return vault.DecodeSlotFile(raw)
}

func (s *RootRotationStage) Inventory() (vaultstore.RootRotationCounts, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return vaultstore.RootRotationCounts{}, vaultstore.ErrClosed
	}
	return s.counts, nil
}

// SealSourceRecovery allows the native journal to resume from the new factors
// even if OS custody becomes unavailable. The old root never leaves native Go
// as plaintext. The binding covers both complete authenticated slot documents.
func (s *RootRotationStage) SealSourceRecovery(nextKey []byte) (vault.Binding, vault.Envelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return vault.Binding{}, vault.Envelope{}, vaultstore.ErrClosed
	}
	if err := s.ctx.Err(); err != nil {
		return vault.Binding{}, vault.Envelope{}, err
	}
	return s.owner.sealRootRotationSource(s.source, s.next, nextKey)
}

func (o *Owner) sealRootRotationSource(source, next vault.SlotFile, nextKey []byte) (vault.Binding, vault.Envelope, error) {
	if err := vault.VerifySlotFile(nextKey, next, next.VaultID, next.FileID, next.Sequence); err != nil {
		return vault.Binding{}, vault.Envelope{}, err
	}
	binding := vault.RootRotationRecoveryBinding(source, next)
	var envelope vault.Envelope
	err := o.root.With(func(key []byte) error {
		var err error
		envelope, err = vault.Seal(nextKey, binding, key)
		return err
	})
	return binding, envelope, err
}

// CloseDatabases closes both SQLite connections while retaining the source
// write lease and root. The controller can fingerprint closed durable files.
// This is irreversible for the resident owner: even an aborted stage now retires
// it in Close. Its unchanged source files remain unlockable after restart.
func (s *RootRotationStage) CloseDatabases() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return vaultstore.ErrClosed
	}
	s.sourceDatabaseClosed = true
	s.closeErr = errors.Join(s.closeErr, s.target.Close(), s.owner.store.Close())
	return s.closeErr
}

// VerifyRootRotation checks every encrypted value and signed manifest in a
// resumed target, including tombstones and fields outside the visible catalog.
func (o *Owner) VerifyRootRotation(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return vaultstore.ErrClosed
	}
	store, ok := o.store.(interface {
		AuditRootRotation(context.Context, vaultstore.RootRotationTransforms) (vaultstore.RootRotationCounts, error)
	})
	if !ok {
		return vaultstore.ErrStorage
	}
	i := o.store.Identity()
	return o.root.With(func(key []byte) error {
		_, err := store.AuditRootRotation(ctx, o.rootRotationTransforms(ctx, i, i, key, key, false))
		return err
	})
}

// RetireSource is called only after the verified target and encrypted recovery
// journal are durable. It does not delete any database, slot or OS key file.
func (s *RootRotationStage) RetireSource() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return vaultstore.ErrClosed
	}
	if _, err := s.owner.checkSecurityProfile(s.ctx, s.policy, s.next); err != nil {
		return err
	}
	return s.owner.closeLocked()
}

func (s *RootRotationStage) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	s.closeErr = errors.Join(s.closeErr, s.target.Close())
	if s.sourceDatabaseClosed {
		s.closeErr = errors.Join(s.closeErr, s.owner.closeLocked())
	}
	s.owner.mu.Unlock()
	return s.closeErr
}

func (o *Owner) rootRotationTransforms(ctx context.Context, old, next vaultstore.Identity, oldKey, nextKey []byte, rotate bool) vaultstore.RootRotationTransforms {
	seal := func(previous []byte, mac []byte, err error, nextMAC func() ([]byte, error)) ([]byte, error) {
		if err != nil {
			return nil, err
		}
		if !hmac.Equal(previous, mac) {
			return nil, vault.ErrAuthentication
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nextMAC()
	}
	return vaultstore.RootRotationTransforms{
		Secret: func(value vaultstore.Secret) (vaultstore.Secret, error) {
			if err := verifyRecord(oldKey, old, value); err != nil {
				return vaultstore.Secret{}, err
			}
			dek, err := vault.Open(oldKey, copyBinding(old, value), value.Copy.Envelope)
			if err != nil {
				return vaultstore.Secret{}, err
			}
			defer vault.Wipe(dek)
			plain, err := vault.Open(dek, valueBinding(old, value), value.Envelope)
			if err != nil {
				return vaultstore.Secret{}, err
			}
			defer vault.Wipe(plain)
			if err := ctx.Err(); err != nil {
				return vaultstore.Secret{}, err
			}
			if !rotate {
				return value, nil
			}
			value.DEK.Version++
			fresh := make([]byte, 32)
			defer vault.Wipe(fresh)
			if _, err := rand.Read(fresh); err != nil {
				return vaultstore.Secret{}, err
			}
			value.Envelope, err = vault.Seal(fresh, valueBinding(next, value), plain)
			if err != nil {
				return vaultstore.Secret{}, err
			}
			value.Copy = vaultstore.KeyCopy{Key: value.DEK, Holder: next.Root, Issuer: next.Root}
			value.Copy.Envelope, err = vault.Seal(nextKey, copyBinding(next, value), fresh)
			if err != nil {
				return vaultstore.Secret{}, err
			}
			value.Copy.Signature, err = recordMAC(nextKey, next, value)
			return value, err
		},
		Credential: func(v vaultstore.Credential) ([]byte, error) {
			mac, err := credentialMAC(oldKey, old, v)
			return seal(v.Seal, mac, err, func() ([]byte, error) { return credentialMAC(nextKey, next, v) })
		},
		Tunnel: func(v vaultstore.Tunnel) ([]byte, error) {
			if v.RowVersion < o.tunnelFloors[v.ID] {
				return nil, vault.ErrRollback
			}
			mac, err := tunnelMAC(oldKey, old, v)
			return seal(v.Seal, mac, err, func() ([]byte, error) { return tunnelMAC(nextKey, next, v) })
		},
		Node: func(v vaultstore.Node) ([]byte, error) {
			if v.RowVersion < max(o.nodeFloors[v.ID], o.vpnSSONodeFloors[v.ID]) {
				return nil, vault.ErrRollback
			}
			if v.SealSignerKeyID != old.Root.ID || v.SealSignerKeyVersion != old.Root.Version {
				return nil, vault.ErrAuthentication
			}
			mac, err := nodeMAC(oldKey, old, v)
			return seal(v.Seal, mac, err, func() ([]byte, error) {
				v.SealSignerKeyID, v.SealSignerKeyVersion = next.Root.ID, next.Root.Version
				return nodeMAC(nextKey, next, v)
			})
		},
		LocalState: func(v vaultstore.LocalState) ([]byte, error) {
			if v.Kind == "vpn-sso" && v.RowVersion < o.vpnSSOFloors[v.ScopeID].RowVersion {
				return nil, vault.ErrRollback
			}
			mac, err := localStateMAC(oldKey, old, v)
			return seal(v.Seal, mac, err, func() ([]byte, error) { return localStateMAC(nextKey, next, v) })
		},
		Profile: func(raw []byte) ([]byte, error) {
			p, err := vault.DecodeLocalPolicy(raw)
			if err != nil {
				return nil, err
			}
			if err := vault.VerifyLocalPolicy(oldKey, p, old.WorkspaceID, old.FileID, old.Root.ID, old.Root.Version, o.profileFloor); err != nil {
				return nil, err
			}
			p.RootKeyID, p.RootKeyVersion = next.Root.ID, next.Root.Version
			return vault.EncodeLocalPolicy(nextKey, p)
		},
	}
}
