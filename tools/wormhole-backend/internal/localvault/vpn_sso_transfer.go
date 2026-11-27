package localvault

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"maps"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const maxVPNSSOTransfers = 4
const maxVPNSSOTransferRetained = 128 * 1024 * 1024
const vpnSSOTransferLifetime = 5 * time.Minute

// Native-only request, following fresh source resolver/Use admission. Binding
// and Minimum come from that resolver and the protected personal device anchor.
// No transport or renderer operation may accept them as unverified claims.
type VPNSSOTransferRequest struct {
	ProfileID, RequestID, SessionID, ChallengeID string
	Epoch                                        uint64
	RestorePublicKey                             []byte
	Minimum                                      VPNSSOFloor
}

type VPNSSOTransferOffer struct {
	Context  vault.VPNSSOTransferContext  `json:"context"`
	Manifest vault.VPNSSOTransferManifest `json:"manifest"`
	Floor    VPNSSOFloor                  `json:"floor"`
}

type vpnSSOTransferKey interface {
	With(func([]byte) error) error
	Close() error
}

type vpnSSOTransferStage struct {
	sourceCheck func(context.Context) error
	context     vault.VPNSSOTransferContext
	binding     VPNSSOBinding
	profile     vpnSSOProfile
	key         vpnSSOTransferKey
	expires     time.Time
	timer       *time.Timer
	input       []vault.SealedBundle
	manifest    *vault.VPNSSOTransferManifest
	output      []vault.SealedBundle
	restore     vault.VPNSSOTransferManifest
	next        int
	ready       bool
	retired     bool
}

func cloneVPNSSOTransferContext(c vault.VPNSSOTransferContext) vault.VPNSSOTransferContext {
	c.SourceDigest = bytes.Clone(c.SourceDigest)
	c.BindingDigest = bytes.Clone(c.BindingDigest)
	c.CapturePublicKey = bytes.Clone(c.CapturePublicKey)
	c.RestorePublicKey = bytes.Clone(c.RestorePublicKey)
	return c
}

func sameVPNSSOTransferContext(a, b vault.VPNSSOTransferContext) bool {
	return a.WorkspaceID == b.WorkspaceID && a.FileID == b.FileID && a.ProfileID == b.ProfileID && a.RequestID == b.RequestID && a.TransferID == b.TransferID && a.SessionID == b.SessionID && a.ChallengeID == b.ChallengeID && a.Epoch == b.Epoch && a.PolicySequence == b.PolicySequence && a.SourceRevision == b.SourceRevision && a.SourceDeleted == b.SourceDeleted && bytes.Equal(a.SourceDigest, b.SourceDigest) && bytes.Equal(a.BindingDigest, b.BindingDigest) && bytes.Equal(a.CapturePublicKey, b.CapturePublicKey) && bytes.Equal(a.RestorePublicKey, b.RestorePublicKey)
}

func sameVPNSSOTransferManifest(a, b vault.VPNSSOTransferManifest) bool {
	return a.Bytes == b.Bytes && bytes.Equal(a.Digest, b.Digest)
}

func (o *Owner) vpnSSOTransferBytes() int {
	n := 0
	for _, stage := range o.vpnSSOTransfers {
		n += browserBundlesBytes(stage.input) + browserBundlesBytes(stage.output)
	}
	return n
}

// A failed key release remains reserved for a matching cleanup/owner-close
// retry. Admission stays quarantined for this owner lifetime after uncertainty.
func (o *Owner) retireVPNSSOTransfer(s *vpnSSOTransferStage) error {
	s.retired = true
	if s.timer != nil {
		s.timer.Stop()
	}
	wipeBrowserBundles(s.input)
	wipeBrowserBundles(s.output)
	s.input, s.output = nil, nil
	if current, exists := o.vpnSSOProfiles[s.context.ProfileID]; exists && current == s.profile {
		delete(o.vpnSSOProfiles, s.context.ProfileID)
	}
	if s.key != nil {
		if err := s.key.Close(); err != nil {
			o.vpnSSOTransferFailure = true
			return err
		}
		s.key = nil
	}
	if o.vpnSSOTransfers[s.context.TransferID] == s {
		delete(o.vpnSSOTransfers, s.context.TransferID)
	}
	return nil
}

func (o *Owner) closeVPNSSOTransfers() error {
	var err error
	for _, stage := range o.vpnSSOTransfers {
		err = errors.Join(err, o.retireVPNSSOTransfer(stage))
	}
	return err
}

func (o *Owner) failVPNSSOTransfer(s *vpnSSOTransferStage, cause error) error {
	return errors.Join(cause, o.retireVPNSSOTransfer(s))
}

func (o *Owner) findVPNSSOTransfer(c vault.VPNSSOTransferContext) (*vpnSSOTransferStage, error) {
	s := o.vpnSSOTransfers[c.TransferID]
	if c.Validate() != nil || s == nil || !sameVPNSSOTransferContext(s.context, c) {
		return nil, vault.ErrAuthentication
	}
	return s, nil
}

func (o *Owner) currentVPNSSOTransfer(ctx context.Context, c vault.VPNSSOTransferContext) (*vpnSSOTransferStage, error) {
	s, err := o.findVPNSSOTransfer(c)
	if err != nil {
		return nil, err
	}
	security, err := o.vpnSSOSecurity(ctx)
	if err == nil && s.sourceCheck != nil {
		err = s.sourceCheck(ctx)
	}
	if err == nil && (s.retired || o.vpnSSOTransferFailure || !time.Now().Before(s.expires) || strconv.FormatUint(security.Sequence, 10) != c.PolicySequence || o.vpnSSOProfiles[c.ProfileID] != s.profile) {
		err = vault.ErrPolicy
	}
	if err == nil {
		floor, exists := o.vpnSSOFloors[s.profile.Scope]
		if !exists || floor.RowVersion != s.profile.Source.Revision || floor.Checkpoint != s.profile.Source {
			err = vaultstore.ErrConflict
		}
	}
	if err != nil {
		return nil, o.failVPNSSOTransfer(s, err)
	}
	return s, nil
}

func (o *Owner) BeginVPNSSOTransfer(ctx context.Context, binding VPNSSOBinding, q VPNSSOTransferRequest) (VPNSSOTransferOffer, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.beginVPNSSOTransfer(ctx, binding, q, vpnSSOTransferLifetime)
}

func (o *Owner) beginVPNSSOTransfer(ctx context.Context, binding VPNSSOBinding, q VPNSSOTransferRequest, lifetime time.Duration) (VPNSSOTransferOffer, error) {
	security, err := o.vpnSSOSecurity(ctx)
	if err != nil {
		return VPNSSOTransferOffer{}, err
	}
	digest, err := binding.digest()
	if err != nil || lifetime <= 0 || lifetime > vpnSSOTransferLifetime {
		return VPNSSOTransferOffer{}, vault.ErrFormat
	}
	i := o.store.Identity()
	c := vault.VPNSSOTransferContext{WorkspaceID: i.WorkspaceID, FileID: i.FileID, ProfileID: q.ProfileID, RequestID: q.RequestID, TransferID: uuid.NewString(), SessionID: q.SessionID, ChallengeID: q.ChallengeID, Epoch: q.Epoch, PolicySequence: strconv.FormatUint(security.Sequence, 10), SourceRevision: "0", SourceDigest: make([]byte, 32), BindingDigest: bytes.Clone(digest[:]), CapturePublicKey: make([]byte, 32), RestorePublicKey: bytes.Clone(q.RestorePublicKey)}
	if c.Validate() != nil {
		return VPNSSOTransferOffer{}, vault.ErrFormat
	}
	if o.vpnSSOTransferFailure || len(o.vpnSSOTransfers) >= maxVPNSSOTransfers {
		return VPNSSOTransferOffer{}, vault.ErrPolicy
	}
	for _, stage := range o.vpnSSOTransfers {
		if stage.context.ProfileID == q.ProfileID {
			return VPNSSOTransferOffer{}, vaultstore.ErrConflict
		}
	}
	if _, err := o.importVPNSSOFloor(vpnSSOScope(digest), q.Minimum); err != nil {
		return VPNSSOTransferOffer{}, err
	}
	key, err := securemem.New(32, o.root.Locked())
	if err != nil {
		return VPNSSOTransferOffer{}, err
	}
	s := &vpnSSOTransferStage{context: c, binding: binding, key: key, expires: time.Now().Add(lifetime)}
	if o.vpnSSOTransfers == nil {
		o.vpnSSOTransfers = make(map[string]*vpnSSOTransferStage)
	}
	o.vpnSSOTransfers[c.TransferID] = s
	fail := func(err error) (VPNSSOTransferOffer, error) {
		return VPNSSOTransferOffer{}, o.failVPNSSOTransfer(s, err)
	}
	err = key.With(func(raw []byte) error {
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		private, err := ecdh.X25519().NewPrivateKey(raw)
		if err != nil {
			return err
		}
		public, err := ecdh.X25519().NewPublicKey(c.RestorePublicKey)
		if err != nil {
			return err
		}
		shared, err := private.ECDH(public)
		vault.Wipe(shared)
		if err != nil {
			return vault.ErrFormat
		}
		s.context.CapturePublicKey = private.PublicKey().Bytes()
		return nil
	})
	if err != nil {
		return fail(err)
	}
	err = o.openVPNSSO(ctx, binding, q.ProfileID, q.Minimum.Checkpoint, func(snapshot VPNSSOSnapshot) error {
		s.context.SourceRevision = strconv.FormatUint(snapshot.Checkpoint.Revision, 10)
		s.context.SourceDeleted = snapshot.Checkpoint.Deleted
		s.context.SourceDigest = bytes.Clone(snapshot.Checkpoint.Digest[:])
		count := (len(snapshot.Archive) + vault.MaxSecretBytes - 1) / vault.MaxSecretBytes
		if o.vpnSSOTransferBytes()+len(snapshot.Archive)+count*48 > maxVPNSSOTransferRetained {
			return vault.ErrPolicy
		}
		var err error
		s.restore, s.output, err = vault.SealVPNSSOTransferArchive(s.context, "restore", snapshot.Archive)
		return err
	})
	if err != nil {
		return fail(err)
	}
	s.profile = o.vpnSSOProfiles[q.ProfileID]
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	s.timer = time.AfterFunc(time.Until(s.expires), func() {
		o.mu.Lock()
		defer o.mu.Unlock()
		if o.vpnSSOTransfers[s.context.TransferID] == s {
			_ = o.retireVPNSSOTransfer(s)
		}
	})
	manifest := s.restore
	manifest.Digest = bytes.Clone(manifest.Digest)
	return VPNSSOTransferOffer{cloneVPNSSOTransferContext(s.context), manifest, o.vpnSSOFloors[vpnSSOScope(digest)]}, nil
}

func (o *Owner) TakeVPNSSOTransfer(ctx context.Context, c vault.VPNSSOTransferContext, index int) (vault.VPNSSOTransferPacket, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	s, err := o.currentVPNSSOTransfer(ctx, c)
	if err != nil {
		return vault.VPNSSOTransferPacket{}, err
	}
	if s.ready || index != s.next || index < 0 || index >= len(s.output) {
		return vault.VPNSSOTransferPacket{}, o.failVPNSSOTransfer(s, vault.ErrFormat)
	}
	bundle := s.output[index]
	copy := vault.SealedBundle{FormatVersion: bundle.FormatVersion, SuiteID: bundle.SuiteID, Enc: bytes.Clone(bundle.Enc), Ciphertext: bytes.Clone(bundle.Ciphertext)}
	if err := ctx.Err(); err != nil {
		wipeBrowserBundles([]vault.SealedBundle{copy})
		return vault.VPNSSOTransferPacket{}, o.failVPNSSOTransfer(s, err)
	}
	vault.Wipe(bundle.Enc)
	vault.Wipe(bundle.Ciphertext)
	s.output[index] = vault.SealedBundle{}
	s.next++
	m := s.restore
	m.Digest = bytes.Clone(m.Digest)
	return vault.VPNSSOTransferPacket{Context: cloneVPNSSOTransferContext(s.context), Direction: "restore", Manifest: m, Index: index, Bundle: copy}, nil
}

// Capture is admitted only after the native browser acknowledges complete
// restore of this exact offer. Receipt is not a gateway-login completion token.
func (o *Owner) AcknowledgeVPNSSOTransfer(ctx context.Context, c vault.VPNSSOTransferContext, restored vault.VPNSSOTransferManifest) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	s, err := o.currentVPNSSOTransfer(ctx, c)
	if err != nil {
		return err
	}
	if s.ready || s.next != len(s.output) || !sameVPNSSOTransferManifest(restored, s.restore) {
		return o.failVPNSSOTransfer(s, vault.ErrFormat)
	}
	wipeBrowserBundles(s.output)
	s.output = nil
	s.ready = true
	return nil
}

func (o *Owner) PushVPNSSOTransfer(ctx context.Context, packet vault.VPNSSOTransferPacket) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	s, err := o.currentVPNSSOTransfer(ctx, packet.Context)
	if err != nil {
		return err
	}
	if !s.ready || packet.Direction != "capture" || packet.Index != len(s.input) || vault.ValidateVPNSSOTransferPacket(packet) != nil || (s.manifest != nil && !sameVPNSSOTransferManifest(*s.manifest, packet.Manifest)) {
		return o.failVPNSSOTransfer(s, vault.ErrFormat)
	}
	if o.vpnSSOTransferBytes()+len(packet.Bundle.Enc)+len(packet.Bundle.Ciphertext) > maxVPNSSOTransferRetained {
		return o.failVPNSSOTransfer(s, vault.ErrPolicy)
	}
	bundle := packet.Bundle
	bundle.Enc = bytes.Clone(bundle.Enc)
	bundle.Ciphertext = bytes.Clone(bundle.Ciphertext)
	if err := ctx.Err(); err != nil {
		wipeBrowserBundles([]vault.SealedBundle{bundle})
		return o.failVPNSSOTransfer(s, err)
	}
	if s.manifest == nil {
		manifest := packet.Manifest
		manifest.Digest = bytes.Clone(manifest.Digest)
		s.manifest = &manifest
	}
	s.input = append(s.input, bundle)
	return nil
}

func (o *Owner) CommitVPNSSOTransfer(ctx context.Context, c vault.VPNSSOTransferContext) (VPNSSOCheckpoint, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	s, err := o.currentVPNSSOTransfer(ctx, c)
	if err != nil {
		return VPNSSOCheckpoint{}, err
	}
	fail := func(err error) (VPNSSOCheckpoint, error) { return VPNSSOCheckpoint{}, o.failVPNSSOTransfer(s, err) }
	if !s.ready || s.manifest == nil {
		return fail(vault.ErrFormat)
	}
	var raw []byte
	err = s.key.With(func(private []byte) error {
		var err error
		raw, err = vault.OpenVPNSSOTransferArchive(private, c, "capture", *s.manifest, s.input)
		return err
	})
	defer vault.Wipe(raw)
	if err != nil {
		return fail(err)
	}
	if err := s.key.Close(); err != nil {
		return fail(err)
	}
	s.key = nil
	checkpoint, err := o.saveVPNSSO(ctx, s.binding, c.ProfileID, raw)
	if err != nil {
		return fail(err)
	}
	if err := o.retireVPNSSOTransfer(s); err != nil {
		return VPNSSOCheckpoint{}, err
	}
	return checkpoint, nil
}

func (o *Owner) CancelVPNSSOTransfer(c vault.VPNSSOTransferContext) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	// A successful commit, expiry or failed action may already have released the
	// stage before native cancellation arrives. Confirm absence for this owner;
	// an existing stage still requires its exact context, including key identity.
	i := o.store.Identity()
	if c.Validate() != nil || c.WorkspaceID != i.WorkspaceID || c.FileID != i.FileID {
		return vault.ErrAuthentication
	}
	if o.vpnSSOTransfers[c.TransferID] == nil {
		return nil
	}
	s, err := o.findVPNSSOTransfer(c)
	if err != nil {
		return err
	}
	return o.retireVPNSSOTransfer(s)
}

// CaptureVPNSSOReceiptSource retains only the native source revalidator for a
// synchronous commit response. Commit retires its transfer before the handler
// publishes checkpoints, so the ordinary receipt floor check cannot recheck that
// source afterward. The returned callback releases no archive or key material.
func (o *Owner) CaptureVPNSSOReceiptSource(ctx context.Context, c vault.VPNSSOTransferContext) (func(context.Context) error, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if ctx == nil {
		return nil, vault.ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if o.closed {
		return nil, vaultstore.ErrClosed
	}
	s, err := o.findVPNSSOTransfer(c)
	if err != nil {
		return nil, err
	}
	check := s.sourceCheck
	return func(ctx context.Context) error {
		o.mu.Lock()
		defer o.mu.Unlock()
		if ctx == nil {
			return vault.ErrFormat
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if o.closed {
			return vaultstore.ErrClosed
		}
		// A successful final check must not introduce unpublished observations.
		// A changed fact suppresses the receipt; the native caller checkpoints
		// those facts on failure before responding, without retrying admission.
		nodes, tunnels := maps.Clone(o.vpnSSONodeFloors), maps.Clone(o.tunnelFloors)
		if check != nil {
			if err := check(ctx); err != nil {
				return err
			}
		}
		if !maps.Equal(nodes, o.vpnSSONodeFloors) || !maps.Equal(tunnels, o.tunnelFloors) {
			return vault.ErrRollback
		}
		return nil
	}, nil
}

// Final native response gate after importing/persisting device checkpoints.
// Checkpoints discovered during persistence must not authorize an older prepared
// restore response or commit receipt. This releases no data and grants no Use.
func (o *Owner) ValidateVPNSSOReceipt(ctx context.Context, c vault.VPNSSOTransferContext, committed *VPNSSOCheckpoint) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if committed == nil {
		_, err := o.currentVPNSSOTransfer(ctx, c)
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if o.closed {
		return vaultstore.ErrClosed
	}
	if _, err := o.vpnSSOSecurity(ctx); err != nil {
		return err
	}
	i := o.store.Identity()
	if c.Validate() != nil || c.WorkspaceID != i.WorkspaceID || c.FileID != i.FileID || !committed.valid() {
		return vault.ErrAuthentication
	}
	var digest [32]byte
	copy(digest[:], c.BindingDigest)
	floor, exists := o.vpnSSOFloors[vpnSSOScope(digest)]
	if !exists || floor.RowVersion != committed.Revision || floor.Checkpoint != *committed {
		return vault.ErrRollback
	}
	return nil
}
