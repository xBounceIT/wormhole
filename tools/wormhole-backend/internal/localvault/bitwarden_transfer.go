package localvault

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const maxBitwardenTransfers = 4
const maxBitwardenTransferRetained = 64 * 1024 * 1024
const bitwardenTransferLifetime = 2 * time.Minute
const maxBitwardenTransferCiphertext = vault.MaxBrowserTransferFrame + 5*(32+16)

type BitwardenTransferRequest struct {
	WorkspaceID, ProfileID, RequestID string
	Epoch                             uint64
	Action, SourceRevision            string
	RestorePublicKey                  []byte
}
type bitwardenTransferKey interface {
	With(func([]byte) error) error
	Close() error
}
type bitwardenTransferStage struct {
	context        vault.BrowserTransferContext
	key            bitwardenTransferKey
	expires        time.Time
	timer          *time.Timer
	input          []vault.SealedBundle
	inputManifest  *vault.BrowserTransferManifest
	output         []vault.SealedBundle
	outputManifest *vault.BrowserTransferManifest
	nextOutput     int
	retired        bool
}

func cloneBrowserTransferContext(c vault.BrowserTransferContext) vault.BrowserTransferContext {
	c.CapturePublicKey = bytes.Clone(c.CapturePublicKey)
	c.RestorePublicKey = bytes.Clone(c.RestorePublicKey)
	return c
}
func sameBrowserTransferContext(a, b vault.BrowserTransferContext) bool {
	return a.WorkspaceID == b.WorkspaceID && a.FileID == b.FileID && a.ProfileID == b.ProfileID && a.RequestID == b.RequestID && a.TransferID == b.TransferID && a.Epoch == b.Epoch && a.PolicySequence == b.PolicySequence && a.Action == b.Action && a.SourceRevision == b.SourceRevision && bytes.Equal(a.CapturePublicKey, b.CapturePublicKey) && bytes.Equal(a.RestorePublicKey, b.RestorePublicKey)
}
func wipeBrowserBundles(values []vault.SealedBundle) {
	for _, value := range values {
		vault.Wipe(value.Enc)
		vault.Wipe(value.Ciphertext)
	}
}
func browserBundlesBytes(values []vault.SealedBundle) int {
	sum := 0
	for _, v := range values {
		sum += len(v.Enc) + len(v.Ciphertext)
	}
	return sum
}
func (o *Owner) bitwardenTransferBytes() int {
	sum := 0
	for _, s := range o.bitwardenTransfers {
		sum += browserBundlesBytes(s.input) + browserBundlesBytes(s.output)
	}
	return sum
}

// Caller holds o.mu. A failed key release remains reserved for close retry.
func (o *Owner) retireBitwardenTransfer(s *bitwardenTransferStage) error {
	s.retired = true
	if s.timer != nil {
		s.timer.Stop()
	}
	wipeBrowserBundles(s.input)
	wipeBrowserBundles(s.output)
	s.input = nil
	s.output = nil
	if s.key != nil {
		if err := s.key.Close(); err != nil {
			o.bitwardenTransferFailure = true
			return err
		}
		s.key = nil
	}
	if o.bitwardenTransfers[s.context.TransferID] == s {
		delete(o.bitwardenTransfers, s.context.TransferID)
	}
	return nil
}
func (o *Owner) closeBitwardenTransfers() error {
	var err error
	for _, s := range o.bitwardenTransfers {
		err = errors.Join(err, o.retireBitwardenTransfer(s))
	}
	return err
}
func (o *Owner) failBitwardenTransfer(s *bitwardenTransferStage, err error) error {
	return errors.Join(err, o.retireBitwardenTransfer(s))
}
func (o *Owner) bitwardenTransferSecurity(ctx context.Context) (SecurityProfile, error) {
	if o.closed {
		return SecurityProfile{}, vaultstore.ErrClosed
	}
	security, err := o.readSecurityProfile(ctx)
	if err != nil {
		return SecurityProfile{}, err
	}
	if security.Effective != vault.Default && security.Effective != vault.Standard {
		return SecurityProfile{}, vault.ErrPolicy
	}
	return security, nil
}
func (o *Owner) findBitwardenTransfer(c vault.BrowserTransferContext) (*bitwardenTransferStage, error) {
	s := o.bitwardenTransfers[c.TransferID]
	if c.Validate() != nil || s == nil || !sameBrowserTransferContext(s.context, c) {
		return nil, vault.ErrAuthentication
	}
	return s, nil
}
func (o *Owner) currentBitwardenTransfer(ctx context.Context, c vault.BrowserTransferContext) (*bitwardenTransferStage, error) {
	s, err := o.findBitwardenTransfer(c)
	if err != nil {
		return nil, err
	}
	if s.retired || o.bitwardenTransferFailure {
		return nil, o.failBitwardenTransfer(s, vault.ErrPolicy)
	}
	security, err := o.bitwardenTransferSecurity(ctx)
	if err == nil && (!time.Now().Before(s.expires) || strconv.FormatUint(security.Sequence, 10) != c.PolicySequence) {
		err = vault.ErrPolicy
	}
	if err != nil {
		return nil, o.failBitwardenTransfer(s, err)
	}
	return s, nil
}
func (o *Owner) BeginBitwardenTransfer(ctx context.Context, q BitwardenTransferRequest) (vault.BrowserTransferContext, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.beginBitwardenTransfer(ctx, q, bitwardenTransferLifetime)
}
func (o *Owner) beginBitwardenTransfer(ctx context.Context, q BitwardenTransferRequest, lifetime time.Duration) (vault.BrowserTransferContext, error) {
	security, err := o.bitwardenTransferSecurity(ctx)
	if err != nil {
		return vault.BrowserTransferContext{}, err
	}
	identity := o.store.Identity()
	c := vault.BrowserTransferContext{WorkspaceID: q.WorkspaceID, FileID: identity.FileID, ProfileID: q.ProfileID, RequestID: q.RequestID, TransferID: uuid.NewString(), Epoch: q.Epoch, PolicySequence: strconv.FormatUint(security.Sequence, 10), Action: q.Action, SourceRevision: q.SourceRevision, CapturePublicKey: make([]byte, 32), RestorePublicKey: bytes.Clone(q.RestorePublicKey)}
	if c.Validate() != nil || c.WorkspaceID != identity.WorkspaceID || lifetime <= 0 || lifetime > bitwardenTransferLifetime {
		return vault.BrowserTransferContext{}, vault.ErrFormat
	}
	if o.bitwardenTransferFailure || len(o.bitwardenTransfers) >= maxBitwardenTransfers {
		return vault.BrowserTransferContext{}, vault.ErrPolicy
	}
	for _, s := range o.bitwardenTransfers {
		if s.context.ProfileID == c.ProfileID {
			return vault.BrowserTransferContext{}, vaultstore.ErrConflict
		}
	}
	key, err := securemem.New(32, o.root.Locked())
	if err != nil {
		return vault.BrowserTransferContext{}, err
	}
	stage := &bitwardenTransferStage{context: c, key: key, expires: time.Now().Add(lifetime)}
	if o.bitwardenTransfers == nil {
		o.bitwardenTransfers = make(map[string]*bitwardenTransferStage)
	}
	o.bitwardenTransfers[c.TransferID] = stage
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
		stage.context.CapturePublicKey = private.PublicKey().Bytes()
		return nil
	})
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		return vault.BrowserTransferContext{}, o.failBitwardenTransfer(stage, err)
	}
	stage.timer = time.AfterFunc(time.Until(stage.expires), func() {
		o.mu.Lock()
		defer o.mu.Unlock()
		if o.bitwardenTransfers[stage.context.TransferID] == stage {
			_ = o.retireBitwardenTransfer(stage)
		}
	})
	return cloneBrowserTransferContext(stage.context), nil
}
func (o *Owner) PushBitwardenTransfer(ctx context.Context, packet vault.BrowserTransferPacket) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	s, err := o.currentBitwardenTransfer(ctx, packet.Context)
	if err != nil {
		return err
	}
	if s.outputManifest != nil || packet.Direction != "capture" || packet.Index != len(s.input) || vault.ValidateBrowserTransferPacket(packet) != nil || (s.inputManifest != nil && *s.inputManifest != packet.Manifest) {
		return o.failBitwardenTransfer(s, vault.ErrFormat)
	}
	if o.bitwardenTransferBytes()+len(packet.Bundle.Enc)+len(packet.Bundle.Ciphertext) > maxBitwardenTransferRetained {
		return o.failBitwardenTransfer(s, vault.ErrPolicy)
	}
	sealed := packet.Bundle
	sealed.Enc = bytes.Clone(sealed.Enc)
	sealed.Ciphertext = bytes.Clone(sealed.Ciphertext)
	if err := ctx.Err(); err != nil {
		wipeBrowserBundles([]vault.SealedBundle{sealed})
		return o.failBitwardenTransfer(s, err)
	}
	if s.inputManifest == nil {
		m := packet.Manifest
		s.inputManifest = &m
	}
	s.input = append(s.input, sealed)
	return nil
}
func (o *Owner) CommitBitwardenTransfer(ctx context.Context, c vault.BrowserTransferContext) (vault.BrowserTransferManifest, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	s, err := o.currentBitwardenTransfer(ctx, c)
	if err != nil {
		return vault.BrowserTransferManifest{}, err
	}
	fail := func(err error) (vault.BrowserTransferManifest, error) {
		return vault.BrowserTransferManifest{}, o.failBitwardenTransfer(s, err)
	}
	if s.inputManifest == nil || s.outputManifest != nil {
		return fail(vault.ErrFormat)
	}
	count, err := vault.BrowserTransferChunkCount(*s.inputManifest)
	if err != nil || count != len(s.input) {
		return fail(vault.ErrFormat)
	}
	// Reserve worst-case output before the state API may commit shared changes.
	if o.bitwardenTransferBytes()-browserBundlesBytes(s.input)+maxBitwardenTransferCiphertext > maxBitwardenTransferRetained {
		return fail(vault.ErrPolicy)
	}
	raw := make([]byte, s.inputManifest.Bytes)
	defer vault.Wipe(raw)
	err = s.key.With(func(private []byte) error {
		offset := 0
		for i, sealed := range s.input {
			chunk, err := vault.OpenBrowserTransferChunk(private, c, "capture", *s.inputManifest, i, sealed)
			if err != nil {
				return err
			}
			copy(raw[offset:], chunk)
			offset += len(chunk)
			vault.Wipe(chunk)
		}
		return nil
	})
	if err != nil {
		return fail(err)
	}
	if err = s.key.Close(); err != nil {
		o.bitwardenTransferFailure = true
		return fail(err)
	}
	s.key = nil
	wipeBrowserBundles(s.input)
	s.input = nil
	payload, err := vault.DecodeBrowserTransferFrame(raw)
	if err != nil {
		return fail(err)
	}
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	if !time.Now().Before(s.expires) {
		return fail(vault.ErrPolicy)
	}
	var manifest vault.BrowserTransferManifest
	seal := func(snapshot BitwardenBrowserSnapshot) error {
		frame, err := vault.EncodeBrowserTransferFrame(snapshot.LocalJSON, snapshot.SessionJSON)
		if err != nil {
			return err
		}
		defer vault.Wipe(frame)
		manifest = vault.BrowserTransferManifest{Bytes: len(frame), Revision: strconv.FormatUint(snapshot.Revision, 10), Restore: snapshot.Restore}
		chunks, err := vault.BrowserTransferChunkCount(manifest)
		if err != nil {
			return err
		}
		for i := 0; i < chunks; i++ {
			size, _ := vault.BrowserTransferChunkSize(manifest, i)
			start := i * vault.MaxSecretBytes
			sealed, err := vault.SealBrowserTransferChunk(c, "restore", manifest, i, frame[start:start+size])
			if err != nil {
				return err
			}
			s.output = append(s.output, sealed)
		}
		return nil
	}
	if c.Action == "hydrate" {
		err = o.readBitwardenBrowserState(ctx, c.ProfileID, payload.LocalJSON, payload.SessionJSON, seal)
	} else {
		revision, _ := strconv.ParseUint(c.SourceRevision, 10, 64)
		err = o.captureBitwardenBrowserState(ctx, c.ProfileID, revision, payload.LocalJSON, payload.SessionJSON, seal)
	}
	if err != nil {
		return fail(err)
	}
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	if !time.Now().Before(s.expires) {
		return fail(vault.ErrPolicy)
	}
	s.inputManifest = nil
	s.outputManifest = &manifest
	return manifest, nil
}

// Take moves one ciphertext packet to the native caller, which owns its buffers.
// The caller marshals it before clearing it; no plaintext crosses this API.
func (o *Owner) TakeBitwardenTransfer(ctx context.Context, c vault.BrowserTransferContext, index int) (vault.BrowserTransferPacket, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	s, err := o.currentBitwardenTransfer(ctx, c)
	if err != nil {
		return vault.BrowserTransferPacket{}, err
	}
	if s.outputManifest == nil || index != s.nextOutput || index < 0 || index >= len(s.output) {
		return vault.BrowserTransferPacket{}, o.failBitwardenTransfer(s, vault.ErrFormat)
	}
	packet := vault.BrowserTransferPacket{Context: cloneBrowserTransferContext(c), Direction: "restore", Manifest: *s.outputManifest, Index: index, Bundle: s.output[index]}
	s.output[index] = vault.SealedBundle{}
	s.nextOutput++
	if s.nextOutput == len(s.output) {
		if err := o.retireBitwardenTransfer(s); err != nil {
			wipeBrowserBundles([]vault.SealedBundle{packet.Bundle})
			return vault.BrowserTransferPacket{}, err
		}
	}
	return packet, nil
}

// Cleanup is permitted even after expiry or policy change. Wrong contexts cannot
// retire another owner's transfer; an already retired identity is idempotent.
func (o *Owner) CancelBitwardenTransfer(c vault.BrowserTransferContext) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if c.Validate() != nil {
		return vault.ErrFormat
	}
	if o.bitwardenTransfers[c.TransferID] == nil {
		return nil
	}
	s, err := o.findBitwardenTransfer(c)
	if err != nil {
		return err
	}
	return o.retireBitwardenTransfer(s)
}
