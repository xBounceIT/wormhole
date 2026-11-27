package localvault

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func vpnTransferRequest(t *testing.T) (VPNSSOTransferRequest, []byte) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return VPNSSOTransferRequest{ProfileID: uuid.NewString(), RequestID: uuid.NewString(), SessionID: uuid.NewString(), ChallengeID: uuid.NewString(), Epoch: 7, RestorePublicKey: key.PublicKey().Bytes()}, key.Bytes()
}

func beginVPNTransfer(t *testing.T, o *Owner, b VPNSSOBinding) (VPNSSOTransferOffer, []byte) {
	t.Helper()
	q, private := vpnTransferRequest(t)
	offer, err := o.BeginVPNSSOTransfer(context.Background(), b, q)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vault.Wipe(private) })
	return offer, private
}

func restoreVPNTransfer(t *testing.T, o *Owner, offer VPNSSOTransferOffer, private, expected []byte) {
	t.Helper()
	ctx, c := context.Background(), offer.Context
	count, err := vault.VPNSSOTransferChunkCount(c, "restore", offer.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	var chunks []vault.SealedBundle
	defer func() { wipeBrowserBundles(chunks) }()
	for i := 0; i < count; i++ {
		packet, err := o.TakeVPNSSOTransfer(ctx, c, i)
		if err != nil || packet.Direction != "restore" || packet.Index != i || !sameVPNSSOTransferContext(packet.Context, c) {
			t.Fatal("restore packet", err)
		}
		chunks = append(chunks, packet.Bundle)
	}
	raw, err := vault.OpenVPNSSOTransferArchive(private, c, "restore", offer.Manifest, chunks)
	if err != nil || !bytes.Equal(raw, expected) {
		t.Fatal("restore changed archive", err)
	}
	vault.Wipe(raw)
	if err := o.AcknowledgeVPNSSOTransfer(ctx, c, offer.Manifest); err != nil {
		t.Fatal(err)
	}
}

func pushVPNTransfer(t *testing.T, o *Owner, c vault.VPNSSOTransferContext, raw []byte) {
	t.Helper()
	m, chunks, err := vault.SealVPNSSOTransferArchive(c, "capture", raw)
	if err != nil {
		t.Fatal(err)
	}
	defer wipeBrowserBundles(chunks)
	for i, bundle := range chunks {
		if err := o.PushVPNSSOTransfer(context.Background(), vault.VPNSSOTransferPacket{Context: c, Direction: "capture", Manifest: m, Index: i, Bundle: bundle}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVPNSSOTransferNativeCustodyRoundtripAndReplay(t *testing.T) {
	o, _, _, _ := owner(t)
	b, ctx := vpnSSOFixture(), context.Background()
	first, private := beginVPNTransfer(t, o, b)
	if first.Context.SourceRevision != "0" || first.Manifest.Bytes != 0 || first.Floor.RowVersion != 0 {
		t.Fatal("empty source")
	}
	restoreVPNTransfer(t, o, first, private, nil)
	archive := bytes.Repeat([]byte("binary\x00\xffarchive"), vault.MaxSecretBytes/15+3)
	pushVPNTransfer(t, o, first.Context, archive)
	checkpoint, err := o.CommitVPNSSOTransfer(ctx, first.Context)
	if err != nil || checkpoint.Revision != 1 || len(o.vpnSSOTransfers) != 0 || len(o.vpnSSOProfiles) != 0 {
		t.Fatal("capture commit", err)
	}
	if _, err := o.CommitVPNSSOTransfer(ctx, first.Context); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("commit replay", err)
	}
	second, private := beginVPNTransfer(t, o, b)
	if second.Context.SourceRevision != "1" || !bytes.Equal(second.Context.SourceDigest, checkpoint.Digest[:]) || second.Floor.Checkpoint != checkpoint {
		t.Fatal("source checkpoint")
	}
	restoreVPNTransfer(t, o, second, private, archive)
	pushVPNTransfer(t, o, second.Context, []byte("updated provider storage"))
	updated, err := o.CommitVPNSSOTransfer(ctx, second.Context)
	if err != nil || updated.Revision != 2 || updated.Digest == checkpoint.Digest {
		t.Fatal(err)
	}
	_, current := openVPNSSO(t, o, b, updated)
	if current != updated {
		t.Fatal("transfer not persisted")
	}
	deleted, err := o.DeleteVPNSSO(ctx, b, updated)
	if err != nil {
		t.Fatal(err)
	}
	third, private := beginVPNTransfer(t, o, b)
	if !third.Context.SourceDeleted || third.Context.SourceRevision != "3" || third.Floor.Checkpoint != deleted {
		t.Fatal("tombstone restore")
	}
	restoreVPNTransfer(t, o, third, private, nil)
	if err := o.CancelVPNSSOTransfer(third.Context); err != nil {
		t.Fatal(err)
	}
}

func TestVPNSSOTransferStrictRestoreAcknowledgementAndCaptureOrder(t *testing.T) {
	o, _, _, _ := owner(t)
	b, ctx := vpnSSOFixture(), context.Background()
	id, _ := openVPNSSO(t, o, b, VPNSSOCheckpoint{})
	saveVPNSSO(t, o, b, id, bytes.Repeat([]byte{7}, vault.MaxSecretBytes+1))
	for _, attack := range []func(VPNSSOTransferOffer) error{
		func(offer VPNSSOTransferOffer) error {
			_, err := o.TakeVPNSSOTransfer(ctx, offer.Context, 1)
			return err
		},
		func(offer VPNSSOTransferOffer) error {
			return o.AcknowledgeVPNSSOTransfer(ctx, offer.Context, offer.Manifest)
		},
		func(offer VPNSSOTransferOffer) error {
			_, err := o.CommitVPNSSOTransfer(ctx, offer.Context)
			return err
		},
		func(offer VPNSSOTransferOffer) error {
			m, chunks, _ := vault.SealVPNSSOTransferArchive(offer.Context, "capture", []byte{1})
			defer wipeBrowserBundles(chunks)
			return o.PushVPNSSOTransfer(ctx, vault.VPNSSOTransferPacket{Context: offer.Context, Direction: "capture", Manifest: m, Index: 0, Bundle: chunks[0]})
		},
	} {
		offer, _ := beginVPNTransfer(t, o, b)
		if err := attack(offer); !errors.Is(err, vault.ErrFormat) || len(o.vpnSSOTransfers) != 0 {
			t.Fatal("state order accepted", err)
		}
	}
	for _, attack := range []func(VPNSSOTransferOffer) error{
		func(offer VPNSSOTransferOffer) error {
			return o.AcknowledgeVPNSSOTransfer(ctx, offer.Context, offer.Manifest)
		},
		func(offer VPNSSOTransferOffer) error {
			_, err := o.TakeVPNSSOTransfer(ctx, offer.Context, 0)
			return err
		},
		func(offer VPNSSOTransferOffer) error {
			_, err := o.CommitVPNSSOTransfer(ctx, offer.Context)
			return err
		},
	} {
		offer, private := beginVPNTransfer(t, o, b)
		restoreVPNTransfer(t, o, offer, private, bytes.Repeat([]byte{7}, vault.MaxSecretBytes+1))
		if err := attack(offer); !errors.Is(err, vault.ErrFormat) {
			t.Fatal("second phase order accepted", err)
		}
	}
	offer, _ := beginVPNTransfer(t, o, b)
	for i := 0; i < 2; i++ {
		if _, err := o.TakeVPNSSOTransfer(ctx, offer.Context, i); err != nil {
			t.Fatal(err)
		}
	}
	bad := offer.Manifest
	bad.Digest = bytes.Repeat([]byte{2}, 32)
	if err := o.AcknowledgeVPNSSOTransfer(ctx, offer.Context, bad); !errors.Is(err, vault.ErrFormat) {
		t.Fatal("wrong archive acknowledged", err)
	}
}

func TestVPNSSOTransferForeignContextsAndMutableCallerBuffers(t *testing.T) {
	o, _, _, _ := owner(t)
	b, ctx := vpnSSOFixture(), context.Background()
	offer, private := beginVPNTransfer(t, o, b)
	actual := cloneVPNSSOTransferContext(offer.Context)
	for _, change := range []func(*vault.VPNSSOTransferContext){
		func(c *vault.VPNSSOTransferContext) { c.RequestID = uuid.NewString() },
		func(c *vault.VPNSSOTransferContext) { c.BindingDigest[0] ^= 1 },
		func(c *vault.VPNSSOTransferContext) { c.SessionID = uuid.NewString() },
		func(c *vault.VPNSSOTransferContext) { c.ChallengeID = "bad" },
		func(c *vault.VPNSSOTransferContext) { c.SourceRevision = "00" },
	} {
		foreign := cloneVPNSSOTransferContext(actual)
		change(&foreign)
		if err := o.CancelVPNSSOTransfer(foreign); err != vault.ErrAuthentication {
			t.Fatal(err)
		}
		if _, err := o.TakeVPNSSOTransfer(ctx, foreign, 0); err != vault.ErrAuthentication {
			t.Fatal(err)
		}
		if err := o.AcknowledgeVPNSSOTransfer(ctx, foreign, offer.Manifest); err != vault.ErrAuthentication {
			t.Fatal(err)
		}
		if err := o.PushVPNSSOTransfer(ctx, vault.VPNSSOTransferPacket{Context: foreign}); err != vault.ErrAuthentication {
			t.Fatal(err)
		}
		if _, err := o.CommitVPNSSOTransfer(ctx, foreign); err != vault.ErrAuthentication {
			t.Fatal(err)
		}
	}
	if len(o.vpnSSOTransfers) != 1 {
		t.Fatal("foreign context retired original")
	}
	offer.Context.BindingDigest[0] ^= 1
	offer.Context.CapturePublicKey[0] ^= 1
	offer.Context.SourceDigest[0] ^= 1
	offer.Context = actual
	restoreVPNTransfer(t, o, offer, private, nil)
	m, chunks, err := vault.SealVPNSSOTransferArchive(actual, "capture", []byte("caller-owned storage"))
	if err != nil {
		t.Fatal(err)
	}
	if err := o.PushVPNSSOTransfer(ctx, vault.VPNSSOTransferPacket{Context: actual, Direction: "capture", Manifest: m, Index: 0, Bundle: chunks[0]}); err != nil {
		t.Fatal(err)
	}
	m.Digest[0] ^= 1
	wipeBrowserBundles(chunks)
	if _, err := o.CommitVPNSSOTransfer(ctx, actual); err != nil {
		t.Fatal("caller mutation changed retained packet", err)
	}
}

func TestVPNSSOTransferCorruptionPartialInputAndConcurrentSourceChange(t *testing.T) {
	o, _, _, _ := owner(t)
	b, ctx := vpnSSOFixture(), context.Background()
	for _, change := range []func(*vault.VPNSSOTransferPacket){
		func(p *vault.VPNSSOTransferPacket) { p.Index = 1 },
		func(p *vault.VPNSSOTransferPacket) { p.Direction = "restore" },
		func(p *vault.VPNSSOTransferPacket) { p.Bundle.Ciphertext = p.Bundle.Ciphertext[:1] },
	} {
		offer, private := beginVPNTransfer(t, o, b)
		restoreVPNTransfer(t, o, offer, private, nil)
		m, chunks, _ := vault.SealVPNSSOTransferArchive(offer.Context, "capture", []byte{1})
		packet := vault.VPNSSOTransferPacket{Context: offer.Context, Direction: "capture", Manifest: m, Index: 0, Bundle: chunks[0]}
		change(&packet)
		if err := o.PushVPNSSOTransfer(ctx, packet); !errors.Is(err, vault.ErrFormat) {
			t.Fatal(err)
		}
		wipeBrowserBundles(chunks)
	}
	for _, corrupt := range []bool{false, true} {
		offer, private := beginVPNTransfer(t, o, b)
		restoreVPNTransfer(t, o, offer, private, nil)
		m, chunks, _ := vault.SealVPNSSOTransferArchive(offer.Context, "capture", bytes.Repeat([]byte{5}, vault.MaxSecretBytes+1))
		if corrupt {
			chunks[0].Ciphertext[0] ^= 1
		}
		for i, chunk := range chunks {
			if !corrupt && i > 0 {
				break
			}
			if err := o.PushVPNSSOTransfer(ctx, vault.VPNSSOTransferPacket{Context: offer.Context, Direction: "capture", Manifest: m, Index: i, Bundle: chunk}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := o.CommitVPNSSOTransfer(ctx, offer.Context); err == nil {
			t.Fatal("partial/corrupt archive committed")
		}
		wipeBrowserBundles(chunks)
	}
	first, private := beginVPNTransfer(t, o, b)
	restoreVPNTransfer(t, o, first, private, nil)
	second, private := beginVPNTransfer(t, o, b)
	restoreVPNTransfer(t, o, second, private, nil)
	pushVPNTransfer(t, o, first.Context, []byte("new login"))
	if _, err := o.CommitVPNSSOTransfer(ctx, first.Context); err != nil {
		t.Fatal(err)
	}
	m, chunks, err := vault.SealVPNSSOTransferArchive(second.Context, "capture", []byte("stale login"))
	if err != nil {
		t.Fatal(err)
	}
	defer wipeBrowserBundles(chunks)
	if err := o.PushVPNSSOTransfer(ctx, vault.VPNSSOTransferPacket{Context: second.Context, Direction: "capture", Manifest: m, Index: 0, Bundle: chunks[0]}); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatal("known newer source accepted more input", err)
	}
	if _, err := o.CommitVPNSSOTransfer(ctx, second.Context); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("retired source committed", err)
	}
}

type vpnTransferKeyProbe struct {
	inner       vpnSSOTransferKey
	fail        int
	withFailure error
	closes      int
}

func TestVPNSSOTransferCancellationConfirmsAbsenceWithoutRetiringNewProfile(t *testing.T) {
	o, _, _, _ := owner(t)
	b, ctx := vpnSSOFixture(), context.Background()
	first, _ := beginVPNTransfer(t, o, b)
	if err := o.CancelVPNSSOTransfer(first.Context); err != nil {
		t.Fatal(err)
	}
	request, private := vpnTransferRequest(t)
	defer vault.Wipe(private)
	request.ProfileID = first.Context.ProfileID
	second, err := o.BeginVPNSSOTransfer(ctx, b, request)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := o.CancelVPNSSOTransfer(first.Context); err != nil {
			t.Fatal("released transfer cancellation failed", err)
		}
	}
	if len(o.vpnSSOTransfers) != 1 || o.vpnSSOTransfers[second.Context.TransferID] == nil {
		t.Fatal("old cleanup retired a reused profile")
	}
	for _, field := range []string{"workspace", "file", "invalid"} {
		foreign := cloneVPNSSOTransferContext(first.Context)
		switch field {
		case "workspace":
			foreign.WorkspaceID = uuid.NewString()
		case "file":
			foreign.FileID = uuid.NewString()
		case "invalid":
			foreign.TransferID = "bad"
		}
		if err := o.CancelVPNSSOTransfer(foreign); err != vault.ErrAuthentication {
			t.Fatal("foreign cleanup confirmed", field, err)
		}
	}
	restoreVPNTransfer(t, o, second, private, nil)
	pushVPNTransfer(t, o, second.Context, []byte("new profile must remain usable"))
	if _, err := o.CommitVPNSSOTransfer(ctx, second.Context); err != nil {
		t.Fatal(err)
	}
	if err := o.CancelVPNSSOTransfer(second.Context); err != nil {
		t.Fatal("committed transfer cancellation failed", err)
	}
}

func (p *vpnTransferKeyProbe) With(use func([]byte) error) error {
	if p.withFailure != nil {
		return p.withFailure
	}
	return p.inner.With(use)
}
func (p *vpnTransferKeyProbe) Close() error {
	p.closes++
	if p.fail > 0 {
		p.fail--
		return vaultstore.ErrStorage
	}
	return p.inner.Close()
}

func TestVPNSSOTransferKeyCleanupQuarantineAndCloseRetry(t *testing.T) {
	o, _, _, _ := owner(t)
	b, ctx := vpnSSOFixture(), context.Background()
	offer, private := beginVPNTransfer(t, o, b)
	restoreVPNTransfer(t, o, offer, private, nil)
	pushVPNTransfer(t, o, offer.Context, []byte("must not persist"))
	s := o.vpnSSOTransfers[offer.Context.TransferID]
	key := &vpnTransferKeyProbe{inner: s.key, fail: 2}
	s.key = key
	if _, err := o.CommitVPNSSOTransfer(ctx, offer.Context); !errors.Is(err, vaultstore.ErrStorage) || !s.retired || !o.vpnSSOTransferFailure || len(s.input) != 0 {
		t.Fatal("key uncertainty not quarantined", err)
	}
	if floor, err := o.ObserveVPNSSO(ctx, b, VPNSSOFloor{}); err != nil || floor.Checkpoint.Revision != 0 {
		t.Fatal("key failure persisted archive", err)
	}
	q, _ := vpnTransferRequest(t)
	if _, err := o.BeginVPNSSOTransfer(ctx, b, q); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	if err := o.CancelVPNSSOTransfer(offer.Context); err != nil || key.closes != 3 || len(o.vpnSSOTransfers) != 0 {
		t.Fatal("matching close retry", err)
	}
	if _, err := o.BeginVPNSSOTransfer(ctx, b, q); err != vault.ErrPolicy {
		t.Fatal("quarantine weakened in-place", err)
	}
}

func TestVPNSSOTransferProfileCloseOwnerCloseAndExpiry(t *testing.T) {
	o, _, _, _ := owner(t)
	b, ctx := vpnSSOFixture(), context.Background()
	offer, _ := beginVPNTransfer(t, o, b)
	if err := o.CloseVPNSSO(offer.Context.ProfileID); err != nil || len(o.vpnSSOTransfers) != 0 {
		t.Fatal("profile retained transfer", err)
	}
	offer, _ = beginVPNTransfer(t, o, b)
	s := o.vpnSSOTransfers[offer.Context.TransferID]
	s.expires = time.Now().Add(-time.Second)
	if err := o.AcknowledgeVPNSSOTransfer(ctx, offer.Context, offer.Manifest); !errors.Is(err, vault.ErrPolicy) || len(o.vpnSSOTransfers) != 0 {
		t.Fatal(err)
	}
	q, _ := vpnTransferRequest(t)
	o.mu.Lock()
	timed, err := o.beginVPNSSOTransfer(ctx, b, q, 5*time.Millisecond)
	o.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		o.mu.Lock()
		_, exists := o.vpnSSOTransfers[timed.Context.TransferID]
		o.mu.Unlock()
		if !exists {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timer retained key")
		}
		time.Sleep(5 * time.Millisecond)
	}
	offer, _ = beginVPNTransfer(t, o, b)
	s = o.vpnSSOTransfers[offer.Context.TransferID]
	key := &vpnTransferKeyProbe{inner: s.key, fail: 1}
	s.key = key
	if err := o.Close(); !errors.Is(err, vaultstore.ErrStorage) {
		t.Fatal("owner hid key release failure", err)
	}
	if err := o.Close(); err != nil || len(o.vpnSSOTransfers) != 0 || key.closes != 2 {
		t.Fatal("owner release retry", err)
	}
}

func TestVPNSSOTransferAdmissionLimitsInvalidKeysAndCancellation(t *testing.T) {
	o, _, _, _ := owner(t)
	b, ctx := vpnSSOFixture(), context.Background()
	for _, change := range []func(*VPNSSOTransferRequest){
		func(q *VPNSSOTransferRequest) { q.ProfileID = "bad" },
		func(q *VPNSSOTransferRequest) { q.Epoch = 0 },
		func(q *VPNSSOTransferRequest) { q.RestorePublicKey = nil },
		func(q *VPNSSOTransferRequest) { q.RestorePublicKey = make([]byte, 32) },
		func(q *VPNSSOTransferRequest) { q.Minimum.RowVersion = ^uint64(0) },
	} {
		q, _ := vpnTransferRequest(t)
		change(&q)
		if _, err := o.BeginVPNSSOTransfer(ctx, b, q); err == nil || len(o.vpnSSOTransfers) != 0 {
			t.Fatal("bad begin published", err)
		}
	}
	q, _ := vpnTransferRequest(t)
	if _, err := o.BeginVPNSSOTransfer(ctx, VPNSSOBinding{}, q); err != vault.ErrFormat {
		t.Fatal(err)
	}
	for _, lifetime := range []time.Duration{0, vpnSSOTransferLifetime + time.Second} {
		o.mu.Lock()
		_, err := o.beginVPNSSOTransfer(ctx, b, q, lifetime)
		o.mu.Unlock()
		if err != vault.ErrFormat {
			t.Fatal(err)
		}
	}
	first, err := o.BeginVPNSSOTransfer(ctx, b, q)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.BeginVPNSSOTransfer(ctx, b, q); err != vaultstore.ErrConflict {
		t.Fatal("duplicate profile", err)
	}
	for len(o.vpnSSOTransfers) < maxVPNSSOTransfers {
		beginVPNTransfer(t, o, b)
	}
	other, _ := vpnTransferRequest(t)
	if _, err := o.BeginVPNSSOTransfer(ctx, b, other); err != vault.ErrPolicy {
		t.Fatal("capacity bypass", err)
	}
	if err := o.CancelVPNSSOTransfer(first.Context); err != nil {
		t.Fatal(err)
	}
	for _, stage := range o.vpnSSOTransfers {
		if err := o.CancelVPNSSOTransfer(cloneVPNSSOTransferContext(stage.context)); err != nil {
			t.Fatal(err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.BeginVPNSSOTransfer(canceled, b, other); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, operation := range []string{"take", "ack", "push", "commit"} {
		offer, _ := beginVPNTransfer(t, o, b)
		var err error
		switch operation {
		case "take":
			_, err = o.TakeVPNSSOTransfer(canceled, offer.Context, 0)
		case "ack":
			err = o.AcknowledgeVPNSSOTransfer(canceled, offer.Context, offer.Manifest)
		case "push":
			err = o.PushVPNSSOTransfer(canceled, vault.VPNSSOTransferPacket{Context: offer.Context})
		case "commit":
			_, err = o.CommitVPNSSOTransfer(canceled, offer.Context)
		}
		if !errors.Is(err, context.Canceled) || len(o.vpnSSOTransfers) != 0 {
			t.Fatal("cancel retained stage", operation, err)
		}
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := o.BeginVPNSSOTransfer(ctx, b, other); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
}

func TestVPNSSOTransferWriteKeyAndPolicyFailureRetireMatchingAttempt(t *testing.T) {
	o, _, _, _ := owner(t)
	b, ctx := vpnSSOFixture(), context.Background()
	for _, failKey := range []bool{false, true} {
		offer, private := beginVPNTransfer(t, o, b)
		restoreVPNTransfer(t, o, offer, private, nil)
		pushVPNTransfer(t, o, offer.Context, []byte("must not publish"))
		stage := o.vpnSSOTransfers[offer.Context.TransferID]
		retained := stage.input[0].Ciphertext
		if failKey {
			stage.key = &vpnTransferKeyProbe{inner: stage.key, withFailure: vault.ErrAuthentication}
		} else {
			probe := &browserStateProbe{Store: o.store, local: o.store.(vaultstore.LocalStateStore), policy: o.store.(vaultstore.ProfileStore), writeFailure: true}
			o.store = probe
		}
		if _, err := o.CommitVPNSSOTransfer(ctx, offer.Context); err == nil || len(o.vpnSSOTransfers) != 0 || len(o.vpnSSOProfiles) != 0 || !bytes.Equal(retained, make([]byte, len(retained))) {
			t.Fatal("failure kept resource/data", err)
		}
		if probe, ok := o.store.(*browserStateProbe); ok {
			probe.writeFailure = false
		}
	}
	offer, _ := beginVPNTransfer(t, o, b)
	policy, err := o.ReadLocalPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	policy.Policy.Sequence++
	if _, err := o.PutLocalPolicy(ctx, policy.Policy, vault.Default, 1); err != nil {
		t.Fatal(err)
	}
	if err := o.AcknowledgeVPNSSOTransfer(ctx, offer.Context, offer.Manifest); !errors.Is(err, vault.ErrPolicy) || len(o.vpnSSOTransfers) != 0 {
		t.Fatal("stale policy", err)
	}
}

func TestVPNSSOTransferOldCleanupPreservesReusedProfile(t *testing.T) {
	o, _, _, _ := owner(t)
	b, ctx := vpnSSOFixture(), context.Background()
	offer, _ := beginVPNTransfer(t, o, b)
	// A different native workflow consumes the old reservation and opens a new
	// one using the same identifier. Old transfer cleanup owns only the old value.
	c := saveVPNSSO(t, o, b, offer.Context.ProfileID, []byte("new native state"))
	if err := o.OpenVPNSSO(ctx, b, offer.Context.ProfileID, c, func(VPNSSOSnapshot) error { return nil }); err != nil {
		t.Fatal(err)
	}
	profile := o.vpnSSOProfiles[offer.Context.ProfileID]
	if err := o.CancelVPNSSOTransfer(offer.Context); err != nil || o.vpnSSOProfiles[offer.Context.ProfileID] != profile {
		t.Fatal("old cleanup retired new profile", err)
	}
	if _, err := o.SaveVPNSSO(ctx, b, offer.Context.ProfileID, []byte("still owned")); err != nil {
		t.Fatal(err)
	}
}

func TestVPNSSOTransferRetainedCiphertextBudget(t *testing.T) {
	o, _, _, _ := owner(t)
	b, ctx := vpnSSOFixture(), context.Background()
	offer, private := beginVPNTransfer(t, o, b)
	restoreVPNTransfer(t, o, offer, private, nil)
	// Reserve the actual budget footprint without spending test time generating
	// unrelated HPKE packets. Accounting depends only on retained buffer lengths.
	id := uuid.NewString()
	o.vpnSSOTransfers[id] = &vpnSSOTransferStage{context: vault.VPNSSOTransferContext{TransferID: id}, output: []vault.SealedBundle{{Ciphertext: make([]byte, maxVPNSSOTransferRetained)}}}
	m, chunks, err := vault.SealVPNSSOTransferArchive(offer.Context, "capture", []byte{1})
	if err != nil {
		t.Fatal(err)
	}
	defer wipeBrowserBundles(chunks)
	if err := o.PushVPNSSOTransfer(ctx, vault.VPNSSOTransferPacket{Context: offer.Context, Direction: "capture", Manifest: m, Index: 0, Bundle: chunks[0]}); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("input exceeded budget", err)
	}
	profileID, _ := openVPNSSO(t, o, b, VPNSSOCheckpoint{})
	saveVPNSSO(t, o, b, profileID, []byte("restore needs ciphertext"))
	q, _ := vpnTransferRequest(t)
	if _, err := o.BeginVPNSSOTransfer(ctx, b, q); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("output exceeded budget", err)
	}
	if _, exists := o.vpnSSOProfiles[q.ProfileID]; exists {
		t.Fatal("failed restore reserved profile")
	}
}

func TestVPNSSOTransferNewObservationStopsPendingRestoreAndAcknowledgement(t *testing.T) {
	o, _, _, _ := owner(t)
	b, ctx := vpnSSOFixture(), context.Background()
	id, _ := openVPNSSO(t, o, b, VPNSSOCheckpoint{})
	c := saveVPNSSO(t, o, b, id, []byte("old provider login"))
	offer, _ := beginVPNTransfer(t, o, b)
	s := o.vpnSSOTransfers[offer.Context.TransferID]
	retained := s.output[0].Ciphertext
	deleted, err := o.DeleteVPNSSO(ctx, b, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.TakeVPNSSOTransfer(ctx, offer.Context, 0); !errors.Is(err, vaultstore.ErrConflict) || len(o.vpnSSOTransfers) != 0 || !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatal("old restore released after deletion", err)
	}
	newID, _ := openVPNSSO(t, o, b, deleted)
	saveVPNSSO(t, o, b, newID, []byte("new provider login"))
	offer, _ = beginVPNTransfer(t, o, b)
	packet, err := o.TakeVPNSSOTransfer(ctx, offer.Context, 0)
	if err != nil {
		t.Fatal(err)
	}
	wipeBrowserBundles([]vault.SealedBundle{packet.Bundle})
	// Even a partially observed newer manifest must prevent acknowledgement of
	// old restored data; the browser must remain unpublished until this succeeds.
	floor, err := o.ObserveVPNSSO(ctx, b, VPNSSOFloor{})
	if err != nil {
		t.Fatal(err)
	}
	floor.RowVersion++
	if _, err := o.ObserveVPNSSO(ctx, b, floor); err != nil {
		t.Fatal(err)
	}
	if err := o.AcknowledgeVPNSSOTransfer(ctx, offer.Context, offer.Manifest); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatal("new manifest floor ignored at restore ack", err)
	}
}
