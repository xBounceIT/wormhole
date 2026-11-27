package localvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func vpnSSOFixture() VPNSSOBinding {
	return VPNSSOBinding{WorkspaceID: uuid.NewString(), FileID: uuid.NewString(), TunnelID: uuid.NewString(), AccountID: uuid.NewString(), Kind: 2, ConfigurationVersion: 1, GatewayOrigin: "https://vpn.test:443", Realm: "staff/è", RouteDigest: sha256.Sum256([]byte("authenticated route")), TrustDigest: sha256.Sum256([]byte("verified trust"))}
}

func openVPNSSO(t *testing.T, o *Owner, b VPNSSOBinding, minimum VPNSSOCheckpoint) (string, VPNSSOCheckpoint) {
	t.Helper()
	id := uuid.NewString()
	var checkpoint VPNSSOCheckpoint
	if err := o.OpenVPNSSO(context.Background(), b, id, minimum, func(s VPNSSOSnapshot) error {
		checkpoint = s.Checkpoint
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return id, checkpoint
}

func saveVPNSSO(t *testing.T, o *Owner, b VPNSSOBinding, id string, data []byte) VPNSSOCheckpoint {
	t.Helper()
	c, err := o.SaveVPNSSO(context.Background(), b, id, bytes.Clone(data))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestVPNSSOEncryptedArchiveLifecycleAndBorrowedWipe(t *testing.T) {
	o, path, opts, key := owner(t)
	ctx, b := context.Background(), vpnSSOFixture()
	id, empty := openVPNSSO(t, o, b, VPNSSOCheckpoint{})
	if empty != (VPNSSOCheckpoint{}) {
		t.Fatal("new scope not empty")
	}
	// Opaque binary archive fixture spans encrypted chunks. The owner must not
	// turn this into a lossy cookie/JSON subset or persist any plaintext bytes.
	archive := bytes.Repeat([]byte("idp-storage\x00\xff\x01"), vault.MaxSecretBytes/14+1)
	if len(archive) <= vault.MaxSecretBytes {
		t.Fatal("fixture must span chunks")
	}
	input := bytes.Clone(archive)
	c, err := o.SaveVPNSSO(ctx, b, id, input)
	if err != nil || c.Revision != 1 || c.Deleted || c.Digest == [32]byte{} || !bytes.Equal(input, make([]byte, len(input))) {
		t.Fatal("save/wipe", err)
	}
	if _, err := o.SaveVPNSSO(ctx, b, id, []byte("replay")); err != vault.ErrPolicy {
		t.Fatal("successful capture replay accepted", err)
	}
	var borrowed []byte
	id = uuid.NewString()
	if err := o.OpenVPNSSO(ctx, b, id, c, func(s VPNSSOSnapshot) error {
		if s.Checkpoint != c || !bytes.Equal(s.Archive, archive) {
			t.Fatal("snapshot mismatch")
		}
		if _, err := json.Marshal(s); err == nil {
			t.Fatal("snapshot serialized")
		}
		borrowed = s.Archive
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("borrowed plaintext retained")
	}
	if err := o.CloseVPNSSO(id); err != nil {
		t.Fatal(err)
	}
	if err := o.CloseVPNSSO(id); err != nil {
		t.Fatal("close not idempotent", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	disk, err := os.ReadFile(path)
	if err != nil || bytes.Contains(disk, []byte("idp-storage")) {
		t.Fatal("plaintext persisted", err)
	}
	opts.Create = false
	reopened, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.OpenVPNSSO(ctx, b, uuid.NewString(), c, func(s VPNSSOSnapshot) error {
		if s.Checkpoint != c || !bytes.Equal(s.Archive, archive) {
			t.Fatal("reopen lost archive")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestVPNSSOBindingsBoundsAndCheckpointValidation(t *testing.T) {
	b := vpnSSOFixture()
	digest, err := b.digest()
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*VPNSSOBinding){
		func(b *VPNSSOBinding) { b.WorkspaceID = uuid.NewString() },
		func(b *VPNSSOBinding) { b.FileID = uuid.NewString() },
		func(b *VPNSSOBinding) { b.TunnelID = uuid.NewString() },
		func(b *VPNSSOBinding) { b.AccountID = uuid.NewString() },
		func(b *VPNSSOBinding) { b.Kind = 9 },
		func(b *VPNSSOBinding) { b.ConfigurationVersion++ },
		func(b *VPNSSOBinding) { b.GatewayOrigin = "https://vpn.test:444" },
		func(b *VPNSSOBinding) { b.Realm += ":staff" },
		func(b *VPNSSOBinding) { b.RouteDigest[0] ^= 1 },
		func(b *VPNSSOBinding) { b.TrustDigest[0] ^= 1 },
	} {
		other := b
		change(&other)
		got, err := other.digest()
		if err != nil || got == digest || vpnSSOScope(got) == vpnSSOScope(digest) {
			t.Fatal("binding dimension ignored", err)
		}
	}
	for _, origin := range []string{"https://vpn.test", "https://[::1]:443"} {
		other := b
		other.GatewayOrigin = origin
		if _, err := other.digest(); err != nil {
			t.Fatal("valid origin refused", origin, err)
		}
	}
	for _, change := range []func(*VPNSSOBinding){
		func(b *VPNSSOBinding) { b.AccountID = uuid.Nil.String() },
		func(b *VPNSSOBinding) { b.TunnelID = "invalid" },
		func(b *VPNSSOBinding) { b.FileID = "12345678-ABCD-4ABC-8ABC-123456789ABC" },
		func(b *VPNSSOBinding) { b.Kind = 1 },
		func(b *VPNSSOBinding) { b.ConfigurationVersion = 0 },
		func(b *VPNSSOBinding) { b.ConfigurationVersion = math.MaxUint64 },
		func(b *VPNSSOBinding) { b.RouteDigest = [32]byte{} },
		func(b *VPNSSOBinding) { b.TrustDigest = [32]byte{} },
		func(b *VPNSSOBinding) { b.Realm = string([]byte{0xff}) },
		func(b *VPNSSOBinding) { b.Realm = "x\n" },
		func(b *VPNSSOBinding) { b.Realm = strings.Repeat("x", 4097) },
	} {
		other := b
		change(&other)
		if _, err := other.digest(); err != vault.ErrFormat {
			t.Fatal("bad binding accepted", err)
		}
	}
	for _, origin := range []string{"", "://", "http://vpn.test", "https://user@vpn.test", "https://vpn.test/", "https://vpn.test?", "https://vpn.test?a=1", "https://vpn.test#fragment", "https://vpn.test:", "https://vpn.test:0", "https://vpn.test:65536", "https://vpn.test:bad", "https://vpn.test/../", "https://v pn.test", "https://è.test", "https://vpn.test\\", "https://vpn.test%00", "https://::1", "https://[not-an-ip]:443", "https://[127.0.0.1]", "https://" + strings.Repeat("a", 4097)} {
		other := b
		other.GatewayOrigin = origin
		if _, err := other.digest(); err != vault.ErrFormat {
			t.Fatal("bad origin accepted", origin, err)
		}
	}
	for _, c := range []VPNSSOCheckpoint{{Revision: 1}, {Revision: math.MaxUint64, Digest: digest}, {Digest: digest}, {Deleted: true}} {
		if c.valid() {
			t.Fatal("bad checkpoint accepted", c)
		}
	}
}

type vpnSSOCancelRead struct {
	*browserStateProbe
	cancel context.CancelFunc
}

func (p vpnSSOCancelRead) ReadLocalState(ctx context.Context, kind, scope string) (vaultstore.LocalState, error) {
	state, err := p.browserStateProbe.ReadLocalState(ctx, kind, scope)
	p.cancel()
	return state, err
}

func TestVPNSSOCancellationAfterStorageReadNeverReleases(t *testing.T) {
	o, _, _, _ := owner(t)
	b, ctx := vpnSSOFixture(), context.Background()
	probe := &browserStateProbe{Store: o.store, local: o.store.(vaultstore.LocalStateStore), policy: o.store.(vaultstore.ProfileStore)}
	canceled, cancel := context.WithCancel(ctx)
	o.store = vpnSSOCancelRead{probe, cancel}
	if err := o.OpenVPNSSO(canceled, b, uuid.NewString(), VPNSSOCheckpoint{}, func(VPNSSOSnapshot) error { t.Fatal("late canceled missing-state release"); return nil }); err != context.Canceled || len(o.vpnSSOProfiles) != 0 {
		t.Fatal(err)
	}
}

func TestVPNSSOMaximumArchiveAndEncryptedChunkShrink(t *testing.T) {
	o, _, _, _ := owner(t)
	b, ctx := vpnSSOFixture(), context.Background()
	id, _ := openVPNSSO(t, o, b, VPNSSOCheckpoint{})
	archive := bytes.Repeat([]byte{0xa7}, MaxVPNSSOArchiveBytes)
	c, err := o.SaveVPNSSO(ctx, b, id, archive)
	if err != nil || c.Revision != 1 || !bytes.Equal(archive, make([]byte, len(archive))) {
		t.Fatal("maximum archive rejected/retained", err)
	}
	digest, _ := b.digest()
	state, err := o.ReadLocalState(ctx, "vpn-sso", vpnSSOScope(digest), 1)
	if err != nil || state.Size != vaultstore.MaxLocalStateBytes || len(state.Fields) != vaultstore.MaxLocalStateChunks {
		t.Fatal("maximum manifest", err)
	}
	id = uuid.NewString()
	if err := o.OpenVPNSSO(ctx, b, id, c, func(s VPNSSOSnapshot) error {
		if len(s.Archive) != MaxVPNSSOArchiveBytes || s.Archive[0] != 0xa7 || s.Archive[len(s.Archive)-1] != 0xa7 {
			t.Fatal("maximum archive truncated")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	c = saveVPNSSO(t, o, b, id, []byte("small new snapshot"))
	shrunk, err := o.ReadLocalState(ctx, "vpn-sso", vpnSSOScope(digest), c.Revision)
	if err != nil || len(shrunk.Fields) != len(state.Fields) {
		t.Fatal("shrink reset chunk versions", err)
	}
	for i, field := range shrunk.Fields {
		if field.Version <= state.Fields[i].Version || field.Present != (i == 0) {
			t.Fatal("chunk not advanced/retired", i)
		}
	}
}

func TestVPNSSOConcurrentCaptureDeleteAndRecreate(t *testing.T) {
	o, _, _, _ := owner(t)
	b, ctx := vpnSSOFixture(), context.Background()
	id1, _ := openVPNSSO(t, o, b, VPNSSOCheckpoint{})
	id2, _ := openVPNSSO(t, o, b, VPNSSOCheckpoint{})
	var wg sync.WaitGroup
	errorsOut := make(chan error, 2)
	for _, id := range []string{id1, id2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := o.SaveVPNSSO(ctx, b, id, []byte("concurrent-idp-state"))
			errorsOut <- err
		}()
	}
	wg.Wait()
	close(errorsOut)
	success, conflict := 0, 0
	for err := range errorsOut {
		switch err {
		case nil:
			success++
		case vaultstore.ErrConflict:
			conflict++
		default:
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("concurrent overwrite", success, conflict)
	}
	stale, checkpoint := openVPNSSO(t, o, b, VPNSSOCheckpoint{})
	deleted, err := o.DeleteVPNSSO(ctx, b, checkpoint)
	if err != nil || !deleted.Deleted || deleted.Revision != 2 || deleted.Digest == checkpoint.Digest {
		t.Fatal("delete", err)
	}
	if same, err := o.DeleteVPNSSO(ctx, b, deleted); err != nil || same != deleted {
		t.Fatal("tombstone retry", err)
	}
	if _, err := o.SaveVPNSSO(ctx, b, stale, []byte("resurrect")); err != vaultstore.ErrConflict {
		t.Fatal("stale login resurrected deleted session", err)
	}
	id, current := openVPNSSO(t, o, b, deleted)
	if current != deleted {
		t.Fatal("tombstone lost")
	}
	recreated := saveVPNSSO(t, o, b, id, []byte("new-login"))
	if recreated.Revision != 3 || recreated.Deleted {
		t.Fatal("recreate reset revision")
	}
	if _, err := o.DeleteVPNSSO(ctx, b, deleted); err != vaultstore.ErrConflict {
		t.Fatal("stale delete accepted", err)
	}
}

func TestVPNSSOFailureRetryCancellationExpiryAndOwnerClose(t *testing.T) {
	o, _, _, _ := owner(t)
	b, ctx := vpnSSOFixture(), context.Background()
	consumerFailure := errors.New("restore fixture")
	failedID := uuid.NewString()
	if err := o.OpenVPNSSO(ctx, b, failedID, VPNSSOCheckpoint{}, func(VPNSSOSnapshot) error { return consumerFailure }); err != consumerFailure || len(o.vpnSSOProfiles) != 0 {
		t.Fatal("failed restore published reservation", err)
	}
	id, _ := openVPNSSO(t, o, b, VPNSSOCheckpoint{})
	probe := &browserStateProbe{Store: o.store, local: o.store.(vaultstore.LocalStateStore), policy: o.store.(vaultstore.ProfileStore), writeFailure: true}
	o.store = probe
	input := []byte("retry-state")
	if _, err := o.SaveVPNSSO(ctx, b, id, input); err != vaultstore.ErrStorage || o.vpnSSOProfiles[id].Source.Revision != 0 || !bytes.Equal(input, make([]byte, len(input))) {
		t.Fatal("failure advanced/dropped reservation or retained input", err)
	}
	probe.writeFailure = false
	c := saveVPNSSO(t, o, b, id, []byte("retry-state"))
	failedID = uuid.NewString()
	var borrowed []byte
	if err := o.OpenVPNSSO(ctx, b, failedID, c, func(s VPNSSOSnapshot) error { borrowed = s.Archive; return consumerFailure }); err != consumerFailure || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("failed restore leaked bytes", err)
	}
	if _, exists := o.vpnSSOProfiles[failedID]; exists {
		t.Fatal("failed restore reservation retained")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := o.OpenVPNSSO(canceled, b, uuid.NewString(), c, func(VPNSSOSnapshot) error { t.Fatal("canceled restore"); return nil }); err != context.Canceled {
		t.Fatal(err)
	}
	id, _ = openVPNSSO(t, o, b, c)
	if _, err := o.SaveVPNSSO(canceled, b, id, []byte("cancel")); err != context.Canceled {
		t.Fatal(err)
	}
	if _, err := o.DeleteVPNSSO(canceled, b, c); err != context.Canceled {
		t.Fatal(err)
	}
	inside, cancelInside := context.WithCancel(ctx)
	if err := o.OpenVPNSSO(inside, b, uuid.NewString(), c, func(VPNSSOSnapshot) error { cancelInside(); return nil }); err != context.Canceled {
		t.Fatal("canceled acknowledgement published profile", err)
	}
	profile := o.vpnSSOProfiles[id]
	profile.Expires = time.Now().Add(-time.Second)
	o.vpnSSOProfiles[id] = profile
	if _, err := o.SaveVPNSSO(ctx, b, id, []byte("expired")); err != vault.ErrPolicy {
		t.Fatal("expired attempt accepted", err)
	}
	openVPNSSO(t, o, b, c)
	if _, exists := o.vpnSSOProfiles[id]; exists {
		t.Fatal("expired reservation not retired")
	}
	if err := o.Close(); err != nil || o.vpnSSOProfiles != nil || o.vpnSSOFloors != nil {
		t.Fatal("close retained runtime", err)
	}
	if err := o.OpenVPNSSO(ctx, b, uuid.NewString(), c, func(VPNSSOSnapshot) error { t.Fatal("closed release"); return nil }); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
	if _, err := o.SaveVPNSSO(ctx, b, id, []byte("closed")); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
	if _, err := o.DeleteVPNSSO(ctx, b, c); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
	if err := o.CloseVPNSSO(id); err != nil {
		t.Fatal("close reservation after owner close", err)
	}
}

func TestVPNSSORejectsMalformedArchivesAndSubstitutedBindings(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	for _, change := range []func([]byte) []byte{
		func(v []byte) []byte { return v[:vpnSSOHeaderBytes] },
		func(v []byte) []byte { v[0] ^= 1; return v },
		func(v []byte) []byte { v[4] ^= 1; return v },
		func(v []byte) []byte { binary.BigEndian.PutUint64(v[36:44], 2); return v },
		func(v []byte) []byte { binary.BigEndian.PutUint32(v[44:48], 0); return v },
		func(v []byte) []byte { return append(v, 1) },
	} {
		b := vpnSSOFixture()
		digest, _ := b.digest()
		raw := make([]byte, vpnSSOHeaderBytes+1)
		copy(raw, "VSS1")
		copy(raw[4:36], digest[:])
		binary.BigEndian.PutUint64(raw[36:44], 1)
		binary.BigEndian.PutUint32(raw[44:48], 1)
		raw[48] = 9
		if _, err := o.PutLocalState(ctx, "vpn-sso", vpnSSOScope(digest), change(raw), 0); err != nil {
			t.Fatal(err)
		}
		if err := o.OpenVPNSSO(ctx, b, uuid.NewString(), VPNSSOCheckpoint{}, func(VPNSSOSnapshot) error { t.Fatal("corrupt archive released"); return nil }); err != vault.ErrAuthentication {
			t.Fatal(err)
		}
	}
	b := vpnSSOFixture()
	id, _ := openVPNSSO(t, o, b, VPNSSOCheckpoint{})
	c := saveVPNSSO(t, o, b, id, []byte("issuer-private-storage"))
	other := b
	other.AccountID = uuid.NewString()
	otherID, otherCheckpoint := openVPNSSO(t, o, other, VPNSSOCheckpoint{})
	if otherCheckpoint != (VPNSSOCheckpoint{}) {
		t.Fatal("another account inherited storage")
	}
	if _, err := o.SaveVPNSSO(ctx, b, otherID, []byte("foreign attempt")); err != vault.ErrPolicy {
		t.Fatal("foreign attempt mutated", err)
	}
	if _, exists := o.vpnSSOProfiles[otherID]; !exists {
		t.Fatal("foreign request retired original attempt")
	}
	if err := o.OpenVPNSSO(ctx, other, uuid.NewString(), c, func(VPNSSOSnapshot) error { t.Fatal("foreign checkpoint released"); return nil }); err != vault.ErrRollback {
		t.Fatal("checkpoint transferred across account", err)
	}
	// Authenticated storage cannot transplant even an otherwise valid archive
	// from one binding to another: the encrypted header also carries the digest.
	digest, _ := b.digest()
	otherDigest, _ := other.digest()
	var copied []byte
	if err := o.WithLocalState(ctx, "vpn-sso", vpnSSOScope(digest), 1, func(v []byte) error { copied = bytes.Clone(v); return nil }); err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(copied)
	if _, err := o.PutLocalState(ctx, "vpn-sso", vpnSSOScope(otherDigest), copied, 0); err != nil {
		t.Fatal(err)
	}
	if err := o.OpenVPNSSO(ctx, other, uuid.NewString(), VPNSSOCheckpoint{}, func(VPNSSOSnapshot) error { t.Fatal("transplanted payload released"); return nil }); err != vault.ErrAuthentication {
		t.Fatal(err)
	}
}

func TestVPNSSOObservedRollbackAndProtectedCheckpointFloors(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx, b := context.Background(), vpnSSOFixture()
	id, _ := openVPNSSO(t, o, b, VPNSSOCheckpoint{})
	c := saveVPNSSO(t, o, b, id, []byte("latest-state"))
	probe := &browserStateProbe{Store: o.store, local: o.store.(vaultstore.LocalStateStore), policy: o.store.(vaultstore.ProfileStore), missing: true}
	o.store = probe
	if err := o.OpenVPNSSO(ctx, b, uuid.NewString(), VPNSSOCheckpoint{}, func(VPNSSOSnapshot) error { t.Fatal("missing observed row released"); return nil }); err != vault.ErrRollback {
		t.Fatal(err)
	}
	probe.missing, probe.corrupt = false, true
	if err := o.OpenVPNSSO(ctx, b, uuid.NewString(), c, func(VPNSSOSnapshot) error { t.Fatal("bad MAC released"); return nil }); err != vault.ErrAuthentication {
		t.Fatal(err)
	}
	probe.corrupt = false
	for _, floor := range []VPNSSOCheckpoint{
		{Revision: 1, Digest: sha256.Sum256([]byte("same-version substitution"))},
		{Revision: 1, Deleted: true, Digest: c.Digest},
	} {
		if err := o.OpenVPNSSO(ctx, b, uuid.NewString(), floor, func(VPNSSOSnapshot) error { t.Fatal("rollback released"); return nil }); err != vault.ErrRollback {
			t.Fatal(err)
		}
	}
	// A successful observation survives failed delivery and reservation close.
	id, _ = openVPNSSO(t, o, b, c)
	if err := o.CloseVPNSSO(id); err != nil {
		t.Fatal(err)
	}
	probe.missing = true
	if err := o.OpenVPNSSO(ctx, b, uuid.NewString(), VPNSSOCheckpoint{}, func(VPNSSOSnapshot) error { t.Fatal("closed profile erased floor"); return nil }); err != vault.ErrRollback {
		t.Fatal(err)
	}
	probe.missing = false
	// An independently protected checkpoint supplies the floor in a fresh owner.
	o.vpnSSOFloors = nil
	probe.missing = true
	if err := o.OpenVPNSSO(ctx, b, uuid.NewString(), c, func(VPNSSOSnapshot) error { t.Fatal("protected floor ignored"); return nil }); err != vault.ErrRollback {
		t.Fatal(err)
	}
	probe.missing = false
	id, _ = openVPNSSO(t, o, b, c)
	probe.writeFailure = true
	if _, err := o.DeleteVPNSSO(ctx, b, c); err != vaultstore.ErrStorage {
		t.Fatal(err)
	}
	probe.writeFailure = false
	deleted, err := o.DeleteVPNSSO(ctx, b, c)
	if err != nil {
		t.Fatal(err)
	}
	probe.missing = true
	if err := o.OpenVPNSSO(ctx, b, uuid.NewString(), VPNSSOCheckpoint{}, func(VPNSSOSnapshot) error { t.Fatal("missing tombstone released"); return nil }); err != vault.ErrRollback {
		t.Fatal(err)
	}
	if deleted.Revision != 2 {
		t.Fatal("failed delete advanced revision")
	}
}

func TestVPNSSOPolicyChangesAndNativeAdmissionBounds(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx, b := context.Background(), vpnSSOFixture()
	id, _ := openVPNSSO(t, o, b, VPNSSOCheckpoint{})
	if err := o.OpenVPNSSO(ctx, b, id, VPNSSOCheckpoint{}, func(VPNSSOSnapshot) error { t.Fatal("duplicate admitted"); return nil }); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	for _, q := range []struct {
		b     VPNSSOBinding
		id    string
		floor VPNSSOCheckpoint
		use   func(VPNSSOSnapshot) error
	}{
		{VPNSSOBinding{}, uuid.NewString(), VPNSSOCheckpoint{}, func(VPNSSOSnapshot) error { return nil }},
		{b, "bad", VPNSSOCheckpoint{}, func(VPNSSOSnapshot) error { return nil }},
		{b, uuid.NewString(), VPNSSOCheckpoint{Revision: 1}, func(VPNSSOSnapshot) error { return nil }},
		{b, uuid.NewString(), VPNSSOCheckpoint{}, nil},
	} {
		if err := o.OpenVPNSSO(ctx, q.b, q.id, q.floor, q.use); err != vault.ErrFormat {
			t.Fatal(err)
		}
	}
	for _, payload := range [][]byte{nil, make([]byte, MaxVPNSSOArchiveBytes+1)} {
		if _, err := o.SaveVPNSSO(ctx, b, id, payload); err != vault.ErrFormat {
			t.Fatal("bad size accepted", err)
		}
	}
	for _, badID := range []string{"bad", uuid.Nil.String()} {
		if _, err := o.SaveVPNSSO(ctx, b, badID, []byte("bad")); err != vault.ErrFormat {
			t.Fatal(err)
		}
		if err := o.CloseVPNSSO(badID); err != vault.ErrFormat {
			t.Fatal(err)
		}
	}
	if _, err := o.SaveVPNSSO(ctx, VPNSSOBinding{}, id, []byte("bad")); err != vault.ErrFormat {
		t.Fatal(err)
	}
	for _, floor := range []VPNSSOCheckpoint{{}, {Revision: 1}} {
		if _, err := o.DeleteVPNSSO(ctx, b, floor); err != vault.ErrFormat {
			t.Fatal(err)
		}
	}
	if _, err := o.DeleteVPNSSO(ctx, VPNSSOBinding{}, VPNSSOCheckpoint{Revision: 1, Digest: b.RouteDigest}); err != vault.ErrFormat {
		t.Fatal(err)
	}
	policy, err := o.ReadLocalPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	policy.Policy.Sequence++
	if _, err := o.PutLocalPolicy(ctx, policy.Policy, vault.Default, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := o.SaveVPNSSO(ctx, b, id, []byte("stale policy")); err != vault.ErrPolicy {
		t.Fatal("old policy attempt accepted", err)
	}
	id, _ = openVPNSSO(t, o, b, VPNSSOCheckpoint{})
	c := saveVPNSSO(t, o, b, id, []byte("new policy"))
	policy.Policy.Sequence++
	if _, err := o.PutLocalPolicy(ctx, policy.Policy, vault.Standard, 2); err != nil {
		t.Fatal(err)
	}
	if err := o.OpenVPNSSO(ctx, b, uuid.NewString(), c, func(VPNSSOSnapshot) error { t.Fatal("weak slots restored at Standard"); return nil }); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	if _, err := o.SaveVPNSSO(ctx, b, id, []byte("policy failure")); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	if _, err := o.DeleteVPNSSO(ctx, b, c); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	if floor, err := o.ObserveVPNSSO(ctx, b, VPNSSOFloor{}); err != nil || floor.Checkpoint != c {
		t.Fatal("policy denial hid observation from protected anchor", err)
	}
}

func TestVPNSSOCapacityExpiresWithoutDroppingRollbackFloors(t *testing.T) {
	o, _, _, _ := owner(t)
	b, ctx := vpnSSOFixture(), context.Background()
	ids := make([]string, maxVPNSSOProfiles)
	for i := range ids {
		ids[i], _ = openVPNSSO(t, o, b, VPNSSOCheckpoint{})
	}
	if err := o.OpenVPNSSO(ctx, b, uuid.NewString(), VPNSSOCheckpoint{}, func(VPNSSOSnapshot) error { t.Fatal("capacity bypass"); return nil }); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	profile := o.vpnSSOProfiles[ids[0]]
	profile.Expires = time.Now().Add(-time.Second)
	o.vpnSSOProfiles[ids[0]] = profile
	openVPNSSO(t, o, b, VPNSSOCheckpoint{})
	if len(o.vpnSSOProfiles) != maxVPNSSOProfiles {
		t.Fatal("expiry did not recover capacity")
	}
	for id := range o.vpnSSOProfiles {
		if err := o.CloseVPNSSO(id); err != nil {
			t.Fatal(err)
		}
	}
	// Fill metadata only; no archive or secret bytes live in the floor registry.
	for len(o.vpnSSOFloors) < maxVPNSSOFloors {
		o.vpnSSOFloors[uuid.NewString()] = VPNSSOFloor{}
	}
	other := b
	other.TunnelID = uuid.NewString()
	if err := o.OpenVPNSSO(ctx, other, uuid.NewString(), VPNSSOCheckpoint{}, func(VPNSSOSnapshot) error { t.Fatal("unbounded floors"); return nil }); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	// Existing scopes remain usable at capacity: no oldest-floor eviction.
	openVPNSSO(t, o, b, VPNSSOCheckpoint{})
	if len(o.vpnSSOFloors) != maxVPNSSOFloors {
		t.Fatal("floor capacity changed")
	}
}

func TestVPNSSOProtectedCheckpointRejectsFullDatabaseReplayAfterRestart(t *testing.T) {
	o, path, opts, key := owner(t)
	b, ctx := vpnSSOFixture(), context.Background()
	id, _ := openVPNSSO(t, o, b, VPNSSOCheckpoint{})
	first := saveVPNSSO(t, o, b, id, []byte("first encrypted snapshot"))
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	olderDatabase, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	opts.Create = false
	later, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	id, _ = openVPNSSO(t, later, b, first)
	second := saveVPNSSO(t, later, b, id, []byte("second encrypted snapshot"))
	deleted, err := later.DeleteVPNSSO(ctx, b, second)
	if err != nil {
		t.Fatal(err)
	}
	if err := later.Close(); err != nil {
		t.Fatal(err)
	}
	// The attacker replays a valid older whole database. No current owner or
	// mutable in-memory floor survives; only the independent checkpoint remains.
	if err := os.WriteFile(path, olderDatabase, 0600); err != nil {
		t.Fatal(err)
	}
	replayed, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer replayed.Close()
	for _, minimum := range []VPNSSOCheckpoint{second, deleted} {
		if err := replayed.OpenVPNSSO(ctx, b, uuid.NewString(), minimum, func(VPNSSOSnapshot) error { t.Fatal("replayed database released SSO archive"); return nil }); err != vault.ErrRollback {
			t.Fatal("protected checkpoint lost at restart", err)
		}
	}
}

func TestVPNSSOTrustedFloorSurvivesFailedReadAndLaterOmission(t *testing.T) {
	o, _, _, _ := owner(t)
	b, ctx := vpnSSOFixture(), context.Background()
	id, _ := openVPNSSO(t, o, b, VPNSSOCheckpoint{})
	saveVPNSSO(t, o, b, id, []byte("old valid snapshot"))
	probe := &browserStateProbe{Store: o.store, local: o.store.(vaultstore.LocalStateStore), policy: o.store.(vaultstore.ProfileStore), corrupt: true}
	o.store = probe
	newer := VPNSSOCheckpoint{Revision: 2, Digest: sha256.Sum256([]byte("independently anchored newer snapshot"))}
	if err := o.OpenVPNSSO(ctx, b, uuid.NewString(), newer, func(VPNSSOSnapshot) error { t.Fatal("corrupt snapshot released"); return nil }); err != vault.ErrAuthentication {
		t.Fatal(err)
	}
	probe.corrupt = false
	if err := o.OpenVPNSSO(ctx, b, uuid.NewString(), VPNSSOCheckpoint{}, func(VPNSSOSnapshot) error { t.Fatal("failed read lost trusted checkpoint"); return nil }); err != vault.ErrRollback {
		t.Fatal("checkpoint omission weakened floor", err)
	}
	probe.missing = true
	newer.Revision++
	newer.Deleted = true
	if err := o.OpenVPNSSO(ctx, b, uuid.NewString(), newer, func(VPNSSOSnapshot) error { t.Fatal("missing snapshot released"); return nil }); err != vault.ErrRollback {
		t.Fatal(err)
	}
	digest, _ := b.digest()
	if o.vpnSSOFloors[vpnSSOScope(digest)].Checkpoint != newer {
		t.Fatal("failed read discarded tombstone checkpoint")
	}
	probe.missing = false
	if err := o.OpenVPNSSO(ctx, b, uuid.NewString(), VPNSSOCheckpoint{}, func(VPNSSOSnapshot) error { t.Fatal("tombstone omitted after failure"); return nil }); err != vault.ErrRollback {
		t.Fatal(err)
	}
}

type vpnSSOSecretProbe struct {
	*browserStateProbe
	metadata   *vaultstore.LocalState
	readSecret func() error
}

func (p vpnSSOSecretProbe) ReadLocalState(ctx context.Context, kind, scope string) (vaultstore.LocalState, error) {
	if p.metadata != nil {
		return *p.metadata, nil
	}
	return p.browserStateProbe.ReadLocalState(ctx, kind, scope)
}

func (p vpnSSOSecretProbe) ReadSecret(ctx context.Context, ref vaultstore.SecretRef) (vaultstore.Secret, error) {
	if err := p.readSecret(); err != nil {
		return vaultstore.Secret{}, err
	}
	return p.Store.ReadSecret(ctx, ref)
}

func TestVPNSSOAuthenticatedManifestRevisionSurvivesUnavailableCiphertext(t *testing.T) {
	o, path, opts, key := owner(t)
	b, ctx := vpnSSOFixture(), context.Background()
	id, _ := openVPNSSO(t, o, b, VPNSSOCheckpoint{})
	first := saveVPNSSO(t, o, b, id, []byte("old storage"))
	digest, _ := b.digest()
	oldManifest, err := o.ReadLocalState(ctx, "vpn-sso", vpnSSOScope(digest), 1)
	if err != nil {
		t.Fatal(err)
	}
	id, _ = openVPNSSO(t, o, b, first)
	saveVPNSSO(t, o, b, id, []byte("new storage"))
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Create = false
	fresh, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	base := &browserStateProbe{Store: fresh.store, local: fresh.store.(vaultstore.LocalStateStore), policy: fresh.store.(vaultstore.ProfileStore)}
	fresh.store = vpnSSOSecretProbe{browserStateProbe: base, readSecret: func() error { return vaultstore.ErrStorage }}
	if err := fresh.OpenVPNSSO(ctx, b, uuid.NewString(), VPNSSOCheckpoint{}, func(VPNSSOSnapshot) error { t.Fatal("unavailable data released"); return nil }); err != vaultstore.ErrStorage {
		t.Fatal(err)
	}
	floor := fresh.vpnSSOFloors[vpnSSOScope(digest)]
	if floor.RowVersion != 2 || floor.Checkpoint != (VPNSSOCheckpoint{}) {
		t.Fatal("manifest floor not retained independently of full snapshot")
	}
	anchored, err := fresh.ObserveVPNSSO(ctx, b, VPNSSOFloor{})
	if err != nil || anchored != floor {
		t.Fatal("failed-read observation unavailable to device anchor", err)
	}
	fresh.store = vpnSSOSecretProbe{browserStateProbe: base, metadata: &oldManifest, readSecret: func() error { t.Fatal("rollback reached decryption"); return nil }}
	if err := fresh.OpenVPNSSO(ctx, b, uuid.NewString(), VPNSSOCheckpoint{}, func(VPNSSOSnapshot) error { t.Fatal("old data released"); return nil }); err != vault.ErrRollback {
		t.Fatal("manifest observation lost after chunk failure", err)
	}
	if err := fresh.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if got, err := restarted.ObserveVPNSSO(ctx, b, anchored); err != nil || got != anchored {
		t.Fatal("restart lost partial manifest floor", err)
	}
	restartBase := &browserStateProbe{Store: restarted.store, local: restarted.store.(vaultstore.LocalStateStore), policy: restarted.store.(vaultstore.ProfileStore)}
	restarted.store = vpnSSOSecretProbe{browserStateProbe: restartBase, metadata: &oldManifest, readSecret: func() error { t.Fatal("restart rollback reached decryption"); return nil }}
	if err := restarted.OpenVPNSSO(ctx, b, uuid.NewString(), VPNSSOCheckpoint{}, func(VPNSSOSnapshot) error { t.Fatal("old data released after restart"); return nil }); err != vault.ErrRollback {
		t.Fatal("imported manifest floor ignored", err)
	}
}

func TestVPNSSOObservationBoundsMonotonicityAndNativeMetadata(t *testing.T) {
	o, _, _, _ := owner(t)
	b, ctx := vpnSSOFixture(), context.Background()
	minimum := VPNSSOFloor{RowVersion: 9007199254740993}
	got, err := o.ObserveVPNSSO(ctx, b, minimum)
	if err != nil || got != minimum {
		t.Fatal(err)
	}
	raw, err := json.Marshal(got)
	if err != nil || !bytes.Contains(raw, []byte(`"rowVersion":"9007199254740993"`)) {
		t.Fatal("observation loses 64-bit revision precision", err)
	}
	var roundtrip VPNSSOFloor
	if err := json.Unmarshal(raw, &roundtrip); err != nil || roundtrip != got {
		t.Fatal("metadata round trip", err)
	}
	if current, err := o.ObserveVPNSSO(ctx, b, VPNSSOFloor{RowVersion: 1}); err != nil || current != got {
		t.Fatal("weaker observation reset floor", err)
	}
	for _, bad := range []VPNSSOFloor{
		{RowVersion: math.MaxUint64},
		{Checkpoint: VPNSSOCheckpoint{Revision: 1}},
		{Checkpoint: VPNSSOCheckpoint{Revision: 1, Digest: b.RouteDigest}, RowVersion: 0},
	} {
		if _, err := o.ObserveVPNSSO(ctx, b, bad); err != vault.ErrFormat {
			t.Fatal("bad observation accepted", err)
		}
	}
	if _, err := o.ObserveVPNSSO(ctx, VPNSSOBinding{}, VPNSSOFloor{}); err != vault.ErrFormat {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.ObserveVPNSSO(canceled, b, VPNSSOFloor{}); err != context.Canceled {
		t.Fatal(err)
	}
	conflict := VPNSSOFloor{Checkpoint: VPNSSOCheckpoint{Revision: 1, Digest: b.RouteDigest}, RowVersion: 1}
	other := vpnSSOFixture()
	if _, err := o.ObserveVPNSSO(ctx, other, conflict); err != nil {
		t.Fatal(err)
	}
	conflict.Checkpoint.Digest[0] ^= 1
	if _, err := o.ObserveVPNSSO(ctx, other, conflict); err != vault.ErrRollback {
		t.Fatal("same-version checkpoint substitution", err)
	}
	for len(o.vpnSSOFloors) < maxVPNSSOFloors {
		o.vpnSSOFloors[uuid.NewString()] = VPNSSOFloor{}
	}
	if _, err := o.ObserveVPNSSO(ctx, vpnSSOFixture(), VPNSSOFloor{}); err != vault.ErrPolicy {
		t.Fatal("observation capacity bypass", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ObserveVPNSSO(ctx, b, minimum); err != vaultstore.ErrClosed {
		t.Fatal("closed owner imported floor", err)
	}
}

func TestVPNSSOCancellationRetainsAlreadyAuthenticatedManifest(t *testing.T) {
	o, path, opts, key := owner(t)
	b, ctx := vpnSSOFixture(), context.Background()
	id, _ := openVPNSSO(t, o, b, VPNSSOCheckpoint{})
	saveVPNSSO(t, o, b, id, []byte("encrypted SSO storage"))
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Create = false
	fresh, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	base := &browserStateProbe{Store: fresh.store, local: fresh.store.(vaultstore.LocalStateStore), policy: fresh.store.(vaultstore.ProfileStore)}
	canceled, cancel := context.WithCancel(ctx)
	fresh.store = vpnSSOCancelRead{base, cancel}
	if err := fresh.OpenVPNSSO(canceled, b, uuid.NewString(), VPNSSOCheckpoint{}, func(VPNSSOSnapshot) error { t.Fatal("late canceled archive released"); return nil }); err != context.Canceled {
		t.Fatal(err)
	}
	floor, err := fresh.ObserveVPNSSO(ctx, b, VPNSSOFloor{})
	if err != nil || floor.RowVersion != 1 || floor.Checkpoint.Revision != 0 {
		t.Fatal("cancellation erased authenticated observation", err)
	}
	base.missing = true
	fresh.store = base
	if err := fresh.OpenVPNSSO(ctx, b, uuid.NewString(), VPNSSOCheckpoint{}, func(VPNSSOSnapshot) error { t.Fatal("cancelled observation lost"); return nil }); err != vault.ErrRollback {
		t.Fatal(err)
	}
}

type vpnSSOManifestProbe struct {
	*browserStateProbe
	read bool
}

func (p *vpnSSOManifestProbe) ReadLocalState(ctx context.Context, kind, scope string) (vaultstore.LocalState, error) {
	if p.read {
		// A later metadata query is a different snapshot. The original manifest
		// and its ciphertext remain available; do not mix it with this answer.
		return vaultstore.LocalState{}, vaultstore.ErrConflict
	}
	p.read = true
	return p.browserStateProbe.ReadLocalState(ctx, kind, scope)
}

func TestVPNSSOUsesOneAuthenticatedManifestForBorrowedSnapshot(t *testing.T) {
	o, _, _, _ := owner(t)
	b, ctx := vpnSSOFixture(), context.Background()
	id, _ := openVPNSSO(t, o, b, VPNSSOCheckpoint{})
	c := saveVPNSSO(t, o, b, id, []byte("consistent native archive"))
	base := &browserStateProbe{Store: o.store, local: o.store.(vaultstore.LocalStateStore), policy: o.store.(vaultstore.ProfileStore)}
	o.store = &vpnSSOManifestProbe{browserStateProbe: base}
	if err := o.OpenVPNSSO(ctx, b, uuid.NewString(), c, func(s VPNSSOSnapshot) error {
		if string(s.Archive) != "consistent native archive" || s.Checkpoint != c {
			t.Fatal("snapshot mixed metadata reads")
		}
		return nil
	}); err != nil {
		t.Fatal("re-read mutable manifest instead of authenticating its chunks", err)
	}
}
