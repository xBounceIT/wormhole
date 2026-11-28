package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func inviteCopySet(t *testing.T, n int) (InviteContext, *InviteBootstrap, []KeyCopyBinding, []SignedKeyCopy, map[KeyRef]ed25519.PublicKey) {
	t.Helper()
	_, c, b, _ := inviteFixture(t)
	public, _ := (&UserKeys{EncryptionPrivate: b.EncryptionPrivate, SigningSeed: b.SigningSeed}).Public()
	issuer := KeyRef{uuid.New(), 1}
	bindings := make([]KeyCopyBinding, n)
	copies := make([]SignedKeyCopy, n)
	for i := range bindings {
		bindings[i] = KeyCopyBinding{WorkspaceID: c.WorkspaceID, Key: KeyRef{uuid.New(), 1}, Holder: KeyRef{c.KeyID, c.KeyVersion}, Issuer: issuer}
		var err error
		copies[i], err = SealKeyCopy(bytes.Repeat([]byte{byte(i + 1)}, 32), bindings[i], public.Encryption, b.SigningSeed)
		if err != nil {
			t.Fatal(err)
		}
	}
	return c, b, bindings, copies, map[KeyRef]ed25519.PublicKey{issuer: public.Signing}
}

func TestInviteRewrapCompleteSetAndRetirement(t *testing.T) {
	c, b, expected, copies, issuers := inviteCopySet(t, 3)
	plan, err := PrepareInviteRewrap(context.Background(), c, b, expected, copies, issuers)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Wipe()
	old, _ := (&UserKeys{EncryptionPrivate: b.EncryptionPrivate, SigningSeed: b.SigningSeed}).Public()
	if VerifyInviteRekey(c, plan.Proof, old) != nil || len(plan.Copies) != len(expected) {
		t.Fatal("invalid complete plan")
	}
	for i, row := range plan.Copies {
		if row.Binding.WorkspaceID != expected[i].WorkspaceID || row.Binding.Key != expected[i].Key {
			t.Fatal("source identity changed")
		}
		if row.Binding.Holder.ID != plan.Proof.EncryptionKeyID || row.Binding.Issuer.ID != plan.Proof.SigningKeyID {
			t.Fatal("replacement identity mismatch")
		}
		key, err := OpenKeyCopy(plan.Keys.EncryptionPrivate, row.Binding, row.Copy, plan.Proof.Public.Signing)
		if err != nil || !bytes.Equal(key, bytes.Repeat([]byte{byte(i + 1)}, 32)) {
			t.Fatalf("replacement %d: %v", i, err)
		}
		Wipe(key)
	}
	raw, _ := json.Marshal(plan)
	if bytes.Contains(raw, []byte(`"Keys"`)) || bytes.Contains(raw, []byte(`"keys"`)) {
		t.Fatal("private material serialized")
	}
	enc, sign := plan.Keys.EncryptionPrivate, plan.Keys.SigningSeed
	plan.Wipe()
	plan.Wipe()
	(*InviteRewrapPlan)(nil).Wipe()
	if !bytes.Equal(enc, make([]byte, 32)) || !bytes.Equal(sign, make([]byte, 32)) || plan.Keys != nil || plan.Copies != nil || plan.Proof.FormatVersion != 0 {
		t.Fatal("plan not retired")
	}
	if len(b.EncryptionPrivate) != 32 {
		t.Fatal("bootstrap retired before transaction")
	}
}

func TestInviteRewrapRejectsIncompleteDuplicateAndUntrustedSet(t *testing.T) {
	c, b, expected, copies, issuers := inviteCopySet(t, 2)
	for _, badCopies := range [][]SignedKeyCopy{copies[:1], append(append([]SignedKeyCopy(nil), copies...), copies[0]), {copies[1], copies[0]}} {
		if plan, err := PrepareInviteRewrap(context.Background(), c, b, expected, badCopies, issuers); err == nil || plan != nil {
			t.Fatal("incomplete/reordered set accepted")
		}
	}
	for _, change := range []func([]KeyCopyBinding){func(v []KeyCopyBinding) { v[1] = v[0] }, func(v []KeyCopyBinding) { v[0].WorkspaceID = uuid.New() }, func(v []KeyCopyBinding) { v[0].Holder.ID = uuid.New() }, func(v []KeyCopyBinding) { v[0].Holder.Version++ }, func(v []KeyCopyBinding) { v[0].Key.Version = 0 }, func(v []KeyCopyBinding) { v[0].Issuer = KeyRef{uuid.New(), 1} }} {
		bad := append([]KeyCopyBinding(nil), expected...)
		change(bad)
		if plan, err := PrepareInviteRewrap(context.Background(), c, b, bad, copies, issuers); err != ErrFormat || plan != nil {
			t.Fatal("invalid expected set accepted")
		}
	}
	for _, change := range []func(*SignedKeyCopy){func(c *SignedKeyCopy) { c.Signature = nil }, func(c *SignedKeyCopy) { c.Envelope.Enc = nil }, func(c *SignedKeyCopy) { c.Signature = make([]byte, 64) }} {
		bad := append([]SignedKeyCopy(nil), copies...)
		change(&bad[1])
		if plan, err := PrepareInviteRewrap(context.Background(), c, b, expected, bad, issuers); err == nil || plan != nil {
			t.Fatal("partial result returned after bad second copy")
		}
	}
	if plan, err := PrepareInviteRewrap(context.Background(), c, nil, expected, copies, issuers); err != ErrFormat || plan != nil {
		t.Fatal("missing bootstrap accepted")
	}
	if plan, err := PrepareInviteRewrap(context.Background(), c, b, expected, copies, nil); err != ErrFormat || plan != nil {
		t.Fatal("missing issuers accepted")
	}
	// Failure does not consume the source; a corrected retry can still succeed.
	plan, err := PrepareInviteRewrap(context.Background(), c, b, expected, copies, issuers)
	if err != nil {
		t.Fatal(err)
	}
	plan.Wipe()
}

func TestInviteRewrapCancellationBoundsAndEmptyGraph(t *testing.T) {
	c, b, expected, copies, issuers := inviteCopySet(t, MaxInviteKeyCopies)
	if plan, err := PrepareInviteRewrap(nil, c, b, nil, nil, nil); err != ErrFormat || plan != nil {
		t.Fatal("nil context accepted")
	}
	if plan, err := PrepareInviteRewrap(context.Background(), c, b, make([]KeyCopyBinding, MaxInviteKeyCopies+1), make([]SignedKeyCopy, MaxInviteKeyCopies+1), nil); err != ErrFormat || plan != nil {
		t.Fatal("unbounded set accepted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if plan, err := PrepareInviteRewrap(canceled, c, b, expected, copies, issuers); err != context.Canceled || plan != nil {
		t.Fatal("canceled operation accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := time.AfterFunc(5*time.Millisecond, cancel)
	defer stop.Stop()
	if plan, err := PrepareInviteRewrap(ctx, c, b, expected, copies, issuers); err != context.Canceled || plan != nil {
		if plan != nil {
			plan.Wipe()
		}
		t.Fatalf("cancellation during batch: %v", err)
	}
	// A separately authenticated empty graph is valid for a user with no grants.
	plan, err := PrepareInviteRewrap(context.Background(), c, b, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Wipe()
	if len(plan.Copies) != 0 || plan.Keys == nil {
		t.Fatal("empty graph did not rekey")
	}
}
