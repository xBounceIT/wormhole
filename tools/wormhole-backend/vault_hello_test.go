package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type helloHandlerCredential struct {
	key         *rsa.PrivateKey
	signatures  int
	attestation vault.HelloAttestation
}

func (c *helloHandlerCredential) PublicKey() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&c.key.PublicKey)
}
func (c *helloHandlerCredential) Attestation(_ context.Context, public *rsa.PublicKey) (vault.HelloAttestation, error) {
	if !c.key.PublicKey.Equal(public) {
		return "", vault.ErrAuthentication
	}
	if c.attestation != "" {
		return c.attestation, nil
	}
	return vault.HelloAttestationUnsupported, nil
}
func (c *helloHandlerCredential) Sign(_ context.Context, challenge []byte) ([]byte, error) {
	c.signatures++
	digest := sha256.Sum256(challenge)
	return rsa.SignPKCS1v15(nil, c.key, crypto.SHA256, digest[:])
}

func TestVaultHelloRecordsVerifiedTPMOnlyInVersion7(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "workspace.db")
	password, recovery := []byte("fixture-vault-password"), bytes.Repeat([]byte{71}, 32)
	h := &vaultFoundationHandler{databasePath: path}
	t.Cleanup(func() { _ = h.Close() })
	if _, err := h.Handle(ctx, "initialize", vaultInput(t, map[string]any{"password": password, "recoveryKey": recovery})); err != nil {
		t.Fatal(err)
	}
	doc, err := readVaultSlotFile(path)
	if err != nil {
		t.Fatal(err)
	}
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	credential := &helloHandlerCredential{key: private, attestation: vault.HelloAttestationTPMVerified}
	h.helloOperation = func(_ context.Context, _ string, _ uintptr, _ bool, use func(vault.HelloCredential) error) error {
		return use(credential)
	}
	raw := vaultInput(t, map[string]any{
		"operation": "hello-enroll", "action": []byte(`{"ownerWindow":"1107"}`),
		"authentication": []byte(vaultInput(t, map[string]any{"vaultId": doc.VaultID, "slotId": doc.Slots[0].ID, "password": password})),
	})
	if reply, err := h.Handle(ctx, "fresh-action", raw); err != nil || string(reply) != `{"enrolled":true}` || credential.signatures != 2 {
		t.Fatal("attested enrollment skipped deterministic proof or failed to publish", err)
	}
	updated, err := readVaultSlotFile(path)
	if err != nil || updated.FormatVersion != vault.SlotFileTPMAttestationVersion || len(updated.Slots) != 3 || updated.Slots[2].Hello == nil || updated.Slots[2].Hello.Attestation != vault.HelloAttestationTPMVerified {
		t.Fatal("expected separately versioned attestation metadata", err)
	}
	if reply, err := h.Handle(ctx, "describe", nil); err != nil || bytes.Contains(reply, []byte("tpm-verified")) || !bytes.Contains(reply, []byte(`"formatVersion":7`)) {
		t.Fatal("descriptor leaked the provider result or lost the supported version", err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	h = &vaultFoundationHandler{databasePath: path}
	if _, err := h.Handle(ctx, "unlock", vaultInput(t, map[string]any{"vaultId": doc.VaultID, "slotId": doc.Slots[1].ID, "recoveryKey": recovery})); err != nil || h.owner == nil {
		t.Fatal("attestation changed the independent software recovery path", err)
	}
}

func TestVaultHelloNativeActionsKeepPasswordAndRecoveryAcrossRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "workspace.db")
	password, recovery := []byte("fixture-vault-password"), bytes.Repeat([]byte{71}, 32)
	h := &vaultFoundationHandler{databasePath: path}
	t.Cleanup(func() { _ = h.Close() })
	if _, err := h.Handle(ctx, "initialize", vaultInput(t, map[string]any{"password": password, "recoveryKey": recovery})); err != nil {
		t.Fatal(err)
	}
	document, err := readVaultSlotFile(path)
	if err != nil {
		t.Fatal(err)
	}
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	credential := &helloHandlerCredential{key: private}
	stageFailure := errors.New("atomic writer rejected the checkpoint")
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	var publications int
	persist := func(next vault.SlotFile, root []byte) error {
		publications++
		if next.Sequence != document.Sequence+1 || len(root) != 32 {
			t.Fatal("enrollment proposed an invalid atomic write")
		}
		return stageFailure
	}
	if err := h.owner.EnrollHelloSlot(cancelled, document, uuid.NewString(), credential, persist); err != context.Canceled || publications != 0 {
		t.Fatal("a canceled request reached slot publication", err)
	}
	if err := h.owner.EnrollHelloSlot(ctx, document, uuid.NewString(), nil, persist); !errors.Is(err, vault.ErrFormat) || publications != 0 {
		t.Fatal("a missing credential reached slot publication", err)
	}
	tampered := document
	tampered.Authentication = bytes.Clone(document.Authentication)
	tampered.Authentication[0] ^= 1
	if err := h.owner.EnrollHelloSlot(ctx, tampered, uuid.NewString(), credential, persist); err != vault.ErrAuthentication || credential.signatures != 0 {
		t.Fatal("an unauthenticated slot file invoked a hardware proof", err)
	}
	wrongRoot := document
	wrongRoot.RootKeyID = uuid.NewString()
	if err := h.owner.EnrollHelloSlot(ctx, wrongRoot, uuid.NewString(), credential, persist); err != vault.ErrAuthentication || credential.signatures != 0 {
		t.Fatal("a different root identity invoked a hardware proof", err)
	}
	initializing := document
	initializing.Initializing = true
	if err := h.owner.EnrollHelloSlot(ctx, initializing, uuid.NewString(), credential, persist); err != vault.ErrPolicy || credential.signatures != 0 {
		t.Fatal("a partial vault initialization invoked a hardware proof", err)
	}
	if err := h.owner.EnrollHelloSlot(ctx, document, uuid.NewString(), credential, persist); err != stageFailure || publications != 1 {
		t.Fatal("enrollment returned success after its write failed", err)
	}
	if stored, err := readVaultSlotFile(path); err != nil || stored.Sequence != document.Sequence || len(stored.Slots) != 2 {
		t.Fatal("failed publication changed the active slot file", err)
	}
	credential.signatures = 0
	var name string
	var opened bool
	provider := func(ctx context.Context, keyName string, owner uintptr, create bool, use func(vault.HelloCredential) error) error {
		if owner != 1107 || ctx.Err() != nil || !strings.HasPrefix(keyName, "WormholeVault-"+document.VaultID+"-") {
			t.Fatal("the native provider received an unbound owner or slot")
		}
		if create {
			if name != "" {
				t.Fatal("a second enrollment opened the provider")
			}
			name = keyName
		} else {
			if keyName != name || opened {
				t.Fatal("unlock substituted or reused the selected key")
			}
			opened = true
		}
		return use(credential)
	}
	h.helloOperation = provider
	action := []byte(`{"ownerWindow":"1107"}`)
	if _, err := h.Handle(ctx, "hello-enroll", action); err != vault.ErrPolicy || name != "" {
		t.Fatal("running as the unlocked user bypassed the fresh factor", err)
	}
	elevate := func(password []byte) json.RawMessage {
		return vaultInput(t, map[string]any{"operation": "hello-enroll", "action": action,
			"authentication": []byte(vaultInput(t, map[string]any{"vaultId": document.VaultID, "slotId": document.Slots[0].ID, "password": password}))})
	}
	if _, err := h.Handle(ctx, "fresh-action", elevate([]byte("incorrect"))); err != vault.ErrAuthentication || name != "" {
		t.Fatal("incorrect password invoked the provider", err)
	}
	validAction := action
	action = []byte(`{"ownerWindow":"0"}`)
	if _, err := h.Handle(ctx, "fresh-action", elevate(password)); err != vaultwire.ErrProtocol || name != "" {
		t.Fatal("an invalid prompt owner triggered a hardware action", err)
	}
	action = validAction
	if reply, err := h.Handle(ctx, "fresh-action", elevate(password)); err != nil || string(reply) != `{"enrolled":true}` || credential.signatures != 2 {
		t.Fatal("fresh software authentication did not enroll the verified Hello factor", err)
	}
	updated, err := readVaultSlotFile(path)
	if err != nil || updated.Sequence != document.Sequence+1 || updated.FormatVersion != vault.SlotFileHelloVersion || len(updated.Slots) != 3 ||
		updated.Slots[0].Kind != vault.SlotPassword || updated.Slots[1].Kind != vault.SlotRecovery || updated.Slots[2].Kind != vault.SlotHello {
		t.Fatal("Hello did not publish an optional persisted slot", err)
	}
	if _, err := h.Handle(ctx, "fresh-action", elevate(password)); err != vault.ErrPolicy || credential.signatures != 2 {
		t.Fatal("an existing slot was replaced without an explicit removal", err)
	}
	if err := h.owner.EnrollHelloSlot(ctx, updated, uuid.NewString(), credential, persist); !errors.Is(err, vault.ErrPolicy) || credential.signatures != 2 {
		t.Fatal("the slot writer accepted a duplicate hardware factor", err)
	}
	request := func(slot string) []byte {
		return vaultInput(t, map[string]any{"vaultId": updated.VaultID, "slotId": slot, "ownerWindow": "1107"})
	}
	competing := &vaultFoundationHandler{databasePath: path, helloOperation: provider}
	defer competing.Close()
	if _, err := competing.Handle(ctx, "hello-unlock", request(updated.Slots[2].ID)); err == nil || opened || competing.owner != nil {
		t.Fatal("competing owners could invoke Hello for the same vault", err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	h = &vaultFoundationHandler{databasePath: path, helloOperation: provider}
	if _, err := h.Handle(ctx, "hello-unlock", json.RawMessage(`{}`)); err != vaultwire.ErrProtocol || opened {
		t.Fatal("an incomplete request opened Hello", err)
	}
	if _, err := h.Handle(ctx, "hello-unlock", vaultInput(t, map[string]any{"vaultId": uuid.NewString(), "slotId": updated.Slots[2].ID, "ownerWindow": "1107"})); err != vault.ErrPolicy || opened {
		t.Fatal("an unrelated workspace gained the hardware prompt", err)
	}
	if _, err := h.Handle(ctx, "hello-unlock", request(updated.Slots[0].ID)); err != vault.ErrAuthentication || opened || h.owner != nil {
		t.Fatal("Hello opened a software slot", err)
	}
	h.helloOperation = func(context.Context, string, uintptr, bool, func(vault.HelloCredential) error) error {
		return errVaultHelloCanceled
	}
	if result, err := h.Handle(ctx, "hello-unlock", request(updated.Slots[2].ID)); err != nil || string(result) != `{"status":"canceled"}` || h.owner != nil || h.closed {
		t.Fatal("a canceled native prompt opened or permanently retired the vault", err)
	}
	h.helloOperation = provider
	if reply, err := h.Handle(ctx, "hello-unlock", request(updated.Slots[2].ID)); err != nil || string(reply) != `{"unlocked":true,"lockedMemory":true}` || !opened || h.owner == nil || credential.signatures != 3 {
		t.Fatal("the registered key did not regain its native vault after restart", err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	h = &vaultFoundationHandler{databasePath: path}
	if _, err := h.Handle(ctx, "unlock", vaultInput(t, map[string]any{"vaultId": updated.VaultID, "slotId": updated.Slots[1].ID,
		"recoveryKey": recovery})); err != nil || h.owner == nil {
		t.Fatal("adding Hello removed the independent recovery path", err)
	}
	removed := 0
	h.helloRemove = func(_ context.Context, key string) bool {
		if key != name {
			t.Fatal("removal chose a different native credential")
		}
		removed++
		return false
	}
	removeAction := func(id string) []byte { return vaultInput(t, map[string]any{"slotId": id}) }
	remove := func(id string, key []byte) []byte {
		return vaultInput(t, map[string]any{"operation": "hello-remove", "action": removeAction(id),
			"authentication": []byte(vaultInput(t, map[string]any{"vaultId": updated.VaultID, "slotId": updated.Slots[1].ID, "recoveryKey": key}))})
	}
	hello := updated.Slots[2].ID
	if _, err := h.Handle(ctx, "hello-remove", removeAction(hello)); !errors.Is(err, vault.ErrPolicy) || removed != 0 {
		t.Fatal("removal bypassed fresh authentication", err)
	}
	if _, err := h.Handle(ctx, "fresh-action", remove("invalid", recovery)); !errors.Is(err, vaultwire.ErrProtocol) || removed != 0 {
		t.Fatal("invalid slot identifier triggered native removal", err)
	}
	if _, err := h.Handle(ctx, "fresh-action", remove(hello, bytes.Repeat([]byte{72}, 32))); !errors.Is(err, vault.ErrAuthentication) || removed != 0 {
		t.Fatal("incorrect recovery key triggered native cleanup", err)
	}
	if _, err := h.Handle(ctx, "fresh-action", remove(updated.Slots[0].ID, recovery)); !errors.Is(err, vault.ErrPolicy) || removed != 0 {
		t.Fatal("removal accepted a software slot", err)
	}
	if reply, err := h.Handle(ctx, "fresh-action", remove(hello, recovery)); err != nil || string(reply) != `{"removed":true,"keyDeleted":false}` || removed != 1 {
		t.Fatal("slot removal failed when the OS credential could not be removed", err)
	}
	after, err := readVaultSlotFile(path)
	if err != nil || after.Sequence != updated.Sequence+1 || len(after.Slots) != 2 ||
		after.Slots[0].ID != updated.Slots[0].ID || after.Slots[1].ID != updated.Slots[1].ID {
		t.Fatal("removal did not preserve the independent software slots", err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	h = &vaultFoundationHandler{databasePath: path, helloOperation: func(context.Context, string, uintptr, bool, func(vault.HelloCredential) error) error {
		t.Fatal("removed slot invoked a platform prompt")
		return nil
	}}
	if _, err := h.Handle(ctx, "hello-unlock", request(hello)); !errors.Is(err, vault.ErrAuthentication) || h.owner != nil {
		t.Fatal("removed slot could still open the vault", err)
	}
	if _, err := h.Handle(ctx, "unlock", vaultInput(t, map[string]any{"vaultId": updated.VaultID, "slotId": updated.Slots[0].ID,
		"password": password})); err != nil || h.owner == nil {
		t.Fatal("removing Hello broke password unlock", err)
	}
}

func TestVaultHelloPublicDispositions(t *testing.T) {
	for _, row := range []struct {
		err    error
		status string
	}{
		{errVaultHelloRemote, "remote-desktop"},
		{errVaultHelloCanceled, "canceled"},
		{errVaultHelloUnavailable, "unavailable"},
		{vault.ErrHelloNondeterministic, "not-repeatable"},
	} {
		data, err := helloReply(nil, errors.Join(errors.New("provider diagnostic"), row.err))
		if err != nil || string(data) != `{"status":"`+row.status+`"}` {
			t.Fatalf("unexpected disposition for %s: %q, %v", row.status, data, err)
		}
	}
	if data, err := helloReply(nil, vault.ErrAuthentication); !errors.Is(err, vault.ErrAuthentication) || len(data) != 0 {
		t.Fatal("an ordinary authentication failure became native status data", err)
	}
	if _, err := vaultHelloAvailability(context.Background(), []byte(`{"ownerWindow":"57"}`)); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("a capability probe accepted a credential owner", err)
	}
}

func TestVaultHelloInputIsMetadataOnly(t *testing.T) {
	vaultID, slot := uuid.NewString(), uuid.NewString()
	valid := map[string]any{"vaultId": vaultID, "slotId": slot, "ownerWindow": "1107"}
	for _, input := range []map[string]any{
		{"vaultId": vaultID, "slotId": slot, "ownerWindow": "01107"},
		{"vaultId": vaultID, "slotId": slot, "ownerWindow": 1107},
		{"vaultId": uuid.Nil.String(), "slotId": slot, "ownerWindow": "1107"},
		{"vaultId": vaultID, "slotId": slot, "ownerWindow": "0"},
		{"vaultId": vaultID, "slotId": slot, "ownerWindow": "1107", "signature": "fixture"},
		{"vaultId": vaultID, "ownerWindow": "1107"},
	} {
		if _, _, err := decodeVaultHello(vaultInput(t, input), false); !errors.Is(err, vaultwire.ErrProtocol) {
			t.Fatal("unexpected Hello input accepted", err)
		}
	}
	if _, owner, err := decodeVaultHello(vaultInput(t, valid), false); err != nil || owner != 1107 {
		t.Fatal("the protected window was rejected", err)
	}
	missing := &vaultFoundationHandler{databasePath: filepath.Join(t.TempDir(), "workspace.db")}
	defer missing.Close()
	if _, err := missing.Handle(context.Background(), "hello-unlock", vaultInput(t, valid)); err != errVaultSlotMissing || missing.owner != nil {
		t.Fatal("hardware unlock could initialize a missing vault", err)
	}
}
