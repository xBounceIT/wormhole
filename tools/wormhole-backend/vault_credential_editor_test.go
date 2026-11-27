package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
	"golang.org/x/crypto/ssh"
)

func credentialEditorInput() map[string]any {
	return map[string]any{"rowVersion": "0", "password": []byte("original password"), "passphrase": []byte{}, "metadata": map[string]any{
		"id": "", "name": " Account ", "protocol": "ssh", "kind": "password", "username": "alice", "domain": "", "provider": "Local", "bitwardenItemId": "", "bitwardenItemName": "", "privateKeyPath": "", "certificatePath": "", "clearPassphrase": false, "clearCertificate": false,
	}}
}

func saveCredentialEditor(t *testing.T, h *vaultFoundationHandler, input map[string]any) vaultstore.Credential {
	t.Helper()
	raw, err := h.Handle(context.Background(), "credential-edit", vaultInput(t, input))
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		ID, RowVersion string
		Updated        bool
	}
	if json.Unmarshal(raw, &saved) != nil || !saved.Updated || !vaultCredentialID(saved.ID) {
		t.Fatal(string(raw))
	}
	c, err := h.owner.ReadCredential(context.Background(), saved.ID, 0)
	if err != nil || strconv.FormatUint(c.RowVersion, 10) != saved.RowVersion {
		t.Fatal(err)
	}
	input["rowVersion"] = saved.RowVersion
	input["metadata"].(map[string]any)["id"] = saved.ID
	return c
}

func TestVaultCredentialEditorPasswordsAndConflicts(t *testing.T) {
	ctx, h := context.Background(), vaultCredentialFixture(t)
	input := credentialEditorInput()
	saved := saveCredentialEditor(t, h, input)
	if saved.Name != "Account" {
		t.Fatal(saved.Name)
	}
	input["password"] = []byte{}
	metadata := input["metadata"].(map[string]any)
	metadata["name"] = "Renamed"
	updated := saveCredentialEditor(t, h, input)
	if updated.CreatedAt != saved.CreatedAt || !reflect.DeepEqual(updated.Fields, saved.Fields) {
		t.Fatal("metadata edit replaced secret/provenance")
	}
	if err := h.owner.WithCredentialSecret(ctx, saved.ID, "password", 2, func(p []byte) error {
		if string(p) != "original password" {
			t.Fatal("secret lost")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"0", "1", "9223372036854775807", "01", "bad"} {
		input["rowVersion"] = version
		if _, err := h.Handle(ctx, "credential-edit", vaultInput(t, input)); err == nil || h.closed {
			t.Fatal("stale/malformed write disposition", err)
		}
	}
	input["rowVersion"] = "2"
	metadata["kind"] = "sshKey"
	if _, err := h.Handle(ctx, "credential-edit", vaultInput(t, input)); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatal(err)
	}
	metadata["kind"], metadata["provider"], metadata["bitwardenItemId"] = "password", "Bitwarden", "external-item"
	saved = saveCredentialEditor(t, h, input)
	if saved.Provider != "bitwarden" || saved.Fields[0].Present {
		t.Fatal("provider switch retained password")
	}
	metadata["provider"], metadata["bitwardenItemId"] = "Local", ""
	if _, err := h.Handle(ctx, "credential-edit", vaultInput(t, input)); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("provider switch preserved absent password", err)
	}
	input["password"] = []byte("replacement")
	saveCredentialEditor(t, h, input)
	duplicate := credentialEditorInput()
	duplicate["metadata"].(map[string]any)["name"] = "Renamed"
	if _, err := h.Handle(ctx, "credential-edit", vaultInput(t, duplicate)); !errors.Is(err, vaultstore.ErrConflict) || h.closed {
		t.Fatal("duplicate name disposition", err)
	}
	metadata["id"] = uuid.NewString()
	if _, err := h.Handle(ctx, "credential-edit", vaultInput(t, input)); err == nil {
		t.Fatal("missing credential edited")
	}
}

func TestVaultCredentialEditorInputFailures(t *testing.T) {
	ctx, h := context.Background(), vaultCredentialFixture(t)
	for _, edit := range []func(map[string]any){
		func(q map[string]any) { delete(q, "metadata") },
		func(q map[string]any) { q["password"] = []int{1} },
		func(q map[string]any) { q["passphrase"] = nil },
		func(q map[string]any) { q["password"] = []byte{0xff} },
		func(q map[string]any) { q["password"] = bytes.Repeat([]byte{'a'}, 4097) },
		func(q map[string]any) { q["metadata"].(map[string]any)["ownerUserId"] = uuid.NewString() },
		func(q map[string]any) { q["metadata"].(map[string]any)["id"] = "bad"; q["rowVersion"] = "1" },
		func(q map[string]any) { q["metadata"].(map[string]any)["username"] = "" },
		func(q map[string]any) {
			q["metadata"].(map[string]any)["provider"] = "Bitwarden"
			q["metadata"].(map[string]any)["bitwardenItemId"] = "item"
			q["password"] = []byte{}
		},
	} {
		input := credentialEditorInput()
		edit(input)
		if _, err := h.Handle(ctx, "credential-edit", vaultInput(t, input)); !errors.Is(err, vaultwire.ErrProtocol) || h.closed {
			t.Fatal(err)
		}
	}
	if _, err := h.Handle(ctx, "credential-edit", make([]byte, 128*1024+1)); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal(err)
	}
	if _, err := (&vaultFoundationHandler{}).Handle(ctx, "credential-edit", vaultInput(t, credentialEditorInput())); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := h.Handle(canceled, "credential-edit", vaultInput(t, credentialEditorInput())); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestVaultCredentialEditorSSHFilesAndStoredFactors(t *testing.T) {
	ctx, h := context.Background(), vaultCredentialFixture(t)
	key := testSshPrivateKey(t, "phrase")
	signer, err := parseSSHSigner(key, []byte("phrase"))
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := testSSHCertificate(t, signer, ssh.UserCert, 0, ssh.CertTimeInfinity)
	keyPath, certPath := filepath.Join(t.TempDir(), "id_ed25519"), filepath.Join(t.TempDir(), "key-cert.pub")
	if os.WriteFile(keyPath, key, 0600) != nil || os.WriteFile(certPath, ssh.MarshalAuthorizedKey(cert), 0600) != nil {
		t.Fatal("fixture write")
	}
	input := credentialEditorInput()
	m := input["metadata"].(map[string]any)
	m["kind"], m["privateKeyPath"], m["certificatePath"] = "sshKey", keyPath, certPath
	input["password"], input["passphrase"] = []byte{}, []byte("phrase")
	saved := saveCredentialEditor(t, h, input)
	if saved.PrivateKeyName != "id_ed25519" || saved.CertificateName != "key-cert.pub" || len(saved.Fields) != 3 {
		t.Fatal("key fields missing", saved)
	}
	m["privateKeyPath"] = ""
	input["passphrase"] = []byte{}
	saveCredentialEditor(t, h, input) // Certificate replacement uses the native stored passphrase.
	m["certificatePath"] = ""
	input["passphrase"] = []byte("wrong")
	if _, err := h.Handle(ctx, "credential-edit", vaultInput(t, input)); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal(err)
	}
	input["passphrase"] = []byte("phrase")
	saveCredentialEditor(t, h, input)
	input["passphrase"] = []byte{}
	m["clearPassphrase"], m["clearCertificate"] = true, true
	saved = saveCredentialEditor(t, h, input)
	if saved.CertificateName != "" {
		t.Fatal("certificate name retained")
	}
	m["clearPassphrase"], m["clearCertificate"] = false, false
	if err := h.owner.WithCredentialSecret(ctx, saved.ID, "passphrase", saved.RowVersion, func([]byte) error { t.Fatal("removed passphrase released"); return nil }); !errors.Is(err, vaultstore.ErrMissing) {
		t.Fatal(err)
	}
	m["certificatePath"] = certPath
	saveCredentialEditor(t, h, input) // OpenSSH public half validates without saved passphrase.
	m["certificatePath"], m["privateKeyPath"] = "", keyPath
	saveCredentialEditor(t, h, input) // Retained certificate checked when replacing a key.
	if err := os.WriteFile(keyPath, testSshPrivateKey(t, ""), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "credential-edit", vaultInput(t, input)); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("mismatched retained certificate accepted", err)
	}
	m["clearCertificate"] = true
	saveCredentialEditor(t, h, input)
	for _, path := range []string{filepath.Join(t.TempDir(), "missing"), t.TempDir()} {
		m["privateKeyPath"] = path
		if _, err := h.Handle(ctx, "credential-edit", vaultInput(t, input)); !errors.Is(err, vaultwire.ErrProtocol) {
			t.Fatal(err)
		}
	}
	m["privateKeyPath"], m["clearCertificate"], m["certificatePath"] = "", false, filepath.Join(t.TempDir(), "missing")
	if _, err := h.Handle(ctx, "credential-edit", vaultInput(t, input)); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal(err)
	}
	// A malformed legacy manifest without a key must not be silently preserved.
	missing := vaultstore.CredentialMetadata{ID: uuid.NewString(), Name: "Missing key", Kind: "sshKey", Protocol: "ssh", Provider: "local", Username: "alice"}
	if _, err := h.owner.PutCredential(ctx, missing, []localvault.SecretChange{}, 0); err != nil {
		t.Fatal(err)
	}
	m["id"], m["certificatePath"], input["rowVersion"] = missing.ID, "", "1"
	if _, err := h.Handle(ctx, "credential-edit", vaultInput(t, input)); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal(err)
	}
}

func TestVaultEditorKeyValidation(t *testing.T) {
	plain, encrypted := testSshPrivateKey(t, ""), testSshPrivateKey(t, "phrase")
	for _, q := range []struct {
		key, password []byte
		valid         bool
	}{{plain, nil, true}, {plain, []byte("bad"), false}, {encrypted, nil, true}, {encrypted, []byte("phrase"), true}, {encrypted, []byte("wrong"), false}, {[]byte("invalid"), nil, false}} {
		if (validateVaultEditorKey(q.key, q.password) == nil) != q.valid {
			t.Fatal("key validation mismatch")
		}
	}
}
