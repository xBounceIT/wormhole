package localvault

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/binary"
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"strconv"
	"testing"
)

func openCredentialDisplay(t *testing.T, key *ecdh.PrivateKey, result CredentialDisplay) []byte {
	return openCredentialPurpose(t, key, result, "wormhole/v1/credential-display")
}
func openClipboardRelease(t *testing.T, key *ecdh.PrivateKey, result NotesDisplay, field string) []byte {
	return openCredentialPurpose(t, key, result, "wormhole/v1/clipboard/"+field)
}
func openCredentialPurpose(t *testing.T, key *ecdh.PrivateKey, result NotesDisplay, purpose string) []byte {
	t.Helper()
	info := []byte(purpose)
	for _, v := range []string{result.WorkspaceID, result.NodeID, result.RequestID, result.RowVersion} {
		info = binary.BigEndian.AppendUint32(info, uint32(len(v)))
		info = append(info, []byte(v)...)
	}
	private, _ := hpke.NewDHKEMPrivateKey(key)
	recipient, err := hpke.NewRecipient(result.Bundle.Enc, private, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := recipient.Open(nil, result.Bundle.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	return plain
}
func TestCredentialDisplayResolvedSecrets(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	n, _, c, _ := resolutionFixture(t, o)
	check := func(n vaultstore.Node, username, domain, secret string, passphrase bool) {
		t.Helper()
		result, err := o.SealConnectionCredentials(ctx, n.ID, uuid.NewString(), n.RowVersion, key.PublicKey().Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if result.NodeID != n.ID || result.RowVersion != strconv.FormatUint(n.RowVersion, 10) {
			t.Fatal("binding")
		}
		plain := openCredentialDisplay(t, key, result)
		defer vault.Wipe(plain)
		want, err := vault.EncodeCredentialDisplay(vault.CredentialDisplayPayload{Username: username, Domain: domain, Secret: []byte(secret), Passphrase: passphrase})
		if err != nil {
			t.Fatal(err)
		}
		defer vault.Wipe(want)
		if !bytes.Equal(plain, want) {
			t.Fatal("wrong account or secret")
		}
		for field, expected := range map[string]string{"username": username, "domain": domain, "secret": secret} {
			sealed, sealErr := o.SealConnectionClipboard(ctx, n.ID, uuid.NewString(), n.RowVersion, field, 30, key.PublicKey().Bytes())
			if expected == "" {
				if sealErr != vault.ErrFormat {
					t.Fatal("empty sealed clipboard", sealErr)
				}
			} else {
				if sealErr != nil {
					t.Fatal(sealErr)
				}
				plain := openClipboardRelease(t, key, sealed, field)
				if !bytes.Equal(plain, append([]byte{1, 30}, []byte(expected)...)) {
					t.Fatal("wrong sealed field")
				}
				vault.Wipe(plain)
			}
			var borrowed []byte
			if err := o.CopyConnectionCredential(ctx, n.ID, n.RowVersion, field, func(value []byte) error {
				borrowed = value
				if string(value) != expected {
					t.Fatal("wrong copied field", field)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("copy retained borrowed secret")
			}
		}

	}
	check(n, "user", "", "selected-password", false)
	n.Protocol = nodePtr(0)
	var err error
	n, err = o.PutNode(ctx, n.NodeMetadata, nil, n.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	n, _ = installAccountMigration(t, o, n, map[string]resolver.EffectiveCredentialSnapshot{"reveal": {SourceKind: "saved", CredentialID: c.ID, Username: "historical", Domain: "CORP"}})
	check(n, "historical", "CORP", "selected-password", false)
	md := c.CredentialMetadata
	md.Kind = "sshKey"
	c, err = o.PutCredential(ctx, md, []SecretChange{{Field: "password", Remove: true}, {Field: "passphrase", Value: []byte("key passphrase")}, {Field: "privateKey", Value: []byte("private key never reveal")}}, c.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	check(n, "historical", "CORP", "key passphrase", true)
	c, err = o.PutCredential(ctx, c.CredentialMetadata, []SecretChange{{Field: "passphrase", Remove: true}}, c.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	check(n, "historical", "CORP", "", true)
	inline := nodeDraft()
	inline.UseInlinePassword = nodePtr(true)
	inline.Username = nodePtr("inline-user")
	leaf, err := o.PutNode(ctx, inline, []SecretChange{{Field: "inlinePassword", Value: []byte("inline-secret")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	check(leaf, "inline-user", "", "inline-secret", false)
	empty, err := o.PutNode(ctx, nodeDraft(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	r, err := o.ResolveConnectionPath(ctx, empty.ID, "", "reveal")
	if err != nil {
		t.Fatal(err)
	}
	check(empty, r.Account.Username, r.Account.Domain, "", false)
}
func TestCredentialDisplayRejectsStaleCorruptAndUnavailable(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	n, _, c, _ := resolutionFixture(t, o)
	for _, revision := range []uint64{0, 2} {
		if _, err := o.SealConnectionCredentials(ctx, n.ID, uuid.NewString(), revision, key.PublicKey().Bytes()); err != vaultstore.ErrConflict {
			t.Fatal(err)
		}
	}
	if _, err := o.SealConnectionCredentials(ctx, uuid.NewString(), uuid.NewString(), 1, key.PublicKey().Bytes()); err == nil {
		t.Fatal("missing")
	}
	if _, err := o.SealConnectionCredentials(ctx, n.ID, uuid.NewString(), 1, nil); err == nil {
		t.Fatal("bad key")
	}
	original := o.store.(completeNodeStore)
	o.store = nodeFilter{completeNodeStore: original, read: func(v vaultstore.Node) (vaultstore.Node, error) { v.Seal = nil; return v, nil }}
	if _, err := o.SealConnectionCredentials(ctx, n.ID, uuid.NewString(), 1, key.PublicKey().Bytes()); err == nil {
		t.Fatal("tamper")
	}
	o.store = original
	o.nodeFloors[n.ID] = 2
	if _, err := o.SealConnectionCredentials(ctx, n.ID, uuid.NewString(), 1, key.PublicKey().Bytes()); err != vault.ErrRollback {
		t.Fatal(err)
	}
	o.nodeFloors[n.ID] = 1
	c, err := o.PutCredential(ctx, c.CredentialMetadata, []SecretChange{{Field: "password", Value: []byte{255}}}, c.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.SealConnectionCredentials(ctx, n.ID, uuid.NewString(), 1, key.PublicKey().Bytes()); err != vault.ErrFormat {
		t.Fatal("invalid text", err)
	}
	md := c.CredentialMetadata
	md.Provider = "bitwarden"
	md.BitwardenItemID = "external"
	_, err = o.PutCredential(ctx, md, []SecretChange{{Field: "password", Remove: true}}, c.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.SealConnectionCredentials(ctx, n.ID, uuid.NewString(), 1, key.PublicKey().Bytes()); err != vault.ErrPolicy {
		t.Fatal("external", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := o.SealConnectionCredentials(ctx, n.ID, uuid.NewString(), 1, key.PublicKey().Bytes()); err == nil {
		t.Fatal("closed")
	}
}

func TestCredentialCopyValidationAndCallbackFailure(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	n, _, c, _ := resolutionFixture(t, o)
	calls := 0
	sink := func([]byte) error { calls++; return vault.ErrPolicy }
	if err := o.CopyConnectionCredential(ctx, n.ID, n.RowVersion, "privateKey", sink); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if err := o.CopyConnectionCredential(ctx, n.ID, n.RowVersion+1, "secret", sink); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("invalid copy released")
	}
	if err := o.CopyConnectionCredential(ctx, n.ID, n.RowVersion, "secret", sink); err != vault.ErrPolicy || calls != 1 {
		t.Fatal(err)
	}
	original := o.store.(integrityStore)
	reads := 0
	o.store = integrityProbe{integrityStore: original, secret: func(value vaultstore.Secret) (vaultstore.Secret, error) { reads++; return value, vault.ErrPolicy }}
	if err := o.CopyConnectionCredential(ctx, n.ID, n.RowVersion, "username", func([]byte) error { return nil }); err != nil || reads != 0 {
		t.Fatal("identity copy read a stored secret", err)
	}
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := o.SealConnectionClipboard(ctx, n.ID, uuid.NewString(), n.RowVersion, "username", 20, key.PublicKey().Bytes()); err != nil || reads != 0 {
		t.Fatal("sealed identity read password", err)
	}
	if err := o.CopyConnectionCredential(ctx, n.ID, n.RowVersion, "secret", sink); err != vault.ErrPolicy || reads != 1 {
		t.Fatal("secret read probe ineffective", err)
	}
	o.store = original
	// Corrupt UTF-8 password is irrelevant to an identity-only copy.
	if _, err := o.PutCredential(ctx, c.CredentialMetadata, []SecretChange{{Field: "password", Value: []byte{255}}}, c.RowVersion); err != nil {
		t.Fatal(err)
	}
	if err := o.CopyConnectionCredential(ctx, n.ID, n.RowVersion, "username", func(value []byte) error {
		if string(value) != "user" {
			t.Fatal("identity")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := o.CopyConnectionCredential(cancelled, n.ID, n.RowVersion, "secret", sink); err == nil {
		t.Fatal("cancelled")
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if err := o.CopyConnectionCredential(ctx, n.ID, n.RowVersion, "secret", sink); err == nil {
		t.Fatal("closed")
	}
}

func TestClipboardReleaseRejectsStaleAndClosedOwner(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	n, _, _, _ := resolutionFixture(t, o)
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	for _, tc := range []struct {
		version uint64
		field   string
		ttl     int
		key     []byte
	}{{n.RowVersion + 1, "secret", 20, key.PublicKey().Bytes()}, {n.RowVersion, "privateKey", 20, key.PublicKey().Bytes()}, {n.RowVersion, "secret", 19, key.PublicKey().Bytes()}, {n.RowVersion, "secret", 20, nil}} {
		if result, err := o.SealConnectionClipboard(ctx, n.ID, uuid.NewString(), tc.version, tc.field, tc.ttl, tc.key); err == nil || result.WorkspaceID != "" {
			t.Fatal("invalid release")
		}
	}
	o.Close()
	if _, err := o.SealConnectionClipboard(ctx, n.ID, uuid.NewString(), n.RowVersion, "secret", 20, key.PublicKey().Bytes()); err == nil {
		t.Fatal("closed")
	}
}
