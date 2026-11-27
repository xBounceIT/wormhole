package vault

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestOrganisationRecoveryRequiresOfflineKeyAndExpectedIdentity(t *testing.T) {
	key := NewRecoveryKey()
	defer Wipe(key)
	keys := &UserKeys{EncryptionPrivate: NewRecoveryKey(), SigningSeed: NewRecoveryKey()}
	defer keys.Wipe()
	public, err := keys.Public()
	if err != nil {
		t.Fatal(err)
	}
	binding := OrganisationRecoveryBinding{WorkspaceID: uuid.New(), Encryption: KeyRef{uuid.New(), 2}, Signing: KeyRef{uuid.New(), 3}}
	capsule, err := SealOrganisationRecovery(key, binding, keys)
	if err != nil {
		t.Fatal(err)
	}
	display, err := FormatRecoveryKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer Wipe(display)
	parsed, err := ParseRecoveryKey(display)
	if err != nil {
		t.Fatal(err)
	}
	defer Wipe(parsed)
	opened, err := OpenOrganisationRecovery(parsed, binding, capsule, public)
	if err != nil || !bytes.Equal(opened.EncryptionPrivate, keys.EncryptionPrivate) || !bytes.Equal(opened.SigningSeed, keys.SigningSeed) {
		t.Fatal("recovery did not restore both organisation keys", err)
	}
	opened.Wipe()
	for _, change := range []func(*OrganisationRecoveryBinding){
		func(b *OrganisationRecoveryBinding) { b.WorkspaceID = uuid.New() },
		func(b *OrganisationRecoveryBinding) { b.Encryption.ID = uuid.New() },
		func(b *OrganisationRecoveryBinding) { b.Encryption.Version++ },
		func(b *OrganisationRecoveryBinding) { b.Signing.ID = uuid.New() },
		func(b *OrganisationRecoveryBinding) { b.Signing.Version++ },
	} {
		other := binding
		change(&other)
		if opened, err := OpenOrganisationRecovery(key, other, capsule, public); opened != nil || err == nil {
			t.Fatal("recovery capsule crossed an identity boundary")
		}
	}
	modified := capsule
	modified.Ciphertext = bytes.Clone(capsule.Ciphertext)
	modified.Ciphertext[0] ^= 1
	for _, tc := range []struct {
		key     []byte
		capsule Envelope
		public  UserPublicKeys
		want    error
	}{
		{make([]byte, 32), capsule, public, ErrAuthentication},
		{key, capsule, UserPublicKeys{public.Signing, public.Encryption}, ErrAuthentication},
		{key, modified, public, ErrAuthentication},
		{key, Envelope{}, public, ErrFormat},
		{nil, capsule, public, ErrFormat},
	} {
		if opened, err := OpenOrganisationRecovery(tc.key, binding, tc.capsule, tc.public); opened != nil || !errors.Is(err, tc.want) {
			t.Fatal("incorrect recovery acceptance", err)
		}
	}
	bad := binding
	bad.Signing = bad.Encryption
	if _, err := SealOrganisationRecovery(key, bad, keys); !errors.Is(err, ErrFormat) {
		t.Fatal("duplicate key identities accepted", err)
	}
	if _, err := OpenOrganisationRecovery(key, bad, capsule, public); !errors.Is(err, ErrFormat) {
		t.Fatal("duplicate key identities accepted on open", err)
	}
	if _, err := SealOrganisationRecovery(key, binding, nil); !errors.Is(err, ErrFormat) {
		t.Fatal("invalid private keys accepted", err)
	}
	if _, err := SealOrganisationRecovery(nil, binding, keys); !errors.Is(err, ErrFormat) {
		t.Fatal("invalid recovery key accepted", err)
	}
}
