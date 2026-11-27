package vault

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestOrganisationRecoveryRecipientBindsWorkspaceAndKeys(t *testing.T) {
	keys := UserKeys{EncryptionPrivate: bytes.Repeat([]byte{11}, 32), SigningSeed: bytes.Repeat([]byte{13}, 32)}
	defer keys.Wipe()
	public, err := keys.Public()
	if err != nil {
		t.Fatal(err)
	}
	recipient := OrganisationRecoveryRecipient{
		WorkspaceID: uuid.New(), Encryption: KeyRef{ID: uuid.New(), Version: 1},
		Signer: KeyRef{ID: uuid.New(), Version: 2}, PublicKey: public.Encryption,
	}
	proof, err := SignOrganisationRecoveryRecipient(recipient, keys.SigningSeed)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyOrganisationRecoveryRecipient(recipient, proof, recipient.WorkspaceID, recipient.Signer, public.Signing); err != nil {
		t.Fatal(err)
	}
	other := UserKeys{EncryptionPrivate: bytes.Repeat([]byte{53}, 32), SigningSeed: bytes.Repeat([]byte{39}, 32)}
	defer other.Wipe()
	otherPublic, err := other.Public()
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*OrganisationRecoveryRecipient){
		"workspace":   func(r *OrganisationRecoveryRecipient) { r.WorkspaceID = uuid.New() },
		"recipient":   func(r *OrganisationRecoveryRecipient) { r.Encryption.ID = uuid.New() },
		"key version": func(r *OrganisationRecoveryRecipient) { r.Encryption.Version++ },
		"signer":      func(r *OrganisationRecoveryRecipient) { r.Signer.Version++ },
		"public key":  func(r *OrganisationRecoveryRecipient) { r.PublicKey = otherPublic.Encryption },
	} {
		t.Run(name, func(t *testing.T) {
			changed := recipient
			change(&changed)
			if err := VerifyOrganisationRecoveryRecipient(changed, proof, recipient.WorkspaceID, recipient.Signer, public.Signing); !errors.Is(err, ErrAuthentication) {
				t.Fatal("proof accepted substituted metadata", err)
			}
		})
	}
	if err := VerifyOrganisationRecoveryRecipient(recipient, proof, recipient.WorkspaceID, recipient.Signer, otherPublic.Signing); !errors.Is(err, ErrAuthentication) {
		t.Fatal("proof accepted an unpinned signer", err)
	}
	if _, err := SignOrganisationRecoveryRecipient(recipient, nil); !errors.Is(err, ErrFormat) {
		t.Fatal("missing signer was accepted", err)
	}
	for _, invalid := range []OrganisationRecoveryRecipient{
		{recipient.WorkspaceID, recipient.Encryption, recipient.Signer, make([]byte, 32)},
		{recipient.WorkspaceID, recipient.Encryption, recipient.Encryption, public.Encryption},
		{uuid.Nil, recipient.Encryption, recipient.Signer, public.Encryption},
	} {
		if _, err := SignOrganisationRecoveryRecipient(invalid, keys.SigningSeed); !errors.Is(err, ErrFormat) {
			t.Fatal("invalid recipient was signed", err)
		}
		if err := VerifyOrganisationRecoveryRecipient(invalid, proof, recipient.WorkspaceID, recipient.Signer, public.Signing); !errors.Is(err, ErrFormat) {
			t.Fatal("invalid recipient was accepted", err)
		}
	}
}
