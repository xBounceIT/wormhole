package sharedcatalog

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func enrolledAuthorFixture(t *testing.T) (vault.UserEnrollmentCertificate, vault.UserKeyState, vault.UserKeyTrust, *vault.UserKeys, ed25519.PrivateKey) {
	t.Helper()
	org := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32))
	t.Cleanup(func() { vault.Wipe(org) })
	b := &vault.InviteBootstrap{EncryptionPrivate: bytes.Repeat([]byte{13}, 32), SigningSeed: bytes.Repeat([]byte{12}, 32), OrganisationPublic: org.Public().(ed25519.PublicKey)}
	t.Cleanup(b.Wipe)
	context := vault.InviteContext{WorkspaceID: uuid.New(), UserID: uuid.New(), InviteID: uuid.New(), KeyID: uuid.New(), KeyVersion: 1, LoginName: "alice"}
	public, err := (&vault.UserKeys{EncryptionPrivate: b.EncryptionPrivate, SigningSeed: b.SigningSeed}).Public()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := vault.SignInviteManifest(vault.InviteManifest{FormatVersion: 1, Context: context, Revision: 5, ExpiresAt: time.Now().Add(time.Hour).Unix(), Bootstrap: public, Copies: []vault.KeyCopyBinding{}, Issuers: []vault.InviteIssuer{}}, org.Seed())
	if err != nil {
		t.Fatal(err)
	}
	keys, proof, err := vault.PrepareInviteRekey(context, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Wipe)
	root := vault.KeyRef{ID: uuid.New(), Version: 1}
	state, err := vault.SignUserKeyState(vault.UserKeyState{FormatVersion: 1, WorkspaceID: context.WorkspaceID, UserID: context.UserID, Sequence: 9, Active: true, Encryption: vault.KeyRef{ID: context.KeyID, Version: 1}, Signing: vault.KeyRef{ID: uuid.New(), Version: 1}, MinimumEncryptionCertificate: 2, MinimumSigningCertificate: 3, Signer: root}, org)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := vault.SignUserKeyCertificate(vault.UserKeyCertificate{FormatVersion: 1, WorkspaceID: state.WorkspaceID, UserID: state.UserID, Key: state.Encryption, Kind: "user-enc", Suite: 2, PublicKey: public.Encryption, Revision: 2, Signer: root}, org)
	if err != nil {
		t.Fatal(err)
	}
	sign, err := vault.SignUserKeyCertificate(vault.UserKeyCertificate{FormatVersion: 1, WorkspaceID: state.WorkspaceID, UserID: state.UserID, Key: state.Signing, Kind: "user-sign", Suite: 1, PublicKey: public.Signing, Revision: 3, Signer: root}, org)
	if err != nil {
		t.Fatal(err)
	}
	return vault.UserEnrollmentCertificate{FormatVersion: 1, Manifest: manifest, BootstrapEncryption: enc, BootstrapSigning: sign, Rekey: proof}, state, vault.UserKeyTrust{WorkspaceID: state.WorkspaceID, UserID: state.UserID, Signer: root, Organisation: org.Public().(ed25519.PublicKey), MinimumSequence: 9}, keys, org
}

func TestEnrolledAuthorSignsEveryCatalogRecordWithFinalKey(t *testing.T) {
	c, state, trust, keys, _ := enrolledAuthorFixture(t)
	private := ed25519.NewKeyFromSeed(keys.SigningSeed)
	defer vault.Wipe(private)
	ref := vault.KeyRef{ID: c.Rekey.SigningKeyID, Version: 1}
	boundary, node := uuid.New(), vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "Final author", Kind: 1}
	seal, err := SignNode(trust.WorkspaceID, boundary, node, 7, ref, private)
	if err != nil {
		t.Fatal(err)
	}
	pin := CurrentNodeTrust{Workspace: trust.WorkspaceID, Node: uuid.MustParse(node.ID), Boundary: boundary, Author: trust.UserID, OrganisationKey: trust.Signer, Organisation: trust.Organisation, MinimumStateSequence: 9, MinimumCertificateRevision: 5, MinimumNodeRevision: 7}
	observed, err := VerifyCurrentNode(node, boundary, seal, vault.UserKeyCertificate{}, state, pin, c)
	if err != nil || observed != (Observation{9, 5, 7}) {
		t.Fatal("final node author", observed, err)
	}
	credential := CredentialRecord{Metadata: vaultstore.CredentialMetadata{ID: uuid.NewString(), Name: "Account", Protocol: "ssh", Kind: "password", Provider: "local"}, Fields: []vaultstore.CredentialField{{Field: "password", Present: true, Version: 1}}}
	sealed, err := SignCredential(trust.WorkspaceID, boundary, credential, 3, ref, private)
	if err != nil {
		t.Fatal(err)
	}
	co, err := VerifyCurrentCredential(credential, boundary, sealed, vault.UserKeyCertificate{}, state, CredentialTrust{Workspace: trust.WorkspaceID, Credential: uuid.MustParse(credential.Metadata.ID), Boundary: boundary, Author: trust.UserID, OrganisationKey: trust.Signer, Organisation: trust.Organisation, MinimumStateSequence: 9, MinimumCertificateRevision: 5, MinimumCredentialRevision: 3}, c)
	if err != nil || co != (CredentialObservation{9, 5, 3}) {
		t.Fatal("final credential author", co, err)
	}
	tunnel := TunnelRecord{Metadata: vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "VPN", Kind: 2}, ConfigurationVersion: 1}
	sealed, err = SignSelection(trust.WorkspaceID, boundary, tunnel, 4, ref, private)
	if err != nil {
		t.Fatal(err)
	}
	so, err := VerifyCurrentSelection(tunnel, boundary, sealed, vault.UserKeyCertificate{}, state, SelectionTrust{Workspace: trust.WorkspaceID, Boundary: boundary, Author: trust.UserID, Scope: SelectionScope{Kind: "tunnel", Subject: uuid.MustParse(tunnel.Metadata.ID)}, OrganisationKey: trust.Signer, Organisation: trust.Organisation, MinimumStateSequence: 9, MinimumCertificateRevision: 5, MinimumSelectionRevision: 4}, c)
	if err != nil || so != (SelectionObservation{9, 5, 4}) {
		t.Fatal("final tunnel author", so, err)
	}
	binding := vault.KeyCopyBinding{WorkspaceID: trust.WorkspaceID, Key: vault.KeyRef{ID: uuid.New(), Version: 1}, Holder: vault.KeyRef{ID: uuid.New(), Version: 1}, Issuer: ref}
	copy, err := vault.SealKeyCopy(bytes.Repeat([]byte{19}, 32), binding, c.Rekey.Public.Encryption, keys.SigningSeed)
	if err != nil {
		t.Fatal(err)
	}
	ko, err := VerifyCurrentKeyCopy(binding, copy, vault.UserKeyCertificate{}, state, trust, 5, c)
	if err != nil || ko != (KeyCopyObservation{9, 5}) {
		t.Fatal("final copy issuer", ko, err)
	}
	wrong := binding
	wrong.Issuer = state.Signing
	if _, err := VerifyCurrentKeyCopy(wrong, copy, vault.UserKeyCertificate{}, state, trust, 5, c); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("bootstrap issuer substitution", err)
	}
	if _, err := VerifyCurrentNode(node, boundary, seal, c.BootstrapSigning, state, pin); err == nil {
		t.Fatal("final signature accepted as bootstrap")
	}
}

func TestEnrolledAuthorRetainsRevocationAndRejectsInvalidChains(t *testing.T) {
	c, state, trust, _, org := enrolledAuthorFixture(t)
	for _, mode := range []string{"state", "revocation", "manifest-floor", "rekey", "duplicate", "mixed", "bootstrap-reset"} {
		t.Run(mode, func(t *testing.T) {
			s, cert, minimum, proofs := state, vault.UserKeyCertificate{}, uint64(5), []vault.UserEnrollmentCertificate{c}
			switch mode {
			case "state":
				s.Sequence++
			case "revocation":
				s.Active = false
				s.Sequence++
				var err error
				s, err = vault.SignUserKeyState(s, org)
				if err != nil {
					t.Fatal(err)
				}
			case "manifest-floor":
				minimum = 6
			case "rekey":
				raw, err := vault.EncodeUserEnrollmentCertificate(c)
				if err != nil {
					t.Fatal(err)
				}
				bad, err := vault.DecodeUserEnrollmentCertificate(raw)
				if err != nil {
					t.Fatal(err)
				}
				bad.Rekey.Signature[0] ^= 1
				proofs = []vault.UserEnrollmentCertificate{bad}
			case "duplicate":
				proofs = append(proofs, c)
			case "mixed":
				cert = c.BootstrapSigning
			case "bootstrap-reset":
				s.Sequence++
				s.Signing.ID = uuid.New()
				var err error
				s, err = vault.SignUserKeyState(s, org)
				if err != nil {
					t.Fatal(err)
				}
			}
			got, err := verifyCurrentAuthor(cert, s, trust, minimum, proofs...)
			if err == nil || got.CertificateRevision != 0 {
				t.Fatal("invalid chain admitted", got, err)
			}
			if mode == "state" {
				if got.StateSequence != 0 {
					t.Fatal("forged state observed")
				}
			} else if got.StateSequence != s.Sequence {
				t.Fatal("authenticated state observation lost")
			}
			if mode == "revocation" && !errors.Is(err, vault.ErrPolicy) {
				t.Fatal(err)
			}
		})
	}
}
