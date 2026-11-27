package workspaceimport

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type authorityFixture struct {
	authority Authority
	member    *vault.UserKeys
	org       ed25519.PrivateKey
	roots     map[uuid.UUID][]byte
}

func certifiedAuthority(t *testing.T, target Target) authorityFixture {
	t.Helper()
	public, org, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vault.Wipe(org) })
	orgRef := vault.KeyRef{ID: uuid.New(), Version: 1}
	trust := vault.UserKeyTrust{WorkspaceID: target.WorkspaceID, UserID: target.UserID, Signer: orgRef, Organisation: public, MinimumSequence: 1}
	bootstrap, err := vault.NewInviteBootstrap(public)
	if err != nil {
		t.Fatal(err)
	}
	defer bootstrap.Wipe()
	bootstrapPublic, err := (&vault.UserKeys{EncryptionPrivate: bootstrap.EncryptionPrivate, SigningSeed: bootstrap.SigningSeed}).Public()
	if err != nil {
		t.Fatal(err)
	}
	invite := vault.InviteContext{WorkspaceID: target.WorkspaceID, UserID: target.UserID, InviteID: uuid.New(), KeyID: uuid.New(), KeyVersion: 1, LoginName: "fixture-owner"}
	member, rekey, err := vault.PrepareInviteRekey(invite, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(member.Wipe)
	orgSeed := org.Seed()
	defer vault.Wipe(orgSeed)
	manifest, err := vault.SignInviteManifest(vault.InviteManifest{FormatVersion: 1, Revision: 1, Context: invite,
		ExpiresAt: time.Now().Add(time.Hour).Unix(), Bootstrap: bootstrapPublic}, orgSeed)
	if err != nil {
		t.Fatal(err)
	}
	state := vault.UserKeyState{FormatVersion: 1, WorkspaceID: target.WorkspaceID, UserID: target.UserID, Sequence: 1, Active: true,
		Encryption: vault.KeyRef{ID: invite.KeyID, Version: 1}, Signing: vault.KeyRef{ID: uuid.New(), Version: 1},
		MinimumEncryptionCertificate: 1, MinimumSigningCertificate: 1, Signer: orgRef}
	state, err = vault.SignUserKeyState(state, org)
	if err != nil {
		t.Fatal(err)
	}
	base := vault.UserKeyCertificate{FormatVersion: 1, WorkspaceID: target.WorkspaceID, UserID: target.UserID, Revision: 1, Signer: orgRef}
	base.Kind, base.Suite, base.Key, base.PublicKey = "user-enc", vault.SuiteX25519HKDFSHA256AES256GCM, state.Encryption, bootstrapPublic.Encryption
	enc, err := vault.SignUserKeyCertificate(base, org)
	if err != nil {
		t.Fatal(err)
	}
	base.Kind, base.Suite, base.Key, base.PublicKey = "user-sign", 1, state.Signing, bootstrapPublic.Signing
	sign, err := vault.SignUserKeyCertificate(base, org)
	if err != nil {
		t.Fatal(err)
	}
	enrollment := vault.UserEnrollmentCertificate{FormatVersion: 1, Manifest: manifest, BootstrapEncryption: enc, BootstrapSigning: sign, Rekey: rekey}
	roots := make(map[uuid.UUID][]byte)
	makeBoundary := func(owner uuid.UUID) *ImportBoundary {
		newRoot := func() (vault.BoundaryKey, []byte) {
			seed := make([]byte, 32)
			rand.Read(seed)
			t.Cleanup(func() { vault.Wipe(seed) })
			key, err := ecdh.X25519().NewPrivateKey(seed)
			if err != nil {
				t.Fatal(err)
			}
			return vault.BoundaryKey{Key: vault.KeyRef{ID: uuid.New(), Version: 1}, Public: key.PublicKey().Bytes()}, seed
		}
		view, viewSeed := newRoot()
		secret, seed := newRoot()
		m, err := vault.SignBoundaryManifest(vault.BoundaryManifest{FormatVersion: 1, WorkspaceID: target.WorkspaceID, BoundaryID: uuid.New(),
			Revision: 1, OwnerUserID: owner, OrgEscrow: true, Active: true, View: view, Secret: secret, Signer: orgRef}, org)
		if err != nil {
			t.Fatal(err)
		}
		roots[m.View.Key.ID], roots[m.Secret.Key.ID] = viewSeed, seed
		return &ImportBoundary{Manifest: m, MinimumRevision: 1}
	}
	return authorityFixture{Authority{Trust: trust, Account: state, Enrollment: enrollment, MinimumEnrollmentRevision: 1,
		EscrowPersonal: true, Personal: makeBoundary(target.UserID), Shared: makeBoundary(uuid.Nil)}, member, org, roots}
}

func unmodifiedConfiguration(_ int, value []byte, _ func(string) (string, error)) ([]byte, error) {
	return value, nil
}

func TestSealImportSignsGraphAndEncryptsEachFieldForItsDestination(t *testing.T) {
	ctx := context.Background()
	f := fixture(t)
	inlineID, host, protocol, enabled := uuid.NewString(), "inline.example", 0, true
	if _, err := f.owner.PutNode(ctx, vaultstore.NodeMetadata{ID: inlineID, Kind: 1, Name: "Inline login", Protocol: &protocol, Host: &host, UseInlinePassword: &enabled},
		[]localvault.SecretChange{{Field: "inlinePassword", Value: []byte("synthetic-inline-secret")}}, 0); err != nil {
		t.Fatal(err)
	}
	source, err := f.owner.CaptureWorkspaceImport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	selection := Selection{Shared: []ItemID{f.folder, f.current, f.tunnel}}
	_, plan, err := Prepare(ctx, source, f.target, selection)
	if err != nil || plan == nil {
		t.Fatal("valid mixed placement could not prepare", err)
	}
	a := certifiedAuthority(t, f.target)
	stage, err := plan.Seal(ctx, f.owner, a.authority, a.member.SigningSeed, unmodifiedConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(stage); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("staged data could be serialized accidentally", err)
	}
	body, signature := stage.PostgresPayload()
	var payload importPayload
	public := a.authority.Enrollment.Rekey.Public.Signing
	if !ed25519.Verify(public, importSigningDigest(body), signature) || json.Unmarshal(body, &payload) != nil ||
		payload.Target != f.target || !bytes.Equal(payload.SourceDigest, source.Fingerprint[:]) || len(payload.Boundaries) != 2 ||
		payload.FormatVersion != 1 || len(payload.Nodes) != 3 || len(payload.Credentials) != 2 || len(payload.Tunnels) != 1 || len(payload.Values) != 5 || len(payload.Pins.Entries) != 1 {
		t.Fatal("staging did not produce the expected signed import")
	}
	for _, plaintext := range []string{"synthetic-test-private-field", "synthetic-private-note", "synthetic-tunnel-secret", "synthetic-inline-secret"} {
		if bytes.Contains(body, []byte(plaintext)) {
			t.Fatal("staging exposed a source field to the database")
		}
	}
	inlineItem := ItemID{Kind: "node", ID: inlineID}
	inlineTarget, _, _ := plan.DestinationFor(inlineItem)
	for _, node := range payload.Nodes {
		trust := sharedcatalog.CurrentNodeTrust{Workspace: f.target.WorkspaceID,
			Node: uuid.MustParse(node.Metadata.ID), Boundary: node.Boundary, Author: f.target.UserID,
			OrganisationKey: a.authority.Trust.Signer, Organisation: a.authority.Trust.Organisation, MinimumNodeRevision: 1}
		if _, err := sharedcatalog.VerifyCurrentNode(node.Metadata, node.Boundary, node.Seal, vault.UserKeyCertificate{}, a.authority.Account, trust, a.authority.Enrollment); err != nil {
			t.Fatal("existing catalog verifier refused an imported node", err)
		}
		fieldTrust := sharedcatalog.SelectionTrust{Workspace: f.target.WorkspaceID, Boundary: node.Boundary, Author: f.target.UserID,
			Scope:           sharedcatalog.SelectionScope{Kind: "node-fields", Subject: uuid.MustParse(node.Metadata.ID)},
			OrganisationKey: a.authority.Trust.Signer, Organisation: a.authority.Trust.Organisation, MinimumSelectionRevision: 1}
		if _, err := sharedcatalog.VerifyCurrentSelection(node.Fields, node.Boundary, node.FieldsSeal, vault.UserKeyCertificate{}, a.authority.Account, fieldTrust, a.authority.Enrollment); err != nil {
			t.Fatal("existing catalog verifier refused an imported node manifest", err)
		}
		if node.Metadata.ID == inlineTarget {
			if len(node.Fields.Fields) != 1 || node.Fields.Fields[0] != (vaultstore.CredentialField{Field: "inlinePassword", Version: 1, Present: true}) {
				t.Fatal("inline credential was missing from its signed manifest")
			}
		} else if len(node.Fields.Fields) != 0 {
			t.Fatal("notes entered the inline Use manifest")
		}
	}
	for _, c := range payload.Credentials {
		trust := sharedcatalog.CredentialTrust{Workspace: f.target.WorkspaceID, Credential: uuid.MustParse(c.Record.Metadata.ID), Boundary: c.Boundary,
			Author: f.target.UserID, OrganisationKey: a.authority.Trust.Signer, Organisation: a.authority.Trust.Organisation, MinimumCredentialRevision: 1}
		if _, err := sharedcatalog.VerifyCurrentCredential(c.Record, c.Boundary, c.Seal, vault.UserKeyCertificate{}, a.authority.Account, trust, a.authority.Enrollment); err != nil {
			t.Fatal("existing catalog verifier refused an imported credential", err)
		}
		if len(c.Record.Fields) != 1 || c.Record.Fields[0] != (vaultstore.CredentialField{Field: "password", Version: 1, Present: true}) {
			t.Fatal("the signed credential manifest did not match its staged field")
		}
	}
	type expect struct {
		field string
		plain string
	}
	expected := make(map[string]expect)
	for item, value := range map[ItemID]expect{
		f.connection: {"notes", "synthetic-private-note"}, f.current: {"password", "synthetic-test-private-field"},
		f.retained: {"password", "synthetic-test-private-field"}, f.tunnel: {"settings", `{"password":"synthetic-tunnel-secret"}`},
		inlineItem: {"inlinePassword", "synthetic-inline-secret"},
	} {
		id, _, _ := plan.DestinationFor(item)
		expected[id] = value
	}
	issuer := vault.KeyCopyTrust{Issuer: payload.Author, Public: public}
	seen := make(map[vault.KeyRef]bool)
	for _, staged := range payload.Values {
		binding := staged.Binding
		want, ok := expected[binding.OwnerID.String()]
		if !ok || binding.Field != want.field || binding.Version != 1 || binding.WorkspaceID != f.target.WorkspaceID || seen[binding.DEK] {
			t.Fatal("duplicate or unbound encrypted field")
		}
		delete(expected, binding.OwnerID.String())
		seen[binding.DEK] = true
		boundary, other := a.authority.Shared.Manifest, a.authority.Personal.Manifest
		if binding.OwnerKind == "node" || binding.OwnerID.String() == payload.Pins.Entries[0].Legacy.CredentialID {
			boundary, other = other, boundary
		}
		if staged.Boundary != boundary.BoundaryID {
			t.Fatal("personal and shared ciphertext used the wrong root")
		}
		trust := vault.BoundaryTrust{WorkspaceID: f.target.WorkspaceID, BoundaryID: boundary.BoundaryID, Signer: a.authority.Trust.Signer, Organisation: a.authority.Trust.Organisation, MinimumRevision: 1}
		open, root, otherRoot := vault.OpenSharedValue, boundary.Secret.Key, other.Secret.Key
		if binding.Field == "notes" {
			open, root, otherRoot = vault.OpenSharedNote, boundary.View.Key, other.View.Key
			if plain, err := vault.OpenSharedValue(a.roots[boundary.Secret.Key.ID], boundary.Secret.Key, binding, staged.Copy, issuer, staged.Envelope, boundary, trust); err == nil || plain != nil {
				vault.Wipe(plain)
				t.Fatal("a view-key note opened through the credential release primitive")
			}
		} else if plain, err := vault.OpenSharedNote(a.roots[boundary.View.Key.ID], boundary.View.Key, binding, staged.Copy, issuer, staged.Envelope, boundary, trust); err != vault.ErrFormat || plain != nil {
			t.Fatal("the note primitive accepted a credential or connection field", err)
		}
		plain, err := open(a.roots[root.ID], root, binding, staged.Copy, issuer, staged.Envelope, boundary, trust)
		matches := bytes.Equal(plain, []byte(want.plain))
		vault.Wipe(plain)
		if err != nil || !matches {
			t.Fatal("sealed value did not open with its existing release primitive", err)
		}
		if plain, err := open(a.roots[otherRoot.ID], root, binding, staged.Copy, issuer, staged.Envelope, boundary, trust); err == nil || plain != nil {
			vault.Wipe(plain)
			t.Fatal("the other scope opened the field")
		}
	}
	if len(expected) != 0 {
		t.Fatal("a live field was lost")
	}
	for i, boundary := range []vault.BoundaryManifest{a.authority.Personal.Manifest, a.authority.Shared.Manifest} {
		encoded, err := vault.EncodeBoundaryManifest(boundary)
		digest := sha256.Sum256(encoded)
		receipt := payload.Boundaries[i]
		if err != nil || receipt.ID != boundary.BoundaryID || receipt.Revision != boundary.Revision || !bytes.Equal(receipt.Digest, digest[:]) {
			t.Fatal("prepared document did not bind the authenticated root manifest", err)
		}
	}
	body[0] ^= 1
	signature[0] ^= 1
	stable, stableSignature := stage.PostgresPayload()
	if !ed25519.Verify(public, importSigningDigest(stable), stableSignature) || bytes.Equal(stable, body) {
		t.Fatal("a retry did not retain its exact signed payload")
	}
}

func TestSealImportRejectsStaleAndUnauthenticatedInputsBeforeLending(t *testing.T) {
	ctx := context.Background()
	f := fixture(t)
	_, plan, err := Prepare(ctx, f.source, f.target, Selection{Shared: []ItemID{f.tunnel}})
	if err != nil || plan == nil {
		t.Fatal(err)
	}
	a := certifiedAuthority(t, f.target)
	never := func(int, []byte, func(string) (string, error)) ([]byte, error) {
		t.Fatal("invalid state reached tunnel staging")
		return nil, nil
	}
	resign := func(m vault.BoundaryManifest) *ImportBoundary {
		signed, err := vault.SignBoundaryManifest(m, a.org)
		if err != nil {
			t.Fatal(err)
		}
		return &ImportBoundary{Manifest: signed, MinimumRevision: 1}
	}
	for _, tc := range []struct {
		name string
		want error
		edit func(*Authority)
	}{
		{"missing boundary", vault.ErrPolicy, func(a *Authority) { a.Personal = nil }},
		{"different account", vault.ErrAuthentication, func(a *Authority) { a.Trust.UserID = uuid.New() }},
		{"wrong escrow policy", vault.ErrPolicy, func(a *Authority) { a.EscrowPersonal = false }},
		{"inactive recipient", vault.ErrPolicy, func(a *Authority) { m := a.Shared.Manifest; m.Active = false; a.Shared = resign(m) }},
		{"foreign personal recipient", vault.ErrPolicy, func(a *Authority) { m := a.Personal.Manifest; m.OwnerUserID = uuid.New(); a.Personal = resign(m) }},
		{"stale manifest", vault.ErrRollback, func(a *Authority) { a.Personal = &ImportBoundary{Manifest: a.Personal.Manifest, MinimumRevision: 2} }},
		{"cross-scope key reuse", vault.ErrPolicy, func(a *Authority) {
			m := a.Shared.Manifest
			m.Secret = a.Personal.Manifest.Secret
			a.Shared = resign(m)
		}},
		{"foreign workspace manifest", vault.ErrAuthentication, func(a *Authority) { m := a.Personal.Manifest; m.WorkspaceID = uuid.New(); a.Personal = resign(m) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := a.authority
			tc.edit(&bad)
			if result, err := plan.Seal(ctx, f.owner, bad, a.member.SigningSeed, never); result != nil || !errors.Is(err, tc.want) {
				t.Fatal("stage accepted invalid authority", err)
			}
		})
	}
	if result, err := plan.Seal(ctx, f.owner, a.authority, bytes.Repeat([]byte{12}, 32), never); result != nil || err != vault.ErrAuthentication {
		t.Fatal("a substituted key could sign the import", err)
	}
	changed := *plan
	changed.Target.RequestID = uuid.New()
	if result, err := changed.Seal(ctx, f.owner, a.authority, a.member.SigningSeed, never); result != nil || err != vault.ErrAuthentication {
		t.Fatal("the imported allocation was detached from the preview", err)
	}
	if result, err := plan.Seal(ctx, f.owner, a.authority, a.member.SigningSeed, nil); result != nil || err != vault.ErrFormat {
		t.Fatal("tunnel settings could bypass their validation", err)
	}
	empty := func(int, []byte, func(string) (string, error)) ([]byte, error) { return nil, nil }
	if result, err := plan.Seal(ctx, f.owner, a.authority, a.member.SigningSeed, empty); result != nil || err != vault.ErrFormat {
		t.Fatal("empty rewritten configuration was accepted", err)
	}
	profile, err := f.owner.ReadCredential(ctx, f.current.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.PutCredential(ctx, profile.CredentialMetadata, []localvault.SecretChange{{Field: "password", Value: []byte("changed source")}}, profile.RowVersion); err != nil {
		t.Fatal(err)
	}
	if result, err := plan.Seal(ctx, f.owner, a.authority, a.member.SigningSeed, never); result != nil || err != vaultstore.ErrConflict {
		t.Fatal("an obsolete preview lent a source field", err)
	}
}

func TestSealImportRemapsOnlyValidFallbackDestinations(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	ssl := vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "SSL fallback", Kind: 2}
	ipsec := vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "IPsec primary", Kind: 9}
	if _, err := f.owner.PutTunnel(ctx, ssl, []byte(`{"password":"synthetic"}`), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.PutTunnel(ctx, ipsec, []byte(ssl.ID), 0); err != nil {
		t.Fatal(err)
	}
	source, err := f.owner.CaptureWorkspaceImport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a := certifiedAuthority(t, f.target)
	primary, fallback := ItemID{Kind: "tunnel", ID: ipsec.ID}, ItemID{Kind: "tunnel", ID: ssl.ID}
	selection := Selection{Shared: []ItemID{primary}}
	_, plan, err := Prepare(ctx, source, f.target, selection)
	if err != nil || plan == nil {
		t.Fatal(err)
	}
	var mapped string
	transform := func(kind int, settings []byte, resolve func(string) (string, error)) ([]byte, error) {
		if kind != 9 {
			return settings, nil
		}
		var err error
		mapped, err = resolve(string(settings))
		return []byte(mapped), err
	}
	if result, err := plan.Seal(ctx, f.owner, a.authority, a.member.SigningSeed, transform); result != nil || err != vault.ErrPolicy {
		t.Fatal("shared IPsec was staged with a personal fallback", err)
	}
	selection.Shared = append(selection.Shared, fallback)
	_, plan, err = Prepare(ctx, source, f.target, selection)
	if err != nil || plan == nil {
		t.Fatal(err)
	}
	if _, err := plan.Seal(ctx, f.owner, a.authority, a.member.SigningSeed, transform); err != nil {
		t.Fatal(err)
	}
	if id, _, _ := plan.DestinationFor(fallback); mapped != id || mapped == fallback.ID {
		t.Fatal("fallback was not mapped to the same imported SSL tunnel")
	}
	for _, invalid := range []string{f.tunnel.ID, uuid.NewString()} {
		wrong := func(kind int, settings []byte, resolve func(string) (string, error)) ([]byte, error) {
			if kind != 9 {
				return settings, nil
			}
			_, err := resolve(invalid)
			return nil, err
		}
		if result, err := plan.Seal(ctx, f.owner, a.authority, a.member.SigningSeed, wrong); result != nil || err != vault.ErrPolicy {
			t.Fatal("missing or wrong-kind fallback was staged", err)
		}
	}
}
