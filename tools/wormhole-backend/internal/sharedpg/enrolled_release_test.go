package sharedpg

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Convert the existing authenticated graph to the same final-key state produced
// by invitation rekey. Original bootstrap private keys never replace final keys.
func enrolledReleaseFixture(t *testing.T, tunnel bool, borrow ...func(*vault.InviteBootstrap)) (connectionFixture, map[string]any, *vault.UserKeys) {
	t.Helper()
	var f connectionFixture
	var wire map[string]any
	if tunnel {
		f, wire = releaseGraphFixture(t, "saved", true, false)
		addTunnelReleaseFixture(t, &f, wire)
	} else {
		f, wire = releaseGraphFixture(t, "saved", true, false)
	}
	return enrollReleaseFixture(t, f, wire, borrow...)
}

func enrollReleaseFixture(t *testing.T, f connectionFixture, wire map[string]any, borrow ...func(*vault.InviteBootstrap)) (connectionFixture, map[string]any, *vault.UserKeys) {
	t.Helper()
	old, e := releaseParseFixture(t, f, wire)
	if e != nil {
		t.Fatal(e)
	}
	b := &vault.InviteBootstrap{EncryptionPrivate: bytes.Repeat([]byte{17}, 32), SigningSeed: f.key.Seed(), OrganisationPublic: bytes.Clone(f.s.PublicKey)}
	defer b.Wipe()
	for _, use := range borrow {
		use(b)
	}
	public, e := (&vault.UserKeys{EncryptionPrivate: b.EncryptionPrivate, SigningSeed: b.SigningSeed}).Public()
	if e != nil {
		t.Fatal(e)
	}
	state := *f.s.Account
	ctx := vault.InviteContext{WorkspaceID: f.s.WorkspaceID, UserID: f.s.UserID, InviteID: uuid.New(), KeyID: state.Encryption.ID, KeyVersion: state.Encryption.Version, LoginName: "alice"}
	seed := f.org.Seed()
	defer vault.Wipe(seed)
	manifest, e := vault.SignInviteManifest(vault.InviteManifest{FormatVersion: 1, Context: ctx, Revision: 5, ExpiresAt: time.Now().Add(time.Hour).Unix(), Bootstrap: public, Copies: []vault.KeyCopyBinding{}, Issuers: []vault.InviteIssuer{}}, seed)
	if e != nil {
		t.Fatal(e)
	}
	keys, rekey, e := vault.PrepareInviteRekey(ctx, b)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(keys.Wipe)
	enc, e := vault.SignUserKeyCertificate(vault.UserKeyCertificate{FormatVersion: 1, WorkspaceID: f.s.WorkspaceID, UserID: f.s.UserID, Key: state.Encryption, Kind: "user-enc", Suite: 2, PublicKey: public.Encryption, Revision: max(1, state.MinimumEncryptionCertificate), Signer: state.Signer}, f.org)
	if e != nil {
		t.Fatal(e)
	}
	c := vault.UserEnrollmentCertificate{FormatVersion: 1, Manifest: manifest, BootstrapEncryption: enc, BootstrapSigning: *f.records.Chain[0].Author.Certificate, Rekey: rekey}
	f.s, e = f.s.AdvanceEnrollment(c, f.s.WrappingRevision)
	if e != nil {
		t.Fatal(e)
	}
	f.key = ed25519.NewKeyFromSeed(keys.SigningSeed)
	t.Cleanup(func() { vault.Wipe(f.key) })
	author := UnverifiedNodeAuthor{Key: f.s.Enrollment.Signing, State: &state, EnrollmentCertificate: &c}
	metadata := wire["metadata"].(map[string]any)
	certificate, e := vault.EncodeUserEnrollmentCertificate(c)
	if e != nil {
		t.Fatal(e)
	}
	certHex := hex.EncodeToString(certificate)
	rowFor := func(raw []any, seal vault.RecordSeal) []any {
		row := append([]any(nil), raw...)
		row[8], row[9], row[11], row[13], row[14] = author.Key.ID.String(), "1", hex.EncodeToString(seal.Signature), author.Key.ID.String(), "1"
		for i := 17; i < 23; i++ {
			row[i] = nil
		}
		return append(row, certHex)
	}
	for i := range f.records.Chain {
		f.records.Chain[i].Author = author
	}
	f.signChain(t)
	chain := metadata["chain"].([]any)
	for i, r := range f.records.Chain {
		chain[i] = rowFor(chain[i].([]any), r.Node.Seal)
	}
	for i, r := range []*UnverifiedCredentialRecord{f.records.Credential, f.records.Gateway} {
		if r == nil {
			continue
		}
		r.Author = author
		f.signProfile(t, r, r.Credential.Seal.Revision)
		name := "credential"
		if i == 1 {
			name = "gateway"
		}
		metadata[name] = rowFor(metadata[name].([]any), r.Credential.Seal)
	}
	if r := f.records.Tunnel; r != nil {
		r.Author = author
		f.signSelection(t, r, r.Selection.Seal.Revision)
		metadata["tunnel"] = rowFor(metadata["tunnel"].([]any), r.Selection.Seal)
	} else {
		metadata["tunnel"] = nil
	}
	issuer := func(copy UnverifiedKeyCopy) []byte {
		if copy.Author != nil {
			return copy.Author.Certificate.PublicKey
		}
		return f.s.PublicKey
	}
	roots := make(map[vault.KeyRef][]byte)
	defer func() {
		for _, raw := range roots {
			vault.Wipe(raw)
		}
	}()
	sealCopy := func(copy UnverifiedKeyCopy, plain, recipient []byte, root bool) []any {
		binding := copy.Binding
		if root {
			binding.Holder = f.s.Enrollment.Encryption
		}
		copy.Author = nil
		seed := f.org.Seed()
		if binding.Issuer != state.Signer {
			vault.Wipe(seed)
			seed = bytes.Clone(keys.SigningSeed)
			binding.Issuer = author.Key
			copy.Author = &author
		}
		defer vault.Wipe(seed)
		sealed, e := vault.SealKeyCopy(plain, binding, recipient, seed)
		if e != nil {
			t.Fatal(e)
		}
		copy.Binding, copy.Copy = binding, sealed
		row := releaseCopyWire(t, copy, 1, 7)
		if len(row) == 23 {
			row = append(row, nil)
		}
		return row
	}
	out := make([]any, 0, len(old.roots))
	for _, copy := range old.roots {
		plain, e := vault.OpenKeyCopy(b.EncryptionPrivate, copy.Binding, copy.Copy, issuer(copy))
		if e != nil {
			t.Fatal(e)
		}
		roots[copy.Binding.Key] = plain
		out = append(out, sealCopy(copy, plain, c.Rekey.Public.Encryption, true))
	}
	wire["roots"] = out
	accounts := wire["accounts"].([]any)
	for i, account := range old.accounts {
		copies := make([]any, 0, len(account.copies))
		for _, copy := range account.copies {
			private := roots[copy.Binding.Holder]
			plain, e := vault.OpenKeyCopy(private, copy.Binding, copy.Copy, issuer(copy))
			if e != nil {
				t.Fatal(e)
			}
			key, e := ecdh.X25519().NewPrivateKey(private)
			if e != nil {
				t.Fatal(e)
			}
			copies = append(copies, sealCopy(copy, plain, key.PublicKey().Bytes(), false))
			vault.Wipe(plain)
		}
		accounts[i].(map[string]any)["copies"] = copies
	}
	metadata["formatVersion"], wire["formatVersion"], wire["enrollment"], wire["nodeFields"] = 3, 5, certHex, nil
	return f, wire, keys
}

func TestEnrolledReleaseAuthenticatesFinalRecipientsAndAuthorFloors(t *testing.T) {
	for _, tunnel := range []bool{false, true} {
		t.Run(map[bool]string{false: "saved", true: "tunnel"}[tunnel], func(t *testing.T) {
			f, wire, keys := enrolledReleaseFixture(t, tunnel)
			g, e := releaseParseFixture(t, f, wire)
			if e != nil {
				t.Fatal(e)
			}
			next, prepared, e := f.s.VerifyCredentialRelease(context.Background(), f.node(), g)
			if e != nil || prepared == nil || next.FormatVersion != 6 || f.s.ValidateAdvance(next) != nil {
				t.Fatal("enrolled graph", e)
			}
			key := catalogEnrollmentName(*f.s.Account)
			if next.Catalog[key].Revision != 5 || next.Catalog[catalogKeyName("key", f.s.Enrollment.Signing)].Revision != 5 || next.Catalog[catalogKeyName("key", f.s.Account.Signing)].Revision != f.records.Chain[0].Author.EnrollmentCertificate.BootstrapSigning.Revision {
				t.Fatal("bootstrap/final floor namespaces mixed")
			}
			open := prepared.WithValues
			if tunnel {
				open = prepared.WithTunnelValues
			}
			if e := open(context.Background(), next, keys.EncryptionPrivate, func(_ resolver.Plan, values CredentialReleaseValues) error {
				if tunnel {
					if values.Tunnel == nil || string(values.Tunnel.Fields["settings"]) != "tunnel-secret" {
						t.Fatal("settings")
					}
				} else if values.Primary == nil || string(values.Primary.Fields["password"]) != "primary-secret" {
					t.Fatal("primary")
				}
				return nil
			}); e != nil {
				t.Fatal("final recipient opening", e)
			}
			_, again, e := f.s.VerifyCredentialRelease(context.Background(), f.node(), g)
			if e != nil {
				t.Fatal(e)
			}
			open = again.WithValues
			if tunnel {
				open = again.WithTunnelValues
			}
			if e := open(context.Background(), next, bytes.Repeat([]byte{17}, 32), func(resolver.Plan, CredentialReleaseValues) error {
				t.Fatal("bootstrap opened final copies")
				return nil
			}); e == nil {
				t.Fatal("bootstrap recipient accepted")
			}
			raw, _ := json.Marshal(wire)
			for _, field := range []string{"enrollment", "nodeFields"} {
				var bad map[string]any
				json.Unmarshal(raw, &bad)
				delete(bad, field)
				if _, e := releaseParseFixture(t, f, bad); e == nil {
					t.Fatal("missing v5 field", field)
				}
			}
		})
	}
}
