package sharedpg

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestGroupBoundaryRootProof(t *testing.T) {
	f, _, keys := enrolledReleaseFixture(t, false)
	holder := f.s.Enrollment.Encryption
	signer := f.s.Account.Signer
	request := AdmissionRequest{WorkspaceID: f.s.WorkspaceID, UserID: f.s.UserID}
	groupSeed, rootSeed := bytes.Repeat([]byte{41}, 32), bytes.Repeat([]byte{42}, 32)
	defer vault.Wipe(groupSeed)
	defer vault.Wipe(rootSeed)
	public := func(seed []byte) []byte {
		t.Helper()
		key, err := ecdh.X25519().NewPrivateKey(seed)
		if err != nil {
			t.Fatal(err)
		}
		return key.PublicKey().Bytes()
	}
	ref := func() vault.KeyRef { return vault.KeyRef{ID: uuid.New(), Version: 1} }
	group, err := vault.SignGroupKeyManifest(vault.GroupKeyManifest{FormatVersion: 1, WorkspaceID: f.s.WorkspaceID,
		GroupID: uuid.New(), GroupRevision: 1, RosterDigest: bytes.Repeat([]byte{12}, 32), Signer: signer,
		Key: vault.BoundaryKey{Key: ref(), Public: public(groupSeed)}, Recovery: ref()}, f.org)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := vault.SignBoundaryManifest(vault.BoundaryManifest{FormatVersion: 1, WorkspaceID: f.s.WorkspaceID,
		BoundaryID: uuid.New(), Revision: 1, OrgEscrow: true, Active: true, Signer: signer,
		View: vault.BoundaryKey{Key: ref(), Public: public(rootSeed)}, Secret: vault.BoundaryKey{Key: ref(), Public: public(bytes.Repeat([]byte{43}, 32))}}, f.org)
	if err != nil {
		t.Fatal(err)
	}
	scope := vault.BoundaryTrust{WorkspaceID: f.s.WorkspaceID, BoundaryID: manifest.BoundaryID,
		Signer: signer, Organisation: f.s.PublicKey, MinimumRevision: 1}
	issuer := vault.KeyCopyTrust{Issuer: signer, Public: f.s.PublicKey}
	root := manifest.View.Key
	orgSeed := f.org.Seed()
	defer vault.Wipe(orgSeed)
	seal := func(key, recipient vault.KeyRef, recipientPublic, material []byte) UnverifiedKeyCopy {
		t.Helper()
		binding := vault.KeyCopyBinding{WorkspaceID: f.s.WorkspaceID, Key: key, Holder: recipient, Issuer: signer}
		copy, err := vault.SealKeyCopy(material, binding, recipientPublic, orgSeed)
		if err != nil {
			t.Fatal(err)
		}
		return UnverifiedKeyCopy{Binding: binding, Copy: copy}
	}
	toJSON := func(v any) json.RawMessage {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	encode := func(m vault.GroupKeyManifest) string {
		t.Helper()
		raw, err := vault.EncodeGroupKeyManifest(m)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(raw)
	}
	member := seal(group.Key.Key, holder, public(keys.EncryptionPrivate), groupSeed)
	wrap := seal(root, group.Key.Key, group.Key.Public, rootSeed)
	copyWire := func(c UnverifiedKeyCopy) json.RawMessage { return toJSON(append(releaseCopyWire(t, c, 1, 7), nil)) }
	wire := groupBoundaryWire{GroupID: group.GroupID.String(), Manifest: encode(group), GroupCopy: copyWire(member), RootCopy: copyWire(wrap)}
	for _, tc := range []struct {
		name string
		edit func(*groupBoundaryWire)
		want error
	}{
		{"invalid group ID", func(w *groupBoundaryWire) { w.GroupID = "bad" }, ErrAdmissionResponse},
		{"different group", func(w *groupBoundaryWire) { w.GroupID = uuid.NewString() }, ErrAdmissionResponse},
		{"malformed manifest", func(w *groupBoundaryWire) { w.Manifest = "BADHEX" }, ErrAdmissionResponse},
		{"oversized manifest", func(w *groupBoundaryWire) {
			w.Manifest = string(bytes.Repeat([]byte{'0'}, 2*vault.MaxGroupKeyManifestBytes+2))
		}, ErrAdmissionResponse},
		{"wrong account recipient", func(w *groupBoundaryWire) { c := member; c.Binding.Holder = ref(); w.GroupCopy = copyWire(c) }, ErrAdmissionResponse},
		{"wrong root recipient", func(w *groupBoundaryWire) { c := wrap; c.Binding.Holder = ref(); w.RootCopy = copyWire(c) }, ErrAdmissionResponse},
		{"wrong issuer", func(w *groupBoundaryWire) { c := wrap; c.Binding.Issuer = ref(); w.RootCopy = copyWire(c) }, vault.ErrAuthentication},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := wire
			tc.edit(&bad)
			if opened, err := parseBoundaryRootCopy(toJSON(bad), request, root, holder, 1, 7, 24); opened != nil || !errors.Is(err, tc.want) {
				t.Fatal("invalid group path parsed", err)
			}
		})
	}
	raw := toJSON(wire)
	for _, bad := range []string{`{}`, `[]`, `[{`, "[" + string(raw) + "," + string(raw) + "]", "[" + string(raw) + "] true"} {
		if result, err := parseBoundaryRootCopies([]byte(bad), request, []vault.KeyRef{root}, holder, 1, 7, 24); result != nil || err != ErrAdmissionResponse {
			t.Fatal("an invalid root list was accepted", err)
		}
	}
	if _, err := parseBoundaryRootCopy(raw, request, root, holder, 1, 7, 23); err != ErrAdmissionResponse {
		t.Fatal("a pre-enrollment response accepted a group path", err)
	}
	result, err := parseBoundaryRootCopies(toJSON([]json.RawMessage{raw}), request, []vault.KeyRef{root}, holder, 1, 7, 24)
	if err != nil || len(result) != 1 || result[0].boundaryRecipient() != holder {
		t.Fatal("the certified group path did not decode to the account recipient", err)
	}
	copy := result[0]
	if seed, err := openBoundaryReleaseRoot(keys.EncryptionPrivate, copy, issuer, manifest, scope, vault.BoundaryView, f.s); seed != nil || err != ErrTrustState {
		t.Fatal("private key operation began before observing the group manifest", err)
	}
	observed, err := f.s.advanceBoundaryRootCopy(copy)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := openBoundaryReleaseRoot(keys.EncryptionPrivate, copy, issuer, manifest, scope, vault.BoundaryView, observed)
	defer vault.Wipe(opened)
	if err != nil || !bytes.Equal(opened, rootSeed) {
		t.Fatal("opening a signed group chain did not return the View root", err)
	}
	if seed, err := openBoundaryReleaseRoot(keys.EncryptionPrivate, copy, issuer, manifest, scope, vault.BoundarySecret, observed); seed != nil || err != vault.ErrAuthentication {
		t.Fatal("a View root was lent as a Secret root", err)
	}
	personal := manifest
	personal.OwnerUserID = f.s.UserID
	personal, err = vault.SignBoundaryManifest(personal, f.org)
	if err != nil {
		t.Fatal(err)
	}
	if seed, err := openBoundaryReleaseRoot(keys.EncryptionPrivate, copy, issuer, personal, scope, vault.BoundaryView, observed); seed != nil || err != vault.ErrAuthentication {
		t.Fatal("a group opened a personal boundary", err)
	}
	// Both copy signatures are verified before opening either HPKE envelope.
	corrupt := func(proof []byte) []byte {
		result := bytes.Clone(proof)
		result[0] ^= 1
		return result
	}
	for _, tamper := range []func(*UnverifiedKeyCopy){
		func(c *UnverifiedKeyCopy) { c.Copy.Signature = corrupt(c.Copy.Signature) },
		func(c *UnverifiedKeyCopy) { c.group.copy.Copy.Signature = corrupt(c.group.copy.Copy.Signature) },
	} {
		damaged, hop := copy, *copy.group
		damaged.group = &hop
		tamper(&damaged)
		state, err := f.s.advanceBoundaryRootCopy(damaged)
		if err != vault.ErrAuthentication || state.Catalog["group-key/"+group.GroupID.String()].Revision != 1 {
			t.Fatal("copy verification failed to preserve an independently signed observation", err)
		}
	}
	rotated := group
	rotated.GroupRevision++
	rotated.Key.Key.Version++
	rotated, err = vault.SignGroupKeyManifest(rotated, f.org)
	if err != nil {
		t.Fatal(err)
	}
	newer, err := observed.AdvanceGroupKey(group.GroupID, rotated)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newer.advanceBoundaryRootCopy(copy); err != vault.ErrRollback {
		t.Fatal("a group key below the committed generation was accepted", err)
	}
}
