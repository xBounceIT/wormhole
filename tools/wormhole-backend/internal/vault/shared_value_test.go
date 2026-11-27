package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"math"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type sharedGraphFixture struct {
	user, root, dek   []byte
	org               ed25519.PrivateKey
	manifest          BoundaryManifest
	trust             BoundaryTrust
	issuer            KeyCopyTrust
	rootBinding       KeyCopyBinding
	rootCopy, dekCopy SignedKeyCopy
	binding           SharedValueBinding
	envelope          Envelope
}

func sharedGraph(t *testing.T) sharedGraphFixture {
	t.Helper()
	m, p, org := boundaryManifestFixture(t)
	f := sharedGraphFixture{user: bytes.Repeat([]byte{17}, 32), root: bytes.Repeat([]byte{2}, 32), dek: bytes.Repeat([]byte{23}, 32), org: org, manifest: m, trust: p, issuer: KeyCopyTrust{Issuer: m.Signer, Public: p.Organisation}}
	t.Cleanup(func() { Wipe(f.user); Wipe(f.root); Wipe(f.dek); Wipe(org) })
	user, e := ecdh.X25519().NewPrivateKey(f.user)
	if e != nil {
		t.Fatal(e)
	}
	f.rootBinding = KeyCopyBinding{WorkspaceID: m.WorkspaceID, Key: m.Secret.Key, Holder: KeyRef{ID: uuid.New(), Version: 9}, Issuer: m.Signer}
	f.rootCopy, e = SealKeyCopy(f.root, f.rootBinding, user.PublicKey().Bytes(), org.Seed())
	if e != nil {
		t.Fatal(e)
	}
	f.binding = SharedValueBinding{WorkspaceID: m.WorkspaceID, OwnerKind: "credential", OwnerID: uuid.New(), Field: "password", Version: 5, DEK: KeyRef{ID: uuid.New(), Version: 4}}
	f.dekCopy, e = SealKeyCopy(f.dek, KeyCopyBinding{WorkspaceID: m.WorkspaceID, Key: f.binding.DEK, Holder: m.Secret.Key, Issuer: m.Signer}, m.Secret.Public, org.Seed())
	if e != nil {
		t.Fatal(e)
	}
	f.envelope, e = SealSharedValue(f.dek, f.binding, []byte("native-only secret"))
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func TestSharedValueEndToEnd(t *testing.T) {
	f := sharedGraph(t)
	if e := VerifyKeyCopy(f.rootBinding, f.rootCopy, f.issuer.Public); e != nil {
		t.Fatal("public verification without private key", e)
	}
	badBinding := f.rootBinding
	badBinding.Holder.Version++
	if e := VerifyKeyCopy(badBinding, f.rootCopy, f.issuer.Public); e != ErrAuthentication {
		t.Fatal("public verification ignored holder context", e)
	}
	root, e := OpenBoundaryKeyCopy(f.user, f.rootBinding, f.rootCopy, f.issuer, f.manifest, f.trust, BoundarySecret)
	if e != nil || !bytes.Equal(root, f.root) {
		t.Fatal("root", e)
	}
	defer Wipe(root)
	plain, e := OpenSharedValue(root, f.manifest.Secret.Key, f.binding, f.dekCopy, f.issuer, f.envelope, f.manifest, f.trust)
	if e != nil || !bytes.Equal(plain, []byte("native-only secret")) {
		t.Fatal("value", e)
	}
	Wipe(plain)
	for _, kind := range []string{"credential", "node", "tunnel", "slot-value"} {
		b := f.binding
		b.OwnerKind = kind
		b.Field = "field/with:delimiters"
		envelope, e := SealSharedValue(f.dek, b, nil)
		if e != nil {
			t.Fatal(e)
		}
		empty, e := OpenSharedValue(root, f.manifest.Secret.Key, b, f.dekCopy, f.issuer, envelope, f.manifest, f.trust)
		if e != nil || len(empty) != 0 {
			t.Fatal("empty tombstone", e)
		}
		Wipe(empty)
	}
}
func TestSharedValueRejectsRelabelingAndGraphTamper(t *testing.T) {
	for _, mode := range []string{"workspace", "owner-kind", "owner-id", "field", "field-version", "dek-id", "dek-version", "view-key", "wrong-root", "issuer-id", "issuer-public", "copy-signature", "value-nonce", "value-ciphertext", "manifest-signature", "wrong-version-private"} {
		t.Run(mode, func(t *testing.T) {
			f := sharedGraph(t)
			rootKey := f.manifest.Secret.Key
			switch mode {
			case "workspace":
				f.binding.WorkspaceID = uuid.New()
			case "owner-kind":
				f.binding.OwnerKind = "node"
			case "owner-id":
				f.binding.OwnerID = uuid.New()
			case "field":
				f.binding.Field = "passphrase"
			case "field-version":
				f.binding.Version++
			case "dek-id":
				f.binding.DEK.ID = uuid.New()
			case "dek-version":
				f.binding.DEK.Version++
			case "view-key":
				rootKey = f.manifest.View.Key
				f.root = bytes.Repeat([]byte{1}, 32)
				var e error
				f.dekCopy, e = SealKeyCopy(f.dek, KeyCopyBinding{WorkspaceID: f.binding.WorkspaceID, Key: f.binding.DEK, Holder: rootKey, Issuer: f.manifest.Signer}, f.manifest.View.Public, f.org.Seed())
				if e != nil {
					t.Fatal(e)
				}
			case "wrong-root":
				f.root = bytes.Repeat([]byte{18}, 32)
			case "issuer-id":
				f.issuer.Issuer.ID = uuid.New()
			case "issuer-public":
				f.issuer.Public = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{19}, 32)).Public().(ed25519.PublicKey)
			case "copy-signature":
				f.dekCopy.Signature = make([]byte, 64)
			case "value-nonce":
				f.envelope.Nonce = nil
			case "value-ciphertext":
				f.envelope.Ciphertext = bytes.Clone(f.envelope.Ciphertext)
				f.envelope.Ciphertext[0] ^= 1
			case "manifest-signature":
				f.manifest.Signature = make([]byte, 64)
			case "wrong-version-private":
				rootKey.Version--
			}
			plain, e := OpenSharedValue(f.root, rootKey, f.binding, f.dekCopy, f.issuer, f.envelope, f.manifest, f.trust)
			if e == nil || plain != nil {
				Wipe(plain)
				t.Fatal("graph/relabel accepted", mode, e)
			}
			if mode == "field-version" && e != ErrAuthentication {
				t.Fatal("version was not authenticated in AEAD", e)
			}
		})
	}
}
func TestBoundaryKeyCopyPublicPinAndPrevious(t *testing.T) {
	f := sharedGraph(t)
	user, _ := ecdh.X25519().NewPrivateKey(f.user)
	for _, mode := range []string{"workspace", "issuer", "key", "holder", "wrong-seed", "wrong-private", "signature", "purpose", "inactive", "view", "previous-secret", "previous-view"} {
		t.Run(mode, func(t *testing.T) {
			f := sharedGraph(t)
			want := f.root
			var e error
			purpose := BoundarySecret
			switch mode {
			case "workspace":
				f.rootBinding.WorkspaceID = uuid.New()
			case "issuer":
				f.issuer.Issuer.ID = uuid.New()
			case "key":
				f.rootBinding.Key.ID = uuid.New()
			case "holder":
				f.rootBinding.Holder.Version++
			case "wrong-seed":
				f.rootCopy, e = SealKeyCopy(bytes.Repeat([]byte{99}, 32), f.rootBinding, user.PublicKey().Bytes(), f.org.Seed())
			case "wrong-private":
				f.user = []byte("bad")
			case "signature":
				f.rootCopy.Signature = nil
			case "purpose":
				purpose = "invalid"
			case "inactive":
				f.manifest.Active = false
				f.manifest, e = SignBoundaryManifest(f.manifest, f.org)
			case "view":
				purpose = BoundaryView
				f.rootBinding.Key = f.manifest.View.Key
				want = bytes.Repeat([]byte{1}, 32)
			case "previous-secret":
				f.rootBinding.Key = f.manifest.PreviousSecret.Key
				want = bytes.Repeat([]byte{4}, 32)
			case "previous-view":
				purpose = BoundaryView
				f.rootBinding.Key = f.manifest.PreviousView.Key
				want = bytes.Repeat([]byte{3}, 32)
			}
			if e != nil {
				t.Fatal(e)
			}
			positive := mode == "view" || mode == "previous-secret" || mode == "previous-view"
			if positive {
				f.rootCopy, e = SealKeyCopy(want, f.rootBinding, user.PublicKey().Bytes(), f.org.Seed())
				if e != nil {
					t.Fatal(e)
				}
			}
			opened, e := OpenBoundaryKeyCopy(f.user, f.rootBinding, f.rootCopy, f.issuer, f.manifest, f.trust, purpose)
			if positive {
				if e != nil || !bytes.Equal(opened, want) {
					t.Fatal("selected root", mode, e)
				}
				Wipe(opened)
			} else if e == nil || opened != nil {
				Wipe(opened)
				t.Fatal("invalid root accepted", mode, e)
			}
		})
	}
}
func TestSharedValueRotationRewrapOnly(t *testing.T) {
	f := sharedGraph(t)
	m := cloneBoundaryFixture(t, f.manifest)
	old := m.Secret
	m.PreviousSecret = &old
	m.Revision++
	m.Secret.Key.Version++
	seed := bytes.Repeat([]byte{7}, 32)
	defer Wipe(seed)
	private, _ := ecdh.X25519().NewPrivateKey(seed)
	m.Secret.Public = private.PublicKey().Bytes()
	m, e := SignBoundaryManifest(m, f.org)
	if e != nil {
		t.Fatal(e)
	}
	copy, e := SealKeyCopy(f.dek, KeyCopyBinding{WorkspaceID: m.WorkspaceID, Key: f.binding.DEK, Holder: m.Secret.Key, Issuer: m.Signer}, m.Secret.Public, f.org.Seed())
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range []struct {
		seed []byte
		root KeyRef
		copy SignedKeyCopy
	}{{f.root, old.Key, f.dekCopy}, {seed, m.Secret.Key, copy}} {
		plain, e := OpenSharedValue(entry.seed, entry.root, f.binding, entry.copy, f.issuer, f.envelope, m, f.trust)
		if e != nil || !bytes.Equal(plain, []byte("native-only secret")) {
			t.Fatal("resumable rewrap", e)
		}
		Wipe(plain)
	}
	m.PreviousSecret = nil
	m.Revision++
	m, e = SignBoundaryManifest(m, f.org)
	if e != nil {
		t.Fatal(e)
	}
	if plain, e := OpenSharedValue(f.root, old.Key, f.binding, f.dekCopy, f.issuer, f.envelope, m, f.trust); e != ErrAuthentication || plain != nil {
		Wipe(plain)
		t.Fatal("old root still accepted", e)
	}
}
func TestSharedValueBindingBounds(t *testing.T) {
	f := sharedGraph(t)
	for _, change := range []func(*SharedValueBinding){func(b *SharedValueBinding) { b.OwnerKind = "local-state" }, func(b *SharedValueBinding) { b.WorkspaceID = uuid.Nil }, func(b *SharedValueBinding) { b.OwnerID = uuid.Nil }, func(b *SharedValueBinding) { b.Field = "" }, func(b *SharedValueBinding) { b.Field = "bad\x00" }, func(b *SharedValueBinding) { b.Field = string([]byte{255}) }, func(b *SharedValueBinding) { b.Field = strings.Repeat("x", 129) }, func(b *SharedValueBinding) { b.Version = 0 }, func(b *SharedValueBinding) { b.Version = math.MaxUint64 }, func(b *SharedValueBinding) { b.DEK.ID = uuid.Nil }, func(b *SharedValueBinding) { b.DEK.Version = 0 }, func(b *SharedValueBinding) { b.DEK.Version = math.MaxUint32 }} {
		b := f.binding
		change(&b)
		if _, e := SealSharedValue(f.dek, b, nil); e != ErrFormat {
			t.Fatal(e)
		}
		if plain, e := OpenSharedValue(f.root, f.manifest.Secret.Key, b, f.dekCopy, f.issuer, f.envelope, f.manifest, f.trust); e != ErrFormat || plain != nil {
			t.Fatal(e)
		}
	}
	b := f.binding
	b.Field = strings.Repeat("x", 128)
	b.Version = math.MaxInt64
	b.DEK.Version = math.MaxInt32
	if _, e := SealSharedValue(f.dek, b, nil); e != nil {
		t.Fatal("bounds", e)
	}
	if _, e := SealSharedValue(nil, f.binding, nil); e != ErrFormat {
		t.Fatal(e)
	}
	b = f.binding
	b.DEK = f.manifest.Secret.Key
	if plain, e := OpenSharedValue(f.root, f.manifest.Secret.Key, b, f.dekCopy, f.issuer, f.envelope, f.manifest, f.trust); e != ErrAuthentication || plain != nil {
		t.Fatal("root as DEK", e)
	}
}

func TestSharedValueSealedProtocolHandoff(t *testing.T) {
	f := sharedGraph(t)
	root, e := OpenBoundaryKeyCopy(f.user, f.rootBinding, f.rootCopy, f.issuer, f.manifest, f.trust, BoundarySecret)
	if e != nil {
		t.Fatal(e)
	}
	defer Wipe(root)
	plain, e := OpenSharedValue(root, f.manifest.Secret.Key, f.binding, f.dekCopy, f.issuer, f.envelope, f.manifest, f.trust)
	if e != nil {
		t.Fatal(e)
	}
	frame, e := EncodeSSHBundle(SSHBundlePayload{Username: "account", Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), Password: plain})
	Wipe(plain)
	if e != nil {
		t.Fatal(e)
	}
	recipientBytes := bytes.Repeat([]byte{31}, 32)
	defer Wipe(recipientBytes)
	recipient, e := ecdh.X25519().NewPrivateKey(recipientBytes)
	if e != nil {
		Wipe(frame)
		t.Fatal(e)
	}
	binding := BundleBinding{WorkspaceID: f.binding.WorkspaceID.String(), SessionID: uuid.NewString(), RequestID: uuid.NewString(), NodeID: uuid.NewString(), Protocol: "ssh", Host: "server.example", Port: 22, Epoch: 1}
	opaque, e := SealBundle(recipient.PublicKey().Bytes(), binding, frame)
	Wipe(frame)
	if e != nil {
		t.Fatal(e)
	}
	opened, e := OpenBundle(recipientBytes, binding, opaque)
	if e != nil {
		t.Fatal(e)
	}
	defer Wipe(opened)
	payload, e := DecodeSSHBundle(opened)
	if e != nil || payload.Username != "account" || !bytes.Equal(payload.Password, []byte("native-only secret")) {
		t.Fatal("protocol handoff", e)
	}
	wrong := binding
	wrong.Host = "attacker.example"
	if data, e := OpenBundle(recipientBytes, wrong, opaque); e == nil || data != nil {
		Wipe(data)
		t.Fatal("redirected protocol handoff", e)
	}
}
