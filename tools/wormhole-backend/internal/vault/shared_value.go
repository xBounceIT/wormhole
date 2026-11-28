package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"math"
	"strconv"

	"github.com/google/uuid"
)

// SharedValueBinding is derived from authenticated selection and signed field
// manifests, never from an envelope's self-description. Version is the field
// version, not the profile/node revision or DEK version.
type SharedValueBinding struct {
	WorkspaceID uuid.UUID
	OwnerKind   string
	OwnerID     uuid.UUID
	Field       string
	Version     uint64
	DEK         KeyRef
}

func (b SharedValueBinding) binding() (Binding, error) {
	switch b.OwnerKind {
	case "credential", "node", "tunnel", "slot-value":
	default:
		return Binding{}, ErrFormat
	}
	if b.WorkspaceID == uuid.Nil || b.OwnerID == uuid.Nil || !validText(b.Field, 128, false) || b.Version == 0 || b.Version > math.MaxInt64 || b.DEK.ID == uuid.Nil || b.DEK.Version == 0 || b.DEK.Version > math.MaxInt32 {
		return Binding{}, ErrFormat
	}
	return Binding{WorkspaceID: b.WorkspaceID.String(), Table: "SecretValues/" + b.OwnerKind, OwnerID: b.OwnerID.String(), Field: "shared/v1/" + strconv.FormatUint(b.Version, 10) + "/" + b.Field, KeyID: b.DEK.ID.String(), KeyVersion: b.DEK.Version}, nil
}

func SealSharedValue(dek []byte, b SharedValueBinding, plaintext []byte) (Envelope, error) {
	binding, err := b.binding()
	if err != nil {
		return Envelope{}, err
	}
	return Seal(dek, binding, plaintext)
}

type BoundaryPurpose string

const (
	BoundaryView   BoundaryPurpose = "view"
	BoundarySecret BoundaryPurpose = "secret"
)

// KeyCopyTrust is independently authenticated issuer material: the pinned org
// signing key, or a current certified member after its state/certificate floors
// have been durably advanced. A server-returned public key alone is not trust.
type KeyCopyTrust struct {
	Issuer KeyRef
	Public ed25519.PublicKey
}

func boundaryRoot(m BoundaryManifest, trust BoundaryTrust, purpose BoundaryPurpose, key KeyRef) (BoundaryKey, error) {
	if err := VerifyBoundaryManifest(m, trust); err != nil {
		return BoundaryKey{}, err
	}
	if !m.Active {
		return BoundaryKey{}, ErrPolicy
	}
	var current BoundaryKey
	var previous *BoundaryKey
	switch purpose {
	case BoundaryView:
		current, previous = m.View, m.PreviousView
	case BoundarySecret:
		current, previous = m.Secret, m.PreviousSecret
	default:
		return BoundaryKey{}, ErrFormat
	}
	if key == current.Key {
		return current, nil
	}
	if previous != nil && key == previous.Key {
		return *previous, nil
	}
	return BoundaryKey{}, ErrAuthentication
}
func boundaryPrivateMatches(private []byte, root BoundaryKey) bool {
	key, err := ecdh.X25519().NewPrivateKey(private)
	return err == nil && bytes.Equal(key.PublicKey().Bytes(), root.Public)
}

// OpenBoundaryKeyCopy opens only a selected current/explicit previous root, then
// verifies its derived public key against the org-signed manifest. The caller
// must first durably observe the manifest and current issuer state and authorize
// the operation. Returned temporary seed must be wiped; resident ownership must
// move it to securemem. This primitive confers no DB/release permission.
func OpenBoundaryKeyCopy(private []byte, b KeyCopyBinding, c SignedKeyCopy, issuer KeyCopyTrust, m BoundaryManifest, trust BoundaryTrust, purpose BoundaryPurpose) ([]byte, error) {
	root, err := boundaryRoot(m, trust, purpose, b.Key)
	if err != nil {
		return nil, err
	}
	if b.WorkspaceID != trust.WorkspaceID || b.Issuer != issuer.Issuer {
		return nil, ErrAuthentication
	}
	seed, err := OpenKeyCopy(private, b, c, issuer.Public)
	if err != nil {
		return nil, err
	}
	if !boundaryPrivateMatches(seed, root) {
		Wipe(seed)
		return nil, ErrAuthentication
	}
	return seed, nil
}

// OpenSharedValue follows an authenticated DEK copy through a SECRET root only.
// Expected field binding, root ref and copy issuer must come from the verified
// release graph; the caller must persist all manifest/field/issuer observations
// and authorize/audit before opening. AAD binds owner kind/ID, field AND version,
// so moving ciphertext or relabeling an old value with a new row version fails.
// Root rotation rewraps the DEK without re-encrypting the value. Returned plaintext
// is temporary native memory; wipe it immediately after sealing to the protocol.
func OpenSharedValue(boundaryPrivate []byte, rootKey KeyRef, b SharedValueBinding, c SignedKeyCopy, issuer KeyCopyTrust, envelope Envelope, m BoundaryManifest, trust BoundaryTrust) ([]byte, error) {
	return openSharedValue(boundaryPrivate, rootKey, b, c, issuer, envelope, m, trust, BoundarySecret)
}

// OpenSharedNote uses a signed view root exclusively for an imported node note.
// The caller must authenticate the signed field revision and commit its trust
// observations before borrowing the view key.
func OpenSharedNote(boundaryPrivate []byte, rootKey KeyRef, b SharedValueBinding, c SignedKeyCopy, issuer KeyCopyTrust, envelope Envelope, m BoundaryManifest, trust BoundaryTrust) ([]byte, error) {
	if b.OwnerKind != "node" || b.Field != "notes" {
		return nil, ErrFormat
	}
	return openSharedValue(boundaryPrivate, rootKey, b, c, issuer, envelope, m, trust, BoundaryView)
}

func openSharedValue(boundaryPrivate []byte, rootKey KeyRef, b SharedValueBinding, c SignedKeyCopy, issuer KeyCopyTrust, envelope Envelope, m BoundaryManifest, trust BoundaryTrust, purpose BoundaryPurpose) ([]byte, error) {
	binding, err := b.binding()
	if err != nil {
		return nil, err
	}
	if b.WorkspaceID != trust.WorkspaceID || b.DEK.ID == rootKey.ID {
		return nil, ErrAuthentication
	}
	root, err := boundaryRoot(m, trust, purpose, rootKey)
	if err != nil {
		return nil, err
	}
	if !boundaryPrivateMatches(boundaryPrivate, root) {
		return nil, ErrAuthentication
	}
	copyBinding := KeyCopyBinding{WorkspaceID: b.WorkspaceID, Key: b.DEK, Holder: rootKey, Issuer: issuer.Issuer}
	dek, err := OpenKeyCopy(boundaryPrivate, copyBinding, c, issuer.Public)
	if err != nil {
		return nil, err
	}
	defer Wipe(dek)
	return Open(dek, binding, envelope)
}
