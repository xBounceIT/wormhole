package vault

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"math"

	"github.com/google/uuid"
)

// BoundaryRotationDEK binds one existing copy to its independently certified
// issuer. The storage adapter must select the complete copy set while holding
// its authorization snapshot. Rewrapping consumes no stored SecretValues.
type BoundaryRotationDEK struct {
	Binding KeyCopyBinding
	Copy    SignedKeyCopy
	Issuer  KeyCopyTrust
}

type BoundaryRootRotation struct {
	Purpose    BoundaryPurpose
	Escrow     SignedKeyCopy
	Recipients []BoundaryKey
	DEKs       []BoundaryRotationDEK
}

type PreparedBoundaryRotation struct {
	Manifest BoundaryManifest
	Copies   []RewrappedKeyCopy
}

// PrepareBoundaryRotation advances one or both roots of an escrowed shared
// boundary. The caller authenticates the retained recipients and commits the
// complete copies and their signed manifest under the original authorization
// snapshot. All private keys created here are temporary. An error or cancel
// discards the publication and leaves the existing manifest usable.
func PrepareBoundaryRotation(ctx context.Context, current BoundaryManifest, trust BoundaryTrust,
	recovery OrganisationRecoveryRecipient, recoveryProof []byte, org *UserKeys, roots []BoundaryRootRotation) (*PreparedBoundaryRotation, error) {
	return prepareBoundaryRotation(ctx, current, trust, uuid.Nil, recovery, recoveryProof, org, roots)
}

// PreparePersonalBoundaryRotation leaves a suspended owner's replacement
// roots in organisation custody and binds the rotation to the signed owner.
func PreparePersonalBoundaryRotation(ctx context.Context, current BoundaryManifest, trust BoundaryTrust, owner uuid.UUID,
	recovery OrganisationRecoveryRecipient, recoveryProof []byte, org *UserKeys, roots []BoundaryRootRotation) (*PreparedBoundaryRotation, error) {
	if owner == uuid.Nil {
		return nil, ErrPolicy
	}
	return prepareBoundaryRotation(ctx, current, trust, owner, recovery, recoveryProof, org, roots)
}

func prepareBoundaryRotation(ctx context.Context, current BoundaryManifest, trust BoundaryTrust, owner uuid.UUID,
	recovery OrganisationRecoveryRecipient, recoveryProof []byte, org *UserKeys, roots []BoundaryRootRotation) (*PreparedBoundaryRotation, error) {
	if ctx == nil || org == nil || len(roots) == 0 || len(roots) > 2 {
		return nil, ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := VerifyBoundaryManifest(current, trust); err != nil {
		return nil, err
	}
	if !current.Active || !current.OrgEscrow || current.OwnerUserID != owner || current.PreviousView != nil || current.PreviousSecret != nil || current.Revision == math.MaxInt64 {
		return nil, ErrPolicy
	}
	if err := VerifyOrganisationRecoveryRecipient(recovery, recoveryProof, trust.WorkspaceID, trust.Signer, trust.Organisation); err != nil {
		return nil, err
	}
	public, err := org.Public()
	if err != nil || !bytes.Equal(public.Signing, trust.Organisation) || !bytes.Equal(public.Encryption, recovery.PublicKey) {
		return nil, ErrAuthentication
	}
	next := &PreparedBoundaryRotation{Manifest: current}
	next.Manifest.Revision++
	orgSigner := ed25519.NewKeyFromSeed(org.SigningSeed)
	defer Wipe(orgSigner)
	replaced := make(map[BoundaryPurpose]bool, len(roots))
	seenDEKs := make(map[KeyRef]bool)
	for _, root := range roots {
		if owner != uuid.Nil && (len(root.Recipients) != 1 || root.Recipients[0].Key != recovery.Encryption) {
			return nil, ErrPolicy
		}
		if replaced[root.Purpose] {
			return nil, ErrFormat
		}
		replaced[root.Purpose] = true
		var old BoundaryKey
		switch root.Purpose {
		case BoundaryView:
			old = current.View
		case BoundarySecret:
			old = current.Secret
		default:
			return nil, ErrFormat
		}
		key, copies, err := rotateBoundaryRoot(ctx, current, trust, recovery, org, old, root, seenDEKs)
		if err != nil {
			return nil, err
		}
		if root.Purpose == BoundaryView {
			next.Manifest.View = key
		} else {
			next.Manifest.Secret = key
		}
		next.Copies = append(next.Copies, copies...)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	next.Manifest, err = SignBoundaryManifest(next.Manifest, orgSigner)
	if err != nil {
		return nil, err
	}
	return next, nil
}

func rotateBoundaryRoot(ctx context.Context, current BoundaryManifest, trust BoundaryTrust, recovery OrganisationRecoveryRecipient,
	org *UserKeys, old BoundaryKey, root BoundaryRootRotation, seenDEKs map[KeyRef]bool) (BoundaryKey, []RewrappedKeyCopy, error) {
	if old.Key.Version == math.MaxInt32 || len(root.Recipients) == 0 {
		return BoundaryKey{}, nil, ErrFormat
	}
	issuer := KeyCopyTrust{Issuer: trust.Signer, Public: trust.Organisation}
	source := KeyCopyBinding{WorkspaceID: trust.WorkspaceID, Key: old.Key, Holder: recovery.Encryption, Issuer: trust.Signer}
	oldSeed, err := OpenBoundaryKeyCopy(org.EncryptionPrivate, source, root.Escrow, issuer, current, trust, root.Purpose)
	if err != nil {
		return BoundaryKey{}, nil, err
	}
	defer Wipe(oldSeed)
	var seed [32]byte
	defer Wipe(seed[:])
	rand.Read(seed[:])
	private, err := ecdh.X25519().NewPrivateKey(seed[:])
	if err != nil {
		return BoundaryKey{}, nil, err
	}
	next := BoundaryKey{Key: old.Key, Public: private.PublicKey().Bytes()}
	next.Key.Version++
	copies := make([]RewrappedKeyCopy, 0, len(root.Recipients)+len(root.DEKs))
	recipients := make(map[uuid.UUID]bool, len(root.Recipients))
	haveRecovery := false
	for _, recipient := range root.Recipients {
		if err := ctx.Err(); err != nil {
			return BoundaryKey{}, nil, err
		}
		id := recipient.Key.ID
		if recipients[id] || id == current.View.Key.ID || id == current.Secret.Key.ID || id == trust.Signer.ID {
			return BoundaryKey{}, nil, ErrFormat
		}
		recipients[id] = true
		if id == recovery.Encryption.ID {
			if recipient.Key != recovery.Encryption || !bytes.Equal(recipient.Public, recovery.PublicKey) {
				return BoundaryKey{}, nil, ErrAuthentication
			}
			haveRecovery = true
		} else if bytes.Equal(recipient.Public, recovery.PublicKey) {
			return BoundaryKey{}, nil, ErrAuthentication
		}
		b := KeyCopyBinding{WorkspaceID: trust.WorkspaceID, Key: next.Key, Holder: recipient.Key, Issuer: trust.Signer}
		copy, err := SealKeyCopy(seed[:], b, recipient.Public, org.SigningSeed)
		if err != nil {
			return BoundaryKey{}, nil, err
		}
		copies = append(copies, RewrappedKeyCopy{Binding: b, Copy: copy})
	}
	if !haveRecovery {
		return BoundaryKey{}, nil, ErrPolicy
	}
	for _, dek := range root.DEKs {
		if err := ctx.Err(); err != nil {
			return BoundaryKey{}, nil, err
		}
		b := dek.Binding
		if b.WorkspaceID != trust.WorkspaceID || b.Holder != old.Key || b.Issuer != dek.Issuer.Issuer ||
			b.Key.ID == current.View.Key.ID || b.Key.ID == current.Secret.Key.ID || recipients[b.Key.ID] || seenDEKs[b.Key] {
			return BoundaryKey{}, nil, ErrAuthentication
		}
		seenDEKs[b.Key] = true
		copy, err := RewrapKeyCopy(oldSeed, b, dek.Copy, dek.Issuer.Public, next.Key, next.Public, trust.Signer, org.SigningSeed)
		if err != nil {
			return BoundaryKey{}, nil, err
		}
		b.Holder, b.Issuer = next.Key, trust.Signer
		copies = append(copies, RewrappedKeyCopy{Binding: b, Copy: copy})
	}
	return next, copies, nil
}
