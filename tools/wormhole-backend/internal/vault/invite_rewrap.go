package vault

import (
	"context"
	"crypto/ed25519"
)

const MaxInviteKeyCopies = 1024

type RewrappedKeyCopy struct {
	Binding KeyCopyBinding `json:"binding"`
	Copy    SignedKeyCopy  `json:"copy"`
}

// InviteRewrapPlan is prepared native state, not a committed enrollment. The
// owner must protect Keys, commit the complete set atomically, and wipe on every
// terminal path. Wiping also retires the public plan to prevent accidental reuse.
type InviteRewrapPlan struct {
	Keys                   *UserKeys          `json:"-"`
	Proof                  InviteRekeyProof   `json:"proof"`
	Copies                 []RewrappedKeyCopy `json:"copies"`
	SourceManifestRevision uint64             `json:"sourceManifestRevision"`
	SourceManifestDigest   []byte             `json:"sourceManifestDigest"`
}

func (p *InviteRewrapPlan) Wipe() {
	if p == nil {
		return
	}
	p.Keys.Wipe()
	p.Keys = nil
	p.Proof = InviteRekeyProof{}
	p.Copies = nil
	p.SourceManifestRevision = 0
	p.SourceManifestDigest = nil
}

// PrepareInviteRewrap requires the complete expected copy set from an
// authenticated key graph and independently certified issuer keys. Array position
// pairs ciphertext with expected metadata; signatures reject reordered ciphertext.
// Equal counts alone do not authenticate completeness. This function neither
// fetches an authoritative graph nor consumes/commits a server-side invitation.
func PrepareInviteRewrap(ctx context.Context, c InviteContext, bootstrap *InviteBootstrap, expected []KeyCopyBinding, copies []SignedKeyCopy, issuers map[KeyRef]ed25519.PublicKey) (*InviteRewrapPlan, error) {
	if ctx == nil || len(expected) > MaxInviteKeyCopies || len(expected) != len(copies) {
		return nil, ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	seen := make(map[KeyRef]bool, len(expected))
	for i, b := range expected {
		if b.WorkspaceID != c.WorkspaceID || b.Holder.ID != c.KeyID || b.Holder.Version != c.KeyVersion || seen[b.Key] {
			return nil, ErrFormat
		}
		seen[b.Key] = true
		info, err := b.info()
		if err != nil {
			return nil, err
		}
		if _, err = keyCopySigningBytes(info, copies[i]); err != nil {
			return nil, err
		}
		if len(issuers[b.Issuer]) != ed25519.PublicKeySize || len(copies[i].Signature) != ed25519.SignatureSize {
			return nil, ErrFormat
		}
	}
	keys, proof, err := PrepareInviteRekey(c, bootstrap)
	if err != nil {
		return nil, err
	}
	p := &InviteRewrapPlan{Keys: keys, Proof: proof, Copies: make([]RewrappedKeyCopy, 0, len(expected))}
	success := false
	defer func() {
		if !success {
			p.Wipe()
		}
	}()
	newHolder := KeyRef{proof.EncryptionKeyID, proof.KeyVersion}
	newIssuer := KeyRef{proof.SigningKeyID, proof.KeyVersion}
	for i, b := range expected {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		copy, err := RewrapKeyCopy(bootstrap.EncryptionPrivate, b, copies[i], issuers[b.Issuer], newHolder, proof.Public.Encryption, newIssuer, keys.SigningSeed)
		if err != nil {
			return nil, err
		}
		b.Holder, b.Issuer = newHolder, newIssuer
		p.Copies = append(p.Copies, RewrappedKeyCopy{Binding: b, Copy: copy})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	success = true
	return p, nil
}
