package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"math"

	"github.com/google/uuid"
)

const MaxGroupKeyManifestBytes = 4096

// GroupKeyManifest authenticates the current public recipient and the reviewed
// membership snapshot used to distribute its private key. It conveys no node
// or boundary permission.
type GroupKeyManifest struct {
	FormatVersion uint16      `json:"formatVersion"`
	WorkspaceID   uuid.UUID   `json:"workspaceId"`
	GroupID       uuid.UUID   `json:"groupId"`
	GroupRevision uint64      `json:"groupRevision"`
	RosterDigest  []byte      `json:"rosterDigest"`
	Key           BoundaryKey `json:"key"`
	Recovery      KeyRef      `json:"recovery"`
	Signer        KeyRef      `json:"signer"`
	Signature     []byte      `json:"signature"`
}

func (m GroupKeyManifest) signingBytes() ([]byte, error) {
	if m.FormatVersion > FormatVersion {
		return nil, ErrNewerFormat
	}
	if m.FormatVersion != FormatVersion || m.WorkspaceID == uuid.Nil || m.GroupID == uuid.Nil ||
		m.GroupRevision == 0 || m.GroupRevision >= math.MaxInt64 || len(m.RosterDigest) != sha256.Size ||
		validateX25519Public(m.Key.Public) != nil {
		return nil, ErrFormat
	}
	refs := []KeyRef{m.Key.Key, m.Recovery, m.Signer}
	for i, ref := range refs {
		if ref.ID == uuid.Nil || ref.Version == 0 || ref.Version > math.MaxInt32 {
			return nil, ErrFormat
		}
		for _, previous := range refs[:i] {
			if ref.ID == previous.ID {
				return nil, ErrFormat
			}
		}
	}
	m.Signature = nil
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, ErrFormat
	}
	return canonical("wormhole/v1/group-key-manifest", raw), nil
}

func SignGroupKeyManifest(m GroupKeyManifest, signer ed25519.PrivateKey) (GroupKeyManifest, error) {
	if len(signer) != ed25519.PrivateKeySize {
		return GroupKeyManifest{}, ErrFormat
	}
	raw, err := m.signingBytes()
	if err != nil {
		return GroupKeyManifest{}, err
	}
	m.Signature = ed25519.Sign(signer, raw)
	return m, nil
}

func VerifyGroupKeyManifest(m GroupKeyManifest, workspace, group uuid.UUID, signer KeyRef, public ed25519.PublicKey, minimum uint32) error {
	raw, err := m.signingBytes()
	if err != nil {
		return err
	}
	if m.WorkspaceID != workspace || m.GroupID != group || m.Signer != signer ||
		len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, raw, m.Signature) {
		return ErrAuthentication
	}
	if m.Key.Key.Version < minimum {
		return ErrRollback
	}
	return nil
}

func EncodeGroupKeyManifest(m GroupKeyManifest) ([]byte, error) {
	if _, err := m.signingBytes(); err != nil {
		return nil, err
	}
	if len(m.Signature) != ed25519.SignatureSize {
		return nil, ErrFormat
	}
	raw, err := json.Marshal(m)
	if err != nil || len(raw) > MaxGroupKeyManifestBytes {
		return nil, ErrFormat
	}
	return raw, nil
}

func DecodeGroupKeyManifest(raw []byte) (GroupKeyManifest, error) {
	if len(raw) == 0 || len(raw) > MaxGroupKeyManifestBytes {
		return GroupKeyManifest{}, ErrFormat
	}
	var result GroupKeyManifest
	if json.Unmarshal(raw, &result) != nil {
		return GroupKeyManifest{}, ErrFormat
	}
	encoded, err := EncodeGroupKeyManifest(result)
	if err != nil {
		return GroupKeyManifest{}, err
	}
	if !bytes.Equal(raw, encoded) {
		return GroupKeyManifest{}, ErrFormat
	}
	return result, nil
}

// OpenGroupKeyCopy authenticates both the expected holder and the public half
// output by HPKE before lending a seed for the next key-copy hop.
func OpenGroupKeyCopy(m GroupKeyManifest, workspace, group uuid.UUID, signer KeyRef, public ed25519.PublicKey, minimum uint32,
	holder KeyRef, private []byte, copy SignedKeyCopy) ([]byte, error) {
	if err := VerifyGroupKeyManifest(m, workspace, group, signer, public, minimum); err != nil {
		return nil, err
	}
	binding := KeyCopyBinding{WorkspaceID: workspace, Key: m.Key.Key, Holder: holder, Issuer: signer}
	seed, err := OpenKeyCopy(private, binding, copy, public)
	if err != nil {
		return nil, err
	}
	if !boundaryPrivateMatches(seed, m.Key) {
		Wipe(seed)
		return nil, ErrAuthentication
	}
	return seed, nil
}
