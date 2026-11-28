package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"path/filepath"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const maxRootRotationPlainBytes = 8 * 1024 * 1024
const maxRootRotationJournalBytes = 14 * 1024 * 1024

type rootRotationFingerprint struct {
	Bytes  int64  `json:"bytes"`
	Digest string `json:"digest"`
}

// Native-only journal. Paths, database fingerprints and old-root recovery are
// encrypted under the newly confirmed root; no plaintext root is serialized.
type rootRotationJournal struct {
	Version        int                     `json:"version"`
	ID             string                  `json:"id"`
	Phase          vault.RootRotationPhase `json:"phase"`
	SourcePath     string                  `json:"sourcePath"`
	Source         vault.SlotFile          `json:"source"`
	Target         vault.SlotFile          `json:"target"`
	SourceDatabase rootRotationFingerprint `json:"sourceDatabase"`
	TargetDatabase rootRotationFingerprint `json:"targetDatabase"`
	SourceRecovery vault.Envelope          `json:"sourceRecovery"`
	Custody        *rootRotationCustody    `json:"custody,omitempty"`
}

type rootRotationCapsule struct {
	Version  int                `json:"version"`
	ID       string             `json:"id"`
	Document vault.SlotFile     `json:"document"`
	Bytes    int                `json:"bytes"`
	Chunks   rootRotationChunks `json:"chunks"`
}

type rootRotationChunks []vault.Envelope

// Reject excess chunks during decoding, before allocating an attacker-sized
// array of envelope structs from an unauthenticated bootstrap file.
func (chunks *rootRotationChunks) UnmarshalJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('[') {
		return vault.ErrFormat
	}
	var result rootRotationChunks
	for d.More() {
		if len(result) >= (maxRootRotationPlainBytes+vault.MaxSecretBytes-1)/vault.MaxSecretBytes {
			return vault.ErrFormat
		}
		var envelope vault.Envelope
		if d.Decode(&envelope) != nil {
			return vault.ErrFormat
		}
		result = append(result, envelope)
	}
	if token, err := d.Token(); err != nil || token != json.Delim(']') {
		return vault.ErrFormat
	}
	if d.Decode(new(any)) != io.EOF {
		return vault.ErrFormat
	}
	*chunks = result
	return nil
}

func rootRotationJournalPath(source string) string { return source + ".root-rotation" }
func (j rootRotationJournal) stagePath() string    { return j.SourcePath + ".rotating-" + j.ID + ".db" }
func (j rootRotationJournal) backupPath() string   { return j.SourcePath + ".retired-" + j.ID + ".db" }

func rootRotationSlotDigest(document vault.SlotFile) string {
	raw, _ := json.Marshal(document)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func validRootRotationDigest(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == s
}

func sameRootRotationDocument(a, b vault.SlotFile) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// Recover the old root only after the new document is authenticated. Callers
// wipe this native borrowed key on every return, including a later denial.
func authenticateRootRotationJournal(j rootRotationJournal, key []byte) ([]byte, error) {
	id, err := uuid.Parse(j.ID)
	s, n := j.Source, j.Target
	if (j.Version != 1 && j.Version != 2) || err != nil || id == uuid.Nil || id.String() != j.ID || (j.Phase.Step() == 0 && j.Phase != vault.RotationStaging) || !filepath.IsAbs(j.SourcePath) || filepath.Clean(j.SourcePath) != j.SourcePath || !legacyPublicationFilename(filepath.Base(j.SourcePath)) || len(j.SourcePath) > 4096 {
		return nil, vault.ErrFormat
	}
	if err := validateRootRotationCustody(j); err != nil {
		return nil, err
	}
	if j.Phase == vault.RotationStaging {
		if j.Version != 1 || !n.Encrypted || j.SourceDatabase != (rootRotationFingerprint{}) || j.TargetDatabase != (rootRotationFingerprint{}) {
			return nil, vault.ErrFormat
		}
	} else {
		for _, fp := range []rootRotationFingerprint{j.SourceDatabase, j.TargetDatabase} {
			if fp.Bytes < 512 || fp.Bytes > 1<<40 || !validRootRotationDigest(fp.Digest) {
				return nil, vault.ErrFormat
			}
		}
	}
	if s.Initializing || s.Migration != nil || s.Rotation != nil || n.Initializing || s.Encrypted && !n.Encrypted || n.Migration != nil || n.Rotation != nil || n.FormatVersion != vault.SlotFileFormatVersion || s.RootKeyVersion == math.MaxUint32 || n.RootKeyVersion != s.RootKeyVersion+1 || n.RootKeyID != s.RootKeyID || n.VaultID != s.VaultID || n.FileID != s.FileID || s.Sequence > math.MaxUint64-vault.RootRotationSequenceSpan || n.Sequence != s.Sequence+vault.RootRotationSequenceSpan || s.FileEpoch == math.MaxUint64 || n.FileEpoch != s.FileEpoch+1 || n.ProfileSequence < s.ProfileSequence {
		return nil, vault.ErrFormat
	}
	if err := vault.VerifySlotFile(key, n, n.VaultID, n.FileID, n.Sequence); err != nil {
		return nil, err
	}
	password, recovery := false, false
	for _, slot := range n.Slots {
		if slot.WrappedKey.KeyVersion != n.RootKeyVersion {
			return nil, vault.ErrFormat
		}
		switch slot.Kind {
		case vault.SlotPassword:
			password = true
		case vault.SlotRecovery:
			recovery = true
		default:
			return nil, vault.ErrPolicy
		}
	}
	if !password || !recovery {
		return nil, vault.ErrPolicy
	}
	nodes, tunnels := map[string]uint64{}, map[string]uint64{}
	anchors := map[string]vault.VPNSSOHighWater{}
	for _, mark := range n.Nodes {
		nodes[mark.NodeID] = mark.Revision
	}
	for _, mark := range n.Tunnels {
		tunnels[mark.TunnelID] = mark.Revision
	}
	for _, mark := range n.VPNSSO {
		anchors[mark.ScopeID] = mark
	}
	for _, mark := range s.Nodes {
		if nodes[mark.NodeID] < mark.Revision {
			return nil, vault.ErrRollback
		}
	}
	for _, mark := range s.Tunnels {
		if tunnels[mark.TunnelID] < mark.Revision {
			return nil, vault.ErrRollback
		}
	}
	for _, mark := range s.VPNSSO {
		if !anchors[mark.ScopeID].Advances(mark) {
			return nil, vault.ErrRollback
		}
	}
	old, err := vault.Open(key, vault.RootRotationRecoveryBinding(s, n), j.SourceRecovery)
	if err != nil {
		return nil, err
	}
	if err := vault.VerifySlotFile(old, s, n.VaultID, n.FileID, s.Sequence); err != nil {
		vault.Wipe(old)
		return nil, err
	}
	if bytes.Equal(old, key) {
		vault.Wipe(old)
		return nil, vault.ErrPolicy
	}
	return old, nil
}

func rootRotationChunkBinding(c rootRotationCapsule, index int) vault.Binding {
	return vault.Binding{WorkspaceID: c.Document.VaultID, Table: "LocalRootRotation/journal-v" + strconv.Itoa(c.Version), OwnerID: c.Document.FileID,
		Field: c.ID + "/" + rootRotationSlotDigest(c.Document) + "/" + strconv.Itoa(c.Bytes) + "/" + strconv.Itoa(len(c.Chunks)) + "/" + strconv.Itoa(index), KeyID: c.Document.RootKeyID, KeyVersion: c.Document.RootKeyVersion}
}

func encodeRootRotationJournal(ctx context.Context, j rootRotationJournal, key []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	old, err := authenticateRootRotationJournal(j, key)
	vault.Wipe(old)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(j)
	defer vault.Wipe(plain)
	if err != nil || len(plain) == 0 || len(plain) > maxRootRotationPlainBytes {
		return nil, vault.ErrFormat
	}
	c := rootRotationCapsule{Version: j.Version, ID: j.ID, Document: j.Target, Bytes: len(plain), Chunks: make([]vault.Envelope, (len(plain)+vault.MaxSecretBytes-1)/vault.MaxSecretBytes)}
	subkey, err := vault.DeriveKey(key, []byte(j.Target.VaultID), vault.PurposeLocalSeal)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(subkey)
	for i := range c.Chunks {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		start := i * vault.MaxSecretBytes
		c.Chunks[i], err = vault.Seal(subkey, rootRotationChunkBinding(c, i), plain[start:min(start+vault.MaxSecretBytes, len(plain))])
		if err != nil {
			return nil, err
		}
	}
	raw, err := json.Marshal(c)
	if err != nil || len(raw) > maxRootRotationJournalBytes {
		return nil, vault.ErrFormat
	}
	return raw, nil
}

// Public bootstrap metadata is only a hint. Strict canonical decoding prevents
// duplicate/case-aliased fields and bounds work before any expensive KDF.
func decodeRootRotationCapsule(raw []byte) (rootRotationCapsule, error) {
	var c rootRotationCapsule
	if len(raw) == 0 || len(raw) > maxRootRotationJournalBytes || json.Unmarshal(raw, &c) != nil {
		return c, vault.ErrFormat
	}
	canonical, _ := json.Marshal(c)
	id, err := uuid.Parse(c.ID)
	if !bytes.Equal(raw, canonical) || (c.Version != 1 && c.Version != 2) || err != nil || id == uuid.Nil || id.String() != c.ID || c.Bytes < 1 || c.Bytes > maxRootRotationPlainBytes || len(c.Chunks) != (c.Bytes+vault.MaxSecretBytes-1)/vault.MaxSecretBytes {
		return rootRotationCapsule{}, vault.ErrFormat
	}
	doc, _ := json.Marshal(c.Document)
	if _, err := vault.DecodeSlotFile(doc); err != nil {
		return rootRotationCapsule{}, err
	}
	if c.Document.Rotation != nil || c.Document.Migration != nil || c.Document.Initializing {
		return rootRotationCapsule{}, vault.ErrFormat
	}
	return c, nil
}

func decodeRootRotationJournal(ctx context.Context, raw, key []byte) (rootRotationJournal, error) {
	var j rootRotationJournal
	if err := ctx.Err(); err != nil {
		return j, err
	}
	c, err := decodeRootRotationCapsule(raw)
	if err != nil {
		return j, err
	}
	if err := vault.VerifySlotFile(key, c.Document, c.Document.VaultID, c.Document.FileID, c.Document.Sequence); err != nil {
		return j, err
	}
	subkey, err := vault.DeriveKey(key, []byte(c.Document.VaultID), vault.PurposeLocalSeal)
	if err != nil {
		return j, err
	}
	defer vault.Wipe(subkey)
	plain := make([]byte, 0, c.Bytes)
	defer func() { vault.Wipe(plain) }()
	for i, chunk := range c.Chunks {
		if err := ctx.Err(); err != nil {
			return j, err
		}
		part, err := vault.Open(subkey, rootRotationChunkBinding(c, i), chunk)
		if err != nil {
			return j, err
		}
		if len(part) != min(vault.MaxSecretBytes, c.Bytes-i*vault.MaxSecretBytes) {
			vault.Wipe(part)
			return j, vault.ErrFormat
		}
		plain = append(plain, part...)
		vault.Wipe(part)
	}
	if json.Unmarshal(plain, &j) != nil {
		return rootRotationJournal{}, vault.ErrFormat
	}
	canonical, _ := json.Marshal(j)
	defer vault.Wipe(canonical)
	if !bytes.Equal(plain, canonical) || j.Version != c.Version || j.ID != c.ID || !sameRootRotationDocument(j.Target, c.Document) {
		return rootRotationJournal{}, vault.ErrAuthentication
	}
	old, err := authenticateRootRotationJournal(j, key)
	vault.Wipe(old)
	if err != nil {
		return rootRotationJournal{}, err
	}
	return j, nil
}

func rootRotationBarrier(j rootRotationJournal, phase vault.RootRotationPhase, oldKey []byte) (vault.SlotFile, error) {
	if phase.Step() == 0 && phase != vault.RotationStaging {
		return vault.SlotFile{}, vault.ErrFormat
	}
	doc := j.Source
	doc.FormatVersion = max(doc.FormatVersion, vault.SlotFileFormatVersion)
	doc.Sequence += phase.Step()
	doc.Rotation = &vault.LocalRootRotation{ID: j.ID, Phase: phase, TargetRootVersion: j.Target.RootKeyVersion, TargetSlotDigest: rootRotationSlotDigest(j.Target)}
	if phase == vault.RotationStaging {
		if !j.Target.Encrypted {
			return vault.SlotFile{}, vault.ErrPolicy
		}
		doc.Rotation.Pending = &vault.PendingRotationKey{Slots: j.Target.Slots, KeyCheck: j.Target.KeyCheck}
	}
	raw, err := vault.EncodeSlotFile(oldKey, doc)
	if err != nil {
		return vault.SlotFile{}, err
	}
	return vault.DecodeSlotFile(raw)
}
