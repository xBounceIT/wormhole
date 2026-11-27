package resolver

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"sort"
)

var (
	ErrMigration      = errors.New("resolver_migration_invalid_plan")
	ErrMigrationStale = errors.New("resolver_migration_stale")
)

// MigrationPlan is native identity metadata, not a renderer DTO or authorization.
// Its fingerprint binds all old/new identity results, including unchanged paths.
// It is a drift check, not a MAC, and does not bind routes, secrets or DB bytes.
// Persist only in an authenticated vault record; recheck against a fresh coherent
// source capture while holding the migration source state before applying pins.
type MigrationPlan struct {
	Version     int              `json:"version"`
	WorkspaceID string           `json:"workspaceId"`
	Fingerprint string           `json:"fingerprint"`
	Entries     []MigrationEntry `json:"entries"`
}

type MigrationEntry struct {
	Legacy    EffectiveCredentialSnapshot `json:"legacy"`
	Candidate EffectiveCredentialSnapshot `json:"candidate"`
	Choice    string                      `json:"choice"` // keep or new; keep is the migration default.
}

type MigrationDecision struct {
	NodeID       string
	ProtocolPath string
	Choice       string
}

// MigrationReport contains IDs and flags only; account identities remain native.
type MigrationReport struct {
	SnapshotDifference
	Choice string `json:"choice"`
}

func snapshotKey(s EffectiveCredentialSnapshot) string { return s.NodeID + ":" + s.ProtocolPath }

// BuildMigration checks supplied path-group shape. The caller must capture all
// current connections and applicable paths: a reveal-only group is valid for web
// nodes but cannot prove that SSH/RDP paths were not omitted. Recheck against the
// complete fresh native baseline detects any such omitted group before use.
func BuildMigration(workspaceID string, legacy, candidate []EffectiveCredentialSnapshot) (MigrationPlan, error) {
	if !canonicalID(workspaceID) || len(legacy) != len(candidate) {
		return MigrationPlan{}, ErrMigration
	}
	old := append([]EffectiveCredentialSnapshot{}, legacy...)
	next := append([]EffectiveCredentialSnapshot{}, candidate...)
	sort.Slice(old, func(i, j int) bool { return snapshotKey(old[i]) < snapshotKey(old[j]) })
	sort.Slice(next, func(i, j int) bool { return snapshotKey(next[i]) < snapshotKey(next[j]) })
	result := MigrationPlan{Version: 1, WorkspaceID: workspaceID, Entries: []MigrationEntry{}}
	digest := sha256.New()
	digest.Write([]byte("wormhole/v1/resolver-migration-identities\x00"))
	writeMigrationDigest(digest, []byte(workspaceID))
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(len(old)))
	digest.Write(count[:])
	for i, before := range old {
		after := next[i]
		if !before.ValidMigrationIdentity() || !after.ValidMigrationIdentity() {
			return MigrationPlan{}, ErrMigration
		}
		if (i > 0 && snapshotKey(before) == snapshotKey(old[i-1])) || snapshotKey(before) != snapshotKey(after) {
			return MigrationPlan{}, ErrMigration
		}
		difference, err := CompareSnapshots(before, after)
		if err != nil {
			return MigrationPlan{}, ErrMigration
		}
		for _, s := range []EffectiveCredentialSnapshot{before, after} {
			// Explicit length-prefixed UTF-8 fields keep the identity fingerprint
			// independent of JSON escaping and serializer implementation choices.
			for _, value := range []string{s.NodeID, s.ProtocolPath, s.CredentialID, s.Username, s.Domain, s.SourceKind} {
				writeMigrationDigest(digest, []byte(value))
			}
			digest.Write([]byte{byte(s.ResolverVersion)}) // Validated versions 0 and 1.
		}
		if difference != nil {
			result.Entries = append(result.Entries, MigrationEntry{Legacy: before, Candidate: after, Choice: "keep"})
		}
	}
	for start := 0; start < len(old); {
		end := start + 1
		for end < len(old) && old[end].NodeID == old[start].NodeID {
			end++
		}
		if !completeMigrationPaths(old[start:end]) {
			return MigrationPlan{}, ErrMigration
		}
		start = end
	}
	result.Fingerprint = hex.EncodeToString(digest.Sum(nil))
	return result, nil
}

func writeMigrationDigest(digest hash.Hash, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	digest.Write(size[:])
	digest.Write(value)
}

func completeMigrationPaths(values []EffectiveCredentialSnapshot) bool {
	paths := make(map[string]bool, len(values))
	for _, value := range values {
		paths[value.ProtocolPath] = true
	}
	if !paths["reveal"] {
		return false
	}
	switch len(paths) {
	case 1:
		return true
	case 2:
		return paths["vnc"]
	case 3:
		return (paths["ssh"] && paths["sftp"]) || (paths["rdp"] && paths["rdp-gateway"])
	}
	return false
}

func (p MigrationPlan) Validate() error {
	fingerprint, err := hex.DecodeString(p.Fingerprint)
	if p.Version != 1 || !canonicalID(p.WorkspaceID) || err != nil || len(fingerprint) != sha256.Size || hex.EncodeToString(fingerprint) != p.Fingerprint {
		return ErrMigration
	}
	previous := ""
	for _, entry := range p.Entries {
		if !entry.Legacy.ValidMigrationIdentity() || !entry.Candidate.ValidMigrationIdentity() {
			return ErrMigration
		}
		key := snapshotKey(entry.Legacy)
		if key <= previous || (entry.Choice != "keep" && entry.Choice != "new") {
			return ErrMigration
		}
		difference, err := CompareSnapshots(entry.Legacy, entry.Candidate)
		if err != nil || difference == nil {
			return ErrMigration
		}
		previous = key
	}
	return nil
}

// ValidMigrationIdentity validates account metadata captured for migration.
func (value EffectiveCredentialSnapshot) ValidMigrationIdentity() bool {
	if value.Validate() != nil {
		return false
	}
	if value.SourceKind == "system" && ((value.ProtocolPath != "rdp" && value.ProtocolPath != "rdp-gateway") || value.Username != "" || value.Domain != "") {
		return false
	}
	if value.ProtocolPath == "vnc" && (value.SourceKind == "inline" || value.Username != "" || value.Domain != "") {
		return false
	}
	return (value.ProtocolPath != "ssh" && value.ProtocolPath != "sftp") || value.Domain == ""
}

// Recheck detects changed identities, additions/removals and forged entry data.
// The source capture must remain stable until pins and imported nodes are stored.
func (p MigrationPlan) Recheck(workspaceID string, legacy, candidate []EffectiveCredentialSnapshot) error {
	if p.Validate() != nil || p.WorkspaceID != workspaceID {
		return ErrMigration
	}
	fresh, err := BuildMigration(workspaceID, legacy, candidate)
	if err != nil {
		return err
	}
	if fresh.Fingerprint != p.Fingerprint || len(fresh.Entries) != len(p.Entries) {
		return ErrMigrationStale
	}
	for i, entry := range p.Entries {
		if entry.Legacy != fresh.Entries[i].Legacy || entry.Candidate != fresh.Entries[i].Candidate {
			return ErrMigrationStale
		}
	}
	return nil
}

// Decide returns a copy. An invalid/duplicate decision rejects the whole batch;
// the supplied plan and its choices are never partially modified.
func (p MigrationPlan) Decide(expectedFingerprint string, decisions []MigrationDecision) (MigrationPlan, error) {
	if p.Validate() != nil || len(decisions) > len(p.Entries) {
		return MigrationPlan{}, ErrMigration
	}
	if p.Fingerprint != expectedFingerprint {
		return MigrationPlan{}, ErrMigrationStale
	}
	result := p
	result.Entries = append([]MigrationEntry{}, p.Entries...)
	indexes := make(map[string]int, len(p.Entries))
	for i, entry := range p.Entries {
		indexes[snapshotKey(entry.Legacy)] = i
	}
	seen := make(map[string]bool, len(decisions))
	for _, decision := range decisions {
		key := decision.NodeID + ":" + decision.ProtocolPath
		i, ok := indexes[key]
		if !ok || seen[key] || (decision.Choice != "keep" && decision.Choice != "new") {
			return MigrationPlan{}, ErrMigration
		}
		seen[key] = true
		result.Entries[i].Choice = decision.Choice
	}
	return result, nil
}

func (p MigrationPlan) Report() ([]MigrationReport, error) {
	if p.Validate() != nil {
		return nil, ErrMigration
	}
	result := make([]MigrationReport, 0, len(p.Entries))
	for _, entry := range p.Entries {
		difference, _ := CompareSnapshots(entry.Legacy, entry.Candidate)
		result = append(result, MigrationReport{SnapshotDifference: *difference, Choice: entry.Choice})
	}
	return result, nil
}
