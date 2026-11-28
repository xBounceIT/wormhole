package vault

import "encoding/hex"

const (
	MigrationCopying       = "copying"
	MigrationDomainsCopied = "domains-copied"
	MigrationRetiring      = "retiring"
	MigrationPublishing    = "publishing"
)

// LocalMigration is authenticated by the slot-file MAC. Binding is a keyed
// commitment to the canonical source path and the complete resolver choices.
// No phase authorizes opening a workspace. Copy phases can be rebuilt; retirement
// must resume its encrypted journal because a source may already be gone.
type LocalMigration struct {
	Binding        string             `json:"binding"`
	Phase          string             `json:"phase"`
	Snapshot       *MigrationSnapshot `json:"snapshot,omitempty"`
	SourceSnapshot *MigrationSnapshot `json:"sourceSnapshot,omitempty"`
}

// MigrationSnapshot binds the closed, flushed SQLite file. ContentAuthentication
// freezes immutable records before retirement while its journal can advance.
// Older copy checkpoints still decode; publication requires the content proof.
type MigrationSnapshot struct {
	Bytes                 int64  `json:"bytes"`
	Authentication        []byte `json:"authentication"`
	ContentAuthentication []byte `json:"contentAuthentication,omitempty"`
}

func (m LocalMigration) valid() bool {
	b, err := hex.DecodeString(m.Binding)
	validSnapshot := func(s *MigrationSnapshot) bool {
		return s != nil && s.Bytes >= 512 && len(s.Authentication) == 32 && (len(s.ContentAuthentication) == 0 || len(s.ContentAuthentication) == 32)
	}
	if m.Phase == MigrationPublishing {
		return err == nil && len(b) == 32 && hex.EncodeToString(b) == m.Binding && validSnapshot(m.Snapshot) && len(m.Snapshot.ContentAuthentication) == 32 && validSnapshot(m.SourceSnapshot) && len(m.SourceSnapshot.ContentAuthentication) == 0
	}
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == m.Binding &&
		m.SourceSnapshot == nil &&
		(m.Phase == MigrationCopying || m.Phase == MigrationDomainsCopied || m.Phase == MigrationRetiring) &&
		(m.Phase != MigrationRetiring || m.Snapshot != nil) &&
		(m.Snapshot == nil || ((m.Phase == MigrationDomainsCopied || m.Phase == MigrationRetiring) && validSnapshot(m.Snapshot)))
}
