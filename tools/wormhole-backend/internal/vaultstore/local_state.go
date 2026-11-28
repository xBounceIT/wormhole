package vaultstore

import (
	"context"
	"fmt"
	"math"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const LocalStateMigrationRetirement = "migration-retirement"
const LocalStateWebSession = "web-session"

const MaxLocalStateBytes = 64 * 1024 * 1024
const MaxLocalStateChunks = MaxLocalStateBytes / vault.MaxSecretBytes

// LocalState is device-local native state, never a shared credential or renderer
// DTO. A sealed manifest binds every chunk, including retired chunk versions.
// ScopeID is the workspace, tunnel or import ID selected by its native consumer.
type LocalState struct {
	ID         string        `json:"id"`
	Kind       string        `json:"kind"`
	ScopeID    string        `json:"scopeId"`
	Size       int           `json:"size"`
	RowVersion uint64        `json:"rowVersion"`
	Deleted    bool          `json:"deleted"`
	Fields     []SecretField `json:"fields"`
	Seal       []byte        `json:"seal"`
}

type LocalStateStore interface {
	Store
	ReadLocalState(context.Context, string, string) (LocalState, error)
	ListLocalStates(context.Context, string, int) ([]LocalState, error)
	WriteLocalState(context.Context, LocalState, []Secret, uint64) error
}

func LocalStateKind(kind string) bool {
	switch kind {
	case "bitwarden-cli", "mcp-token", "azure-refresh", "azure-legacy", "watchguard-cache", "watchguard-legacy", "stormshield-cache", "stormshield-legacy", "azure-import", "bitwarden-browser", "bitwarden-browser-backup", "bitwarden-installation", "bitwarden-install-intent", "vpn-sso":
		return true
	case "migration-source-inventory", LocalStateMigrationRetirement, LocalStateWebSession, "legacy-secret", "legacy-tunnel-row", "legacy-private-key", "legacy-tunnel-file", "legacy-browser-file":
		return true
	}
	return false
}

func LocalStateChunkField(index int) string { return fmt.Sprintf("chunk%02d", index) }

func (s LocalState) ActiveChunks() int {
	if s.Deleted {
		return 0
	}
	return max(1, (s.Size+vault.MaxSecretBytes-1)/vault.MaxSecretBytes)
}

func (s LocalState) Validate() error {
	if !validID(s.ID) || !validID(s.ScopeID) || !LocalStateKind(s.Kind) || s.Size < 0 || s.Size > MaxLocalStateBytes || s.RowVersion == 0 || s.RowVersion > math.MaxInt64 || len(s.Seal) != 32 || len(s.Fields) == 0 || len(s.Fields) > MaxLocalStateChunks || (s.Deleted && s.Size != 0) || len(s.Fields) < s.ActiveChunks() {
		return ErrFormat
	}
	for i, f := range s.Fields {
		if f.Field != LocalStateChunkField(i) || f.Version == 0 || f.Version > math.MaxInt64 || f.Present != (i < s.ActiveChunks()) {
			return ErrFormat
		}
	}
	return nil
}
