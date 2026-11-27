package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

const maxSharedInvitationInput = 2 * sharedpg.MaxInvitationBytes

func parseInitialSharedInvitation(token string) (sharedpg.Invitation, error) {
	if len(token) > maxSharedInvitationInput {
		return sharedpg.Invitation{}, sharedpg.ErrInvitation
	}
	i, err := sharedpg.DecodeInvitation(token, time.Now())
	if err != nil {
		return sharedpg.Invitation{}, err
	}
	if _, err := i.EnrollmentRole(time.Now()); err != nil || strings.IndexFunc(i.LoginName, unicode.IsControl) >= 0 {
		return sharedpg.Invitation{}, sharedpg.ErrInvitation
	}
	return i, nil
}

// Public invitation metadata only; it authenticates neither the organisation nor
// a policy. Only initial protected input may request this operation. File paths
// are selected by main, never by the application renderer. No PostgreSQL/SQLite I/O.
func (h *vaultFoundationHandler) inspectSharedInvitation(ctx context.Context, file bool, payload []byte) (json.RawMessage, error) {
	if ctx == nil || h.closed || h.owner != nil || h.shared != nil || h.enrollment != nil || h.rotationMaterial != nil || h.releaseWorkspace != nil || h.migrationQuiesced || !filepath.IsAbs(h.databasePath) || filepath.Clean(h.databasePath) != h.databasePath || len(payload) > 8*maxSharedInvitationInput {
		return nil, vaultwire.ErrProtocol
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := requireNewVaultWorkspace(h.databasePath); err != nil {
		return nil, err
	}
	var token string
	if file {
		var path string
		if decodeVaultObject(payload, map[string]any{"path": &path}, "path") != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || !utf8.ValidString(path) || strings.ContainsRune(path, 0) {
			return nil, vaultwire.ErrProtocol
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return nil, sharedpg.ErrInvitation
		}
		raw, err := readBoundedRegularFile(path, maxSharedInvitationInput)
		defer vault.Wipe(raw)
		if err != nil {
			return nil, sharedpg.ErrInvitation
		}
		token = string(raw)
	} else if decodeVaultObject(payload, map[string]any{"invitation": &token}, "invitation") != nil {
		return nil, vaultwire.ErrProtocol
	}
	i, err := parseInitialSharedInvitation(token)
	if err != nil {
		return nil, err
	}
	canonical, err := sharedpg.EncodeInvitation(i, time.Now())
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Invitation  string           `json:"invitation"`
		WorkspaceID string           `json:"workspaceId"`
		LoginName   string           `json:"loginName"`
		TLS         sharedpg.TLSMode `json:"tls"`
	}{canonical, i.WorkspaceID.String(), i.LoginName, i.TLS})
}
