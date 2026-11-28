package localvault

import (
	"context"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type TunnelEditorDisplay struct {
	WorkspaceID string             `json:"workspaceId"`
	TunnelID    string             `json:"tunnelId"`
	RequestID   string             `json:"requestId"`
	RowVersion  string             `json:"rowVersion"`
	Bundle      vault.SealedBundle `json:"bundle"`
}

// The native projector removes stored factors before encryption. Metadata,
// configuration authentication, projection and sealing share one owner lock;
// concurrent writes cannot produce a display bound to a different revision.
// Only local View is admitted here; shared-mode grants need a separate API.
func (o *Owner) SealTunnelEditor(ctx context.Context, id, request string, revision uint64, publicKey []byte, project func(vaultstore.Tunnel, []byte) ([]byte, error)) (TunnelEditorDisplay, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	s, err := o.tunnelStore()
	if err != nil {
		return TunnelEditorDisplay{}, err
	}
	if project == nil {
		return TunnelEditorDisplay{}, vault.ErrFormat
	}
	t, err := s.ReadTunnel(ctx, id)
	if err != nil {
		return TunnelEditorDisplay{}, err
	}
	if t.ID != id {
		return TunnelEditorDisplay{}, vault.ErrAuthentication
	}
	if err := o.verifyTunnel(t); err != nil {
		return TunnelEditorDisplay{}, err
	}
	if t.Deleted {
		return TunnelEditorDisplay{}, vaultstore.ErrMissing
	}
	if revision == 0 || t.RowVersion != revision {
		return TunnelEditorDisplay{}, vaultstore.ErrConflict
	}
	result := TunnelEditorDisplay{WorkspaceID: s.Identity().WorkspaceID, TunnelID: id, RequestID: request, RowVersion: strconv.FormatUint(revision, 10)}
	err = o.withSecret(ctx, vaultstore.SecretRef{OwnerKind: "tunnel", OwnerID: id, Field: "settings"}, t.ConfigurationVersion, true, func(configuration []byte) error {
		plaintext, e := project(t, configuration)
		defer vault.Wipe(plaintext)
		if e != nil {
			return e
		}
		result.Bundle, e = vault.SealTunnelEditorDisplay(publicKey, result.WorkspaceID, id, request, revision, plaintext)
		return e
	})
	if err != nil {
		return TunnelEditorDisplay{}, err
	}
	return result, nil
}
