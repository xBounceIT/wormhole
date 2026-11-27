package localvault

import (
	"context"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type NotesDisplay struct {
	WorkspaceID string             `json:"workspaceId"`
	NodeID      string             `json:"nodeId"`
	RequestID   string             `json:"requestId"`
	RowVersion  string             `json:"rowVersion"`
	Bundle      vault.SealedBundle `json:"bundle"`
}

// Authenticate the exact row and borrow its note under the same owner lock.
// Local View is granted by unlock; shared-mode grants require a separate API.
func (o *Owner) SealNodeNotes(ctx context.Context, id, request string, revision uint64, publicKey []byte) (NotesDisplay, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	s, err := o.nodeStore()
	if err != nil {
		return NotesDisplay{}, err
	}
	n, err := s.ReadNode(ctx, id)
	if err != nil {
		return NotesDisplay{}, err
	}
	if n.ID != id {
		return NotesDisplay{}, vault.ErrAuthentication
	}
	if err := o.verifyNode(n); err != nil {
		return NotesDisplay{}, err
	}
	if n.Deleted {
		return NotesDisplay{}, vaultstore.ErrMissing
	}
	if n.RowVersion != revision {
		return NotesDisplay{}, vaultstore.ErrConflict
	}
	result := NotesDisplay{WorkspaceID: s.Identity().WorkspaceID, NodeID: id, RequestID: request, RowVersion: strconv.FormatUint(revision, 10)}
	seal := func(value []byte) error {
		if !ValidNodeNotes(value) {
			return vault.ErrFormat
		}
		var err error
		result.Bundle, err = vault.SealNotesDisplay(publicKey, result.WorkspaceID, id, request, revision, value)
		return err
	}
	for _, f := range n.Fields {
		if f.Field == "notes" && f.Present {
			if err := o.withSecret(ctx, vaultstore.SecretRef{OwnerKind: "node", OwnerID: id, Field: "notes"}, f.Version, true, seal); err != nil {
				return NotesDisplay{}, err
			}
			return result, nil
		}
	}
	// A valid row without notes displays an authenticated empty value.
	if err := seal(nil); err != nil {
		return NotesDisplay{}, err
	}
	return result, nil
}
