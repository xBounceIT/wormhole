package localvault

import (
	"context"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"strconv"
)

// Only the trusted main-process caller may supply this recipient. The native
// handler must enforce fresh authentication and select the policy TTL.
func (o *Owner) SealConnectionClipboard(ctx context.Context, id, request string, revision uint64, field string, seconds int, publicKey []byte) (NotesDisplay, error) {
	var result NotesDisplay
	err := o.withConnectionCredential(ctx, id, revision, field, func(workspace string, value []byte) error {
		bundle, err := vault.SealClipboardRelease(publicKey, workspace, id, request, revision, field, seconds, value)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		result = NotesDisplay{WorkspaceID: workspace, NodeID: id, RequestID: request, RowVersion: strconv.FormatUint(revision, 10), Bundle: bundle}
		return nil
	})
	if err != nil {
		return NotesDisplay{}, err
	}
	return result, nil
}
