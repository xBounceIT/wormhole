package localvault

import (
	"context"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// WebSessionArchiveOwner identifies an admitted workspace account on this
// device. Callers derive it from native admission and the authenticated file.
type WebSessionArchiveOwner struct {
	WorkspaceID, FileID, AccountID uuid.UUID
}

func (a WebSessionArchiveOwner) binding(node uuid.UUID) WebSessionBinding {
	return WebSessionBinding{
		WorkspaceID: a.WorkspaceID.String(), FileID: a.FileID.String(),
		AccountID: a.AccountID.String(), NodeID: node.String(),
	}
}

type webSessionHeader struct {
	size       int
	digest     []byte
	owner      WebSessionArchiveOwner
	node       uuid.UUID
	generation uuid.UUID
}

func parseWebSessionHeader(prefix []byte, state vaultstore.LocalState) (webSessionHeader, error) {
	if len(prefix) < webSessionHeaderBytes {
		return webSessionHeader{}, vault.ErrAuthentication
	}
	h := webSessionHeader{digest: prefix[len(webSessionArchiveMagic):webSessionHeaderBytes]}
	switch string(prefix[:len(webSessionArchiveMagic)]) {
	case webSessionArchiveMagic:
		h.size = webSessionHeaderBytes
	case indexedWebSessionMagic, sharedWebSessionMagic:
		h.size = indexedWebSessionHeaderBytes
		shared := string(prefix[:len(webSessionArchiveMagic)]) == sharedWebSessionMagic
		if shared {
			h.size = sharedWebSessionHeaderBytes
		}
		if len(prefix) < h.size {
			return webSessionHeader{}, vault.ErrAuthentication
		}
		offset := webSessionHeaderBytes
		for _, id := range []*uuid.UUID{&h.owner.WorkspaceID, &h.owner.FileID, &h.owner.AccountID, &h.node} {
			copy(id[:], prefix[offset:offset+len(id)])
			offset += len(id)
		}
		if shared {
			copy(h.generation[:], prefix[offset:h.size])
			if h.generation == uuid.Nil {
				return webSessionHeader{}, vault.ErrAuthentication
			}
		}
		scope, err := h.owner.binding(h.node).scope()
		if err != nil || scope != state.ScopeID {
			return webSessionHeader{}, vault.ErrAuthentication
		}
	default:
		return webSessionHeader{}, vault.ErrAuthentication
	}
	if state.Size <= h.size || state.Size > h.size+vault.MaxWebSessionArchiveBytes {
		return webSessionHeader{}, vault.ErrAuthentication
	}
	return h, nil
}

// WebSessionArchiveRecord contains only the authenticated node and revision
// needed for native permission reconciliation.
type WebSessionArchiveRecord struct {
	Node       uuid.UUID
	Revision   uint64
	Generation uuid.UUID
}

// ListWebSessionArchives scans a page of authenticated manifests and opens
// only the first chunk of each web archive. The cursor advances across other
// record kinds too. Legacy archives remain directly readable by scope.
func (o *Owner) ListWebSessionArchives(ctx context.Context, owner WebSessionArchiveOwner, after string, limit int) ([]WebSessionArchiveRecord, string, error) {
	if ctx == nil || owner.WorkspaceID == uuid.Nil || owner.FileID == uuid.Nil || owner.AccountID == uuid.Nil {
		return nil, "", vault.ErrFormat
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	states, err := o.listLocalStates(ctx, after, limit)
	if err != nil {
		return nil, "", err
	}
	var archives []WebSessionArchiveRecord
	for _, state := range states {
		if state.Kind != vaultstore.LocalStateWebSession {
			continue
		}
		field := state.Fields[0]
		ref := vaultstore.SecretRef{OwnerKind: "local-state", OwnerID: state.ID, Field: field.Field}
		err := o.withSecret(ctx, ref, field.Version, true, func(prefix []byte) error {
			if len(prefix) != min(state.Size, vault.MaxSecretBytes) {
				return vault.ErrAuthentication
			}
			header, err := parseWebSessionHeader(prefix, state)
			if err == nil && header.node != uuid.Nil && header.owner == owner {
				archives = append(archives, WebSessionArchiveRecord{
					Node: header.node, Revision: state.RowVersion, Generation: header.generation,
				})
			}
			return err
		})
		if err != nil {
			return nil, "", err
		}
	}
	next := ""
	if len(states) > 0 && len(states) == limit {
		next = states[len(states)-1].ID
	}
	return archives, next, nil
}

// RevokeWebSessionArchive erases the exact authenticated revision observed by
// the reconciliation pass. The tombstone invalidates earlier browser writers.
func (o *Owner) RevokeWebSessionArchive(ctx context.Context, owner WebSessionArchiveOwner, record WebSessionArchiveRecord) error {
	_, err := o.ForgetWebSessionState(ctx, owner.binding(record.Node), record.Revision)
	return err
}
