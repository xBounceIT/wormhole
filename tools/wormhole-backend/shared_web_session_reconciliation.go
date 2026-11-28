package main

import (
	"context"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type sharedWebViewSession interface {
	WebSessionViewsSupported(context.Context) (bool, error)
	OpenWebSessionView(context.Context, uuid.UUID) (uuid.UUID, error)
	CheckWebSessionViews(context.Context, []uuid.UUID) (map[uuid.UUID]uuid.UUID, error)
}

// Resolve device custody only under the shared admission gate.
func (c *sharedAdmissionController) webArchiveOwner() (*localvault.Owner, localvault.WebSessionArchiveOwner, error) {
	if c.vpnSSO == nil || c.vpnSSO.owner == nil {
		return nil, localvault.WebSessionArchiveOwner{}, nil
	}
	file, err := uuid.Parse(c.vpnSSO.fileID)
	if err != nil || file == uuid.Nil || file.String() != c.vpnSSO.fileID {
		return nil, localvault.WebSessionArchiveOwner{}, vault.ErrAuthentication
	}
	return c.vpnSSO.owner, localvault.WebSessionArchiveOwner{
		WorkspaceID: c.trustBinding.WorkspaceID, FileID: file, AccountID: c.trustBinding.UserID,
	}, nil
}

func (c *sharedAdmissionController) webViewSession(ctx context.Context) (sharedWebViewSession, error) {
	session, ok := c.session.(sharedWebViewSession)
	if !ok {
		return nil, nil
	}
	supported, err := session.WebSessionViewsSupported(ctx)
	if err != nil || !supported {
		return nil, err
	}
	return session, nil
}

func (c *sharedAdmissionController) reconcileWebViewGenerations(ctx context.Context) error {
	cache, owner, err := c.webArchiveOwner()
	if err != nil || cache == nil {
		return err
	}
	var session sharedWebViewSession
	for after := ""; ; {
		records, next, err := cache.ListWebSessionArchives(ctx, owner, after, sharedpg.MaxTreePage)
		if err != nil {
			return err
		}
		if len(records) != 0 {
			if session == nil {
				session, err = c.webViewSession(ctx)
				if err != nil || session == nil {
					return err
				}
			}
			nodes := make([]uuid.UUID, 0, len(records))
			for _, record := range records {
				nodes = append(nodes, record.Node)
			}
			current, err := session.CheckWebSessionViews(ctx, nodes)
			if err != nil {
				return err
			}
			for _, record := range records {
				if record.Generation == uuid.Nil || record.Generation != current[record.Node] {
					if err := cache.RevokeWebSessionArchive(ctx, owner, record); err != nil {
						return err
					}
				}
			}
		}
		if next == "" {
			return nil
		}
		after = next
	}
}

// The gate and committed catalog observation protect both the verified range
// and the per-device cache. A page makes no claim about IDs after its cursor
// when the server reports more results.
func (c *sharedAdmissionController) reconcileVisibleWebArchives(ctx context.Context, cursor sharedpg.TreeCursor, page *sharedCatalogPage) error {
	cache, owner, err := c.webArchiveOwner()
	if err != nil || cache == nil {
		return err
	}
	first := cursor.After.String()
	last := first
	visible := make(map[string]struct{}, len(page.Nodes))
	for _, node := range page.Nodes {
		if node.ID <= last {
			return sharedpg.ErrAdmissionResponse
		}
		visible[node.ID] = struct{}{}
		last = node.ID
	}
	if page.Epoch == 0 ||
		(cursor.After != uuid.Nil && (page.Epoch != cursor.Epoch || page.ChangeSeq != cursor.ChangeSeq)) ||
		(page.Next != nil && (last == first || page.Next.After.String() != last ||
			page.Next.Epoch != page.Epoch || page.Next.ChangeSeq != page.ChangeSeq)) {
		return sharedpg.ErrAdmissionResponse
	}
	for after := ""; ; {
		records, next, err := cache.ListWebSessionArchives(ctx, owner, after, sharedpg.MaxTreePage)
		if err != nil {
			return err
		}
		for _, record := range records {
			id := record.Node.String()
			if id <= first || (page.Next != nil && id > last) {
				continue
			}
			if _, ok := visible[id]; ok {
				continue
			}
			if err := cache.RevokeWebSessionArchive(ctx, owner, record); err != nil {
				return err
			}
		}
		if next == "" {
			return nil
		}
		after = next
	}
}
