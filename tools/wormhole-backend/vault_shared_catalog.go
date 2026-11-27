package main

import (
	"context"
	"encoding/json"
	"math"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type vaultSharedCatalogCursor struct {
	After     string `json:"after"`
	Epoch     string `json:"epoch"`
	ChangeSeq string `json:"changeSeq"`
}
type vaultSharedCatalogNode struct {
	ID            string  `json:"id"`
	ParentID      *string `json:"parentId"`
	Name          string  `json:"name"`
	Kind          int     `json:"kind"`
	SortOrder     string  `json:"sortOrder"`
	Protocol      *int    `json:"protocol"`
	Host          *string `json:"host"`
	Port          *int    `json:"port"`
	Username      *string `json:"username"`
	CanUse        bool    `json:"canUse"`
	NotesRevision string  `json:"notesRevision,omitempty"`
	EditRevision  string  `json:"editRevision,omitempty"`
	GrantRevision string  `json:"grantRevision,omitempty"`
	GrantBoundary string  `json:"grantBoundary,omitempty"`
}
type vaultSharedCatalogPage struct {
	Epoch     string                    `json:"epoch"`
	ChangeSeq string                    `json:"changeSeq"`
	Nodes     []vaultSharedCatalogNode  `json:"nodes"`
	Next      *vaultSharedCatalogCursor `json:"next"`
}

func decodeSharedCatalogRequest(payload []byte) (sharedpg.TreeCursor, int, error) {
	var after, epoch, seq string
	var limit int
	bad := func() (sharedpg.TreeCursor, int, error) { return sharedpg.TreeCursor{}, 0, vaultwire.ErrProtocol }
	if len(payload) > 1024 || decodeVaultObject(payload, map[string]any{"after": &after, "epoch": &epoch, "changeSeq": &seq, "limit": &limit}, "after", "epoch", "changeSeq", "limit") != nil || limit < 1 || limit > sharedpg.MaxTreePage {
		return bad()
	}
	e, err := strconv.ParseUint(epoch, 10, 63)
	s, err2 := strconv.ParseUint(seq, 10, 63)
	if err != nil || err2 != nil || strconv.FormatUint(e, 10) != epoch || strconv.FormatUint(s, 10) != seq {
		return bad()
	}
	if after == "" {
		if e != 0 || s != 0 {
			return bad()
		}
		return sharedpg.TreeCursor{}, limit, nil
	}
	id, err := uuid.Parse(after)
	if err != nil || id == uuid.Nil || id.String() != after || e == 0 {
		return bad()
	}
	return sharedpg.TreeCursor{After: id, Epoch: e, ChangeSeq: s}, limit, nil
}

func (h *vaultFoundationHandler) sharedCatalog(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if ctx == nil || h.closed || h.owner != nil || h.shared == nil || h.shared.controller == nil || !h.shared.controller.Unlocked() {
		return nil, vaultwire.ErrProtocol
	}
	cursor, limit, err := decodeSharedCatalogRequest(payload)
	if err != nil {
		return nil, err
	}
	page, err := h.shared.controller.CatalogPage(ctx, cursor, limit)
	if err != nil {
		return nil, h.retire(err)
	}
	if page == nil || page.Epoch == 0 || page.Epoch > math.MaxInt64 || page.ChangeSeq > math.MaxInt64 || len(page.Nodes) > limit {
		return nil, h.retire(vaultwire.ErrProtocol)
	}
	result := vaultSharedCatalogPage{Epoch: strconv.FormatUint(page.Epoch, 10), ChangeSeq: strconv.FormatUint(page.ChangeSeq, 10), Nodes: make([]vaultSharedCatalogNode, 0, len(page.Nodes))}
	for _, node := range page.Nodes {
		public := vaultSharedCatalogNode{ID: node.ID, ParentID: node.ParentID, Name: node.Name, Kind: node.Kind,
			SortOrder: strconv.FormatInt(node.SortOrder, 10), Protocol: node.Protocol, Host: node.Host, Port: node.Port, Username: node.Username, CanUse: node.CanUse}
		if node.NotesRevision > 0 {
			public.NotesRevision = strconv.FormatUint(node.NotesRevision, 10)
		}
		if node.EditRevision > 0 {
			public.EditRevision = strconv.FormatUint(node.EditRevision, 10)
		}
		if node.GrantRevision > 0 {
			public.GrantRevision = strconv.FormatUint(node.GrantRevision, 10)
			if node.GrantBoundary != uuid.Nil {
				public.GrantBoundary = node.GrantBoundary.String()
			}
		}
		result.Nodes = append(result.Nodes, public)
	}
	if page.Next != nil {
		result.Next = &vaultSharedCatalogCursor{After: page.Next.After.String(), Epoch: strconv.FormatUint(page.Next.Epoch, 10), ChangeSeq: strconv.FormatUint(page.Next.ChangeSeq, 10)}
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > vaultwire.MaxFrameBytes-65536 {
		return nil, h.retire(vaultwire.ErrProtocol)
	}
	if err := ctx.Err(); err != nil {
		return nil, h.retire(err)
	}
	return raw, nil
}
