package main

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Stored display metadata only. Nullable fields retain their inheritance meaning;
// this response is not a resolution plan, authorization or connection capability.
type vaultCatalogNode struct {
	ID                string  `json:"id"`
	ParentID          *string `json:"parentId"`
	Name              string  `json:"name"`
	Kind              int     `json:"kind"`
	SortOrder         string  `json:"sortOrder"`
	Protocol          *int    `json:"protocol"`
	Host              *string `json:"host"`
	Port              *int    `json:"port"`
	Username          *string `json:"username"`
	RowVersion        string  `json:"rowVersion"`
	HasNotes          bool    `json:"hasNotes"`
	HasInlinePassword bool    `json:"hasInlinePassword"`
}

type vaultCatalogCredential struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	Kind       string `json:"kind"`
	Username   string `json:"username"`
	Domain     string `json:"domain"`
	Provider   string `json:"provider"`
	RowVersion string `json:"rowVersion"`
}

type vaultCatalogTunnel struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Kind       int    `json:"kind"`
	RowVersion string `json:"rowVersion"`
}

func (h *vaultFoundationHandler) catalog(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if h.owner == nil || len(payload) != 0 {
		return nil, vaultwire.ErrProtocol
	}
	catalog, err := h.owner.ReadCatalog(ctx, vaultwire.MaxFrameBytes-65536)
	if err != nil {
		return nil, err
	}
	result := struct {
		Nodes       []vaultCatalogNode       `json:"nodes"`
		Credentials []vaultCatalogCredential `json:"credentials"`
		Tunnels     []vaultCatalogTunnel     `json:"tunnels"`
	}{Nodes: []vaultCatalogNode{}, Credentials: []vaultCatalogCredential{}, Tunnels: []vaultCatalogTunnel{}}
	for _, n := range catalog.Nodes {
		view := nodeView(n)
		result.Nodes = append(result.Nodes, vaultCatalogNode{n.ID, n.ParentID, n.Name, n.Kind, strconv.FormatInt(n.SortOrder, 10), n.Protocol, n.Host, n.Port, n.Username, view.RowVersion, view.HasNotes, view.HasInlinePassword})
	}
	for _, c := range catalog.Credentials {
		result.Credentials = append(result.Credentials, vaultCatalogCredential{c.ID, c.Name, c.Protocol, c.Kind, c.Username, c.Domain, c.Provider, strconv.FormatUint(c.RowVersion, 10)})
	}
	for _, t := range catalog.Tunnels {
		result.Tunnels = append(result.Tunnels, vaultCatalogTunnel{t.ID, t.Name, t.Kind, strconv.FormatUint(t.RowVersion, 10)})
	}
	return json.Marshal(result)
}
