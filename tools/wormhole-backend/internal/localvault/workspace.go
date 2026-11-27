package localvault

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// WorkspaceView is native authenticated metadata, never a renderer DTO. Its
// resolutions include migration-pinned identities but no connection secrets.
type WorkspaceView struct {
	Catalog     Catalog
	Resolutions map[string]WorkspaceResolution
}

// Retain only display values, not each resolution's complete ancestor revisions,
// credential manifests or migration metadata. This is not a launch capability.
type WorkspaceResolution struct {
	Host                   string
	Port                   int
	Username               string
	Domain                 string
	GatewayCredentialID    string
	GatewaySameCredentials bool
	ExternalRDPClient      bool
}

func (o *Owner) ReadWorkspace(ctx context.Context, maximum int) (WorkspaceView, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	catalog, err := o.readCatalog(ctx, maximum)
	if err != nil {
		return WorkspaceView{}, err
	}
	result := WorkspaceView{Catalog: catalog, Resolutions: make(map[string]WorkspaceResolution)}
	remaining := maximum
	for _, node := range catalog.Nodes {
		if err := ctx.Err(); err != nil {
			return WorkspaceView{}, err
		}
		if node.Kind == 0 {
			continue
		}
		resolution, err := o.resolveConnection(ctx, node.ID, "")
		// Incomplete or incompatible connection settings remain visible/editable.
		// Authentication, storage, migration and cancellation failures do not.
		if errors.Is(err, resolver.ErrTarget) || errors.Is(err, resolver.ErrCredential) || errors.Is(err, resolver.ErrTunnel) {
			continue
		}
		if err != nil {
			return WorkspaceView{}, err
		}
		display := WorkspaceResolution{Host: resolution.Plan.Host, Port: resolution.Plan.Port,
			Username: resolution.Account.Username, Domain: resolution.Account.Domain,
			GatewayCredentialID: resolution.Plan.GatewayCredentialID, GatewaySameCredentials: resolution.Plan.GatewaySameCredentials,
			ExternalRDPClient: resolution.Plan.ExternalRDPClient}
		// Inheritance can expand a small catalog into a much larger display. Bound
		// the accumulated resolutions before building the final transport tree.
		raw, err := json.Marshal(display)
		if err != nil || len(raw)+len(node.ID)+8 > remaining {
			return WorkspaceView{}, vault.ErrFormat
		}
		remaining -= len(raw) + len(node.ID) + 8
		result.Resolutions[node.ID] = display
	}
	return result, nil
}
