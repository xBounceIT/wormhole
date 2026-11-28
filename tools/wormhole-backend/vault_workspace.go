package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func (h *vaultFoundationHandler) workspace(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if h.owner == nil || len(payload) != 0 {
		return nil, vaultwire.ErrProtocol
	}
	view, err := h.owner.ReadWorkspace(ctx, vaultwire.MaxFrameBytes/2)
	if err != nil {
		return nil, err
	}
	result, err := projectVaultWorkspace(ctx, view)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > vaultwire.MaxFrameBytes-65536 {
		return nil, vaultwire.ErrProtocol
	}
	return raw, nil
}

func vaultDisplayValue[T any](value *T) (result T) {
	if value != nil {
		return *value
	}
	return
}
func vaultDisplaySet[T any](target *T, value *T) {
	if value != nil {
		*target = *value
	}
}

func projectVaultWorkspace(ctx context.Context, view localvault.WorkspaceView) (workspaceSnapshot, error) {
	remaining := vaultwire.MaxFrameBytes - 65536
	charge := func(value any, copies int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, err := json.Marshal(value)
		if err != nil || (len(raw)+32)*copies > remaining {
			return vaultwire.ErrProtocol
		}
		remaining -= (len(raw) + 32) * copies
		return nil
	}
	result := workspaceSnapshot{Tree: []*treeNode{}, Credentials: []credentialRecord{}, CredentialOptions: map[string][]credentialRecord{"rdp": {}, "ssh": {}, "vnc": {}}, Tunnels: []tunnelRecord{}}
	for _, c := range view.Catalog.Credentials {
		// Certificate bytes, provider tokens and private-key contents are never read.
		record := credentialRecord{RowVersion: strconv.FormatUint(c.RowVersion, 10), ID: c.ID, Name: c.Name, Protocol: c.Protocol, Kind: c.Kind, Username: c.Username, Domain: c.Domain, Provider: "Local", CanEdit: true, CanDelete: true, BitwardenItemID: c.BitwardenItemID, BitwardenItemName: c.BitwardenItemName, PrivateKeyFileName: c.PrivateKeyName, CertificateFileName: c.CertificateName}
		if c.Provider == "bitwarden" {
			record.Provider = "Bitwarden"
		}
		for _, f := range c.Fields {
			if f.Field == "certificate" && f.Present {
				record.HasCertificate = true
			}
		}
		if err := charge(record, 2); err != nil {
			return workspaceSnapshot{}, err
		}
		result.Credentials = append(result.Credentials, record)
		result.CredentialOptions[c.Protocol] = append(result.CredentialOptions[c.Protocol], record)
	}
	sort.Slice(result.Credentials, func(i, j int) bool {
		a, b := result.Credentials[i], result.Credentials[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.ID < b.ID
	})
	for protocol := range result.CredentialOptions {
		values := result.CredentialOptions[protocol]
		sort.Slice(values, func(i, j int) bool {
			if values[i].Name != values[j].Name {
				return values[i].Name < values[j].Name
			}
			return values[i].ID < values[j].ID
		})
	}
	for _, t := range view.Catalog.Tunnels {
		record := tunnelRecord{ID: t.ID, Name: t.Name, Kind: tunnelName(int64(t.Kind)), RowVersion: strconv.FormatUint(t.RowVersion, 10)}
		if err := charge(record, 1); err != nil {
			return workspaceSnapshot{}, err
		}
		result.Tunnels = append(result.Tunnels, record)
	}
	sort.Slice(result.Tunnels, func(i, j int) bool {
		a, b := result.Tunnels[i], result.Tunnels[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.ID < b.ID
	})
	stored := make(map[string]vaultstore.NodeMetadata, len(view.Catalog.Nodes))
	for _, n := range view.Catalog.Nodes {
		stored[n.ID] = n.NodeMetadata
	}
	nodes := make(map[string]*treeNode, len(stored))
	ordered := append([]vaultstore.Node(nil), view.Catalog.Nodes...)
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if a.SortOrder != b.SortOrder {
			return a.SortOrder < b.SortOrder
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.ID < b.ID
	})
	for _, n := range ordered {
		if err := ctx.Err(); err != nil {
			return workspaceSnapshot{}, err
		}
		tree := &treeNode{ID: n.ID, RowVersion: strconv.FormatUint(n.RowVersion, 10), Name: n.Name, Kind: "folder", Persisted: true,
			Username: vaultDisplayValue(n.Username), SshAutoSudo: n.SshAutoSudo, HTTPIgnoreCertErrors: n.HTTPIgnoreCertErrors,
			HTTPPath: vaultDisplayValue(n.HTTPPath), TunnelEnabled: n.TunnelEnabled, TunnelConfigID: vaultDisplayValue(n.TunnelConfigID),
			CredentialMode: n.CredentialMode, CredentialID: vaultDisplayValue(n.CredentialID), HasInlineCredential: vaultDisplayValue(n.UseInlinePassword)}
		if n.Kind == 1 {
			tree.Kind = "connection"
			chain := []vaultstore.NodeMetadata{n.NodeMetadata}
			for current := n.NodeMetadata; current.ParentID != nil; {
				current = stored[*current.ParentID]
				chain = append(chain, current)
			}
			for _, ancestor := range chain {
				if ancestor.Protocol != nil {
					tree.Protocol = protocolName(sql.NullInt64{Int64: int64(*ancestor.Protocol), Valid: true})
					break
				}
			}
			tree.Host, tree.Port = vaultDisplayValue(n.Host), vaultDisplayValue(n.Port)
			if tree.Protocol == "rdp" {
				settings := vaultWorkspaceRDP(chain)
				tree.RDP = &settings
			}
			if tree.Protocol == "serial" {
				baud, data, stop, parity, flow := 9600, 8, 1, 0, 0
				for i := len(chain) - 1; i >= 0; i-- {
					ancestor := chain[i]
					vaultDisplaySet(&baud, ancestor.SerialBaudRate)
					vaultDisplaySet(&data, ancestor.SerialDataBits)
					vaultDisplaySet(&stop, ancestor.SerialStopBits)
					vaultDisplaySet(&parity, ancestor.SerialParity)
					vaultDisplaySet(&flow, ancestor.SerialFlowControl)
					vaultDisplaySet(&tree.Host, ancestor.Host)
				}
				tree.SerialBaudRate, tree.SerialDataBits, tree.SerialStopBits, tree.SerialParity, tree.SerialFlowControl = &baud, &data, &stop, &parity, &flow
			}
			if resolution, ok := view.Resolutions[n.ID]; ok {
				tree.Host, tree.Port = resolution.Host, resolution.Port
				if tree.Protocol == "rdp" {
					tree.Username = resolution.Username
					tree.RDP.Domain = resolution.Domain
					tree.RDP.GatewayCredentialID = resolution.GatewayCredentialID
					tree.RDP.GatewayUseSameCreds = resolution.GatewaySameCredentials
					tree.RDP.UseExternalClient = resolution.ExternalRDPClient
					*tree.RDP = normalizePersistedWorkspaceRdpSettings(*tree.RDP)
				}
			}
		}
		if err := charge(tree, 1); err != nil {
			return workspaceSnapshot{}, err
		}
		nodes[n.ID] = tree
	}
	for _, n := range ordered {
		if n.ParentID == nil {
			result.Tree = append(result.Tree, nodes[n.ID])
		} else {
			parent := nodes[*n.ParentID]
			parent.Children = append(parent.Children, nodes[n.ID])
		}
	}
	return result, nil
}

func vaultWorkspaceRDP(chain []vaultstore.NodeMetadata) workspaceRdpSettings {
	return normalizePersistedWorkspaceRdpSettings(resolver.ProjectRDPSettings(chain))
}
