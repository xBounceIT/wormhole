package main

import (
	"encoding/json"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
	"strconv"
)

// Decode native-only credential handoffs consistently. A result grants no
// authority: the typed owner still re-resolves, audits and seals the connection.
func decodeVaultProtocolBundleRequest(operation, protocol string, raw []byte) (localvault.TunnelBundleRequest, *vault.TunnelBundleBinding, string, error) {
	var q localvault.TunnelBundleRequest
	var epoch, endpoint string
	var route json.RawMessage
	if len(raw) > 4096 || (protocol != "rdp" && protocol != "vnc") {
		return q, nil, "", vaultwire.ErrProtocol
	}
	fields := map[string]any{"nodeId": &q.NodeID, "credentialOverride": &q.CredentialOverride, "sessionId": &q.SessionID, "requestId": &q.RequestID, "epoch": &epoch, "publicKey": &q.PublicKey}
	required := []string{"nodeId", "credentialOverride", "sessionId", "requestId", "epoch", "publicKey"}
	routed := operation == protocol+"-route-bundle"
	if routed {
		fields["route"] = &route
		fields["endpoint"] = &endpoint
		required = append(required, "route", "endpoint")
	} else if operation != protocol+"-bundle" {
		return q, nil, "", vaultwire.ErrProtocol
	}
	if decodeVaultObject(raw, fields, required...) != nil {
		return q, nil, "", vaultwire.ErrProtocol
	}
	var err error
	q.Epoch, err = strconv.ParseUint(epoch, 10, 64)
	if err != nil || strconv.FormatUint(q.Epoch, 10) != epoch {
		return q, nil, "", vaultwire.ErrProtocol
	}
	if routed {
		binding, err := decodeTunnelBundleBinding(route)
		if err != nil {
			return q, nil, "", err
		}
		return q, &binding, endpoint, nil
	}
	return q, nil, "", nil
}
