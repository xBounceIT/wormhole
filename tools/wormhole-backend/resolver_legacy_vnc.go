package main

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
)

// The active VNC walk is shared with capture. Only the caller-provided reader
// can obtain a password; migration supplies a metadata/presence reader instead.
func resolveLegacyVNCTarget(database sqlMetadataReader, nodeID, credentialID string, resolvePassword bool, readCredential func(string) (string, bool, error), observe func(resolver.EffectiveCredentialSnapshot)) (vncTarget, error) {
	target := vncTarget{}
	selectedCredentialID := ""
	nodeFound := false
	target.nodeID = normalizeID(nodeID)
	if resolvePassword && credentialID != "" {
		password, _, err := readCredential(credentialID)
		if err != nil {
			return vncTarget{}, err
		}
		target.password = password
	}
	if nodeID == "" {
		return target, nil
	}

	columns, err := tableColumns(database, "Nodes")
	if err != nil {
		return vncTarget{}, err
	}
	if len(columns) == 0 {
		return target, nil
	}
	visited := make(map[string]struct{})
	currentID := normalizeID(nodeID)
	inheritCredential := true
	var resolvedProtocol int64
	var portContextProtocol int64
	protocolResolved := false
	portContextResolved := false
	tunnelResolved := false
	tunnelEnabled := false
	tunnelConfigID := ""
	displayName := ""
	for currentID != "" {
		if _, seen := visited[currentID]; seen {
			return vncTarget{}, errors.New("VNC connection tree contains a cycle")
		}
		visited[currentID] = struct{}{}
		row, err := readVncNode(database, columns, currentID)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return vncTarget{}, err
		}
		nodeFound = true
		if displayName == "" && row.name.Valid && strings.TrimSpace(row.name.String) != "" {
			displayName = strings.TrimSpace(row.name.String)
		}
		if !protocolResolved && row.protocol.Valid {
			resolvedProtocol = row.protocol.Int64
			protocolResolved = true
		}
		if !target.hostSet() && row.host.Valid && strings.TrimSpace(row.host.String) != "" {
			target.host = strings.TrimSpace(row.host.String)
		}
		if target.port == 0 && row.port.Valid && row.port.Int64 > 0 && row.port.Int64 <= 65535 {
			target.port = int(row.port.Int64)
		}
		if target.port != 0 && !portContextResolved && row.protocol.Valid {
			portContextProtocol = row.protocol.Int64
			portContextResolved = true
		}
		if !tunnelResolved && row.tunnelEnabled.Valid {
			tunnelResolved = true
			tunnelEnabled = row.tunnelEnabled.Int64 != 0
		}
		if tunnelConfigID == "" && row.tunnelConfigID.Valid {
			tunnelConfigID = normalizeTunnelID(row.tunnelConfigID.String)
		}

		if inheritCredential {
			if row.credentialMode.Valid {
				if row.credentialMode.Int64 != 0 {
					inheritCredential = false
					if row.credentialMode.Int64 == 2 && resolvePassword && row.credentialID.Valid && strings.TrimSpace(row.credentialID.String) != "" {
						password, found, err := readCredential(row.credentialID.String)
						if err != nil {
							return vncTarget{}, err
						}
						if found {
							target.password = password
							selectedCredentialID = normalizeID(row.credentialID.String)
						}
					}
				}
			} else if row.credentialID.Valid && strings.TrimSpace(row.credentialID.String) != "" {
				if resolvePassword {
					password, found, err := readCredential(row.credentialID.String)
					if err != nil {
						return vncTarget{}, err
					}
					if found {
						target.password = password
						selectedCredentialID = normalizeID(row.credentialID.String)
					}
				}
				inheritCredential = false
			}
		}
		if !row.parentID.Valid {
			break
		}
		currentID = normalizeID(row.parentID.String)
	}
	if protocolResolved && portContextResolved && resolvedProtocol != portContextProtocol {
		target.port = 0
	}
	if protocolResolved && resolvedProtocol != vncProtocolValue {
		return vncTarget{}, errors.New("VNC node does not resolve to the VNC protocol")
	}
	if tunnelEnabled && tunnelConfigID == "" {
		return vncTarget{}, errors.New("VNC connection enables a VPN tunnel but no tunnel is configured")
	}
	if tunnelEnabled {
		target.tunnelConfigID = tunnelConfigID
	}
	target.displayName = displayName
	if nodeFound && resolvePassword && credentialID == "" {
		source := "none"
		if selectedCredentialID != "" {
			source = "saved"
		}
		observe(legacyResolutionSnapshot(target.nodeID, "vnc", selectedCredentialID, "", "", source))
	}
	return target, nil
}

func legacyVNCCredentialEligible(database sqlMetadataReader, credentialID string) (bool, error) {
	columns, err := tableColumns(database, "CredentialProfiles")
	if err != nil {
		return false, err
	}
	if len(columns) == 0 {
		return false, nil
	}
	providerExpression := "0"
	if _, ok := columns["SecretProvider"]; ok {
		providerExpression = "COALESCE(SecretProvider, 0)"
	}
	protocolExpression := "NULL"
	if _, ok := columns["Protocol"]; ok {
		protocolExpression = "Protocol"
	}
	kindExpression := "NULL"
	if _, ok := columns["Kind"]; ok {
		kindExpression = "Kind"
	}
	var provider, protocol, kind sql.NullInt64
	if err := database.QueryRow(
		"SELECT "+providerExpression+", "+protocolExpression+", "+kindExpression+" FROM CredentialProfiles WHERE lower(Id) = ?;",
		normalizeID(credentialID),
	).Scan(&provider, &protocol, &kind); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	if provider.Valid && provider.Int64 != 0 {
		// Bitwarden values are intentionally not exposed to the renderer or copied into the
		// database. The UI can provide a connect-time password when the native cache has none.
		return false, nil
	}
	if protocol.Valid && protocol.Int64 != vncProtocolValue {
		return false, nil
	}
	if kind.Valid && kind.Int64 != 0 {
		return false, nil
	}
	return true, nil
}
