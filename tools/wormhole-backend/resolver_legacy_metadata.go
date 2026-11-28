package main

import (
	"errors"
	"strings"
)

// These are the existing legacy metadata walks, shared by the active connection
// paths and migration capture. They deliberately preserve legacy inheritance;
// the candidate resolver in internal/resolver has a separate versioned contract.
// Neither helper accesses storage, secret material, providers or network services.
func resolveLegacySSHMetadata(nodes map[string]*sshNode, nodeID string) (sshTarget, bool, error) {
	return resolveLegacyFileMetadata(nodes, nodeID, false)
}

func resolveLegacyFileMetadata(nodes map[string]*sshNode, nodeID string, smb bool) (sshTarget, bool, error) {
	root := nodes[normalizeID(nodeID)]
	if root == nil || root.kind == 0 {
		return sshTarget{}, false, errors.New("SSH connection was not found")
	}
	endpoint, err := resolveFileNodeEndpoint(nodes, root.id, smb)
	if err != nil {
		return sshTarget{}, false, err
	}

	username := ""
	usernameSet := false
	credentialID := ""
	credentialResolved := root.useInlinePassword
	identityBoundary := false
	credentialContextPending := false
	var credentialContextProtocol *int64
	knownFingerprint := ""
	autoSudo := false
	autoSudoSet := false
	tunnelEnabled := false
	tunnelSet := false
	tunnelConfigID := ""
	current := root
	seen := make(map[string]struct{})
	trustContext := make(map[string]sshNode)
	for current != nil {
		if _, duplicate := seen[current.id]; duplicate {
			return sshTarget{}, false, errors.New("SSH connection tree contains a cycle")
		}
		seen[current.id] = struct{}{}
		trustContext[current.id] = *current
		if !identityBoundary && !usernameSet && (current.usernameSet || strings.TrimSpace(current.username) != "") {
			username = strings.TrimSpace(current.username)
			usernameSet = true
		}
		if knownFingerprint == "" && strings.TrimSpace(current.knownHostFingerprint) != "" {
			knownFingerprint = strings.TrimSpace(current.knownHostFingerprint)
		}
		if !autoSudoSet && current.autoSudo != nil {
			autoSudo = *current.autoSudo
			autoSudoSet = true
		}
		if !tunnelSet && current.tunnelEnabled != nil {
			tunnelEnabled = *current.tunnelEnabled
			tunnelSet = true
		}
		if tunnelConfigID == "" && current.tunnelConfigID != "" {
			tunnelConfigID = current.tunnelConfigID
		}
		if !credentialResolved {
			if current.credentialMode != nil {
				if *current.credentialMode != 0 {
					credentialResolved = true
					if *current.credentialMode == 2 { // saved
						credentialID = current.credentialID
						if credentialID != "" {
							identityBoundary = true
							credentialContextPending = true
						}
					}
				}
			} else if current.credentialID != "" {
				credentialResolved = true
				credentialID = current.credentialID
				identityBoundary = true
				credentialContextPending = true
			}
		}
		if credentialContextPending && credentialContextProtocol == nil && current.protocol != nil {
			value := *current.protocol
			credentialContextProtocol = &value
		}
		if current.parentID == "" {
			break
		}
		current = nodes[current.parentID]
	}

	if tunnelSet && tunnelEnabled && tunnelConfigID == "" {
		return sshTarget{}, false, errors.New("SSH connection enables a VPN tunnel but no tunnel is configured")
	}
	if credentialContextProtocol != nil && sshCredentialProtocol(*credentialContextProtocol) != sshCredentialProtocol(endpoint.protocol) {
		credentialID = ""
	}

	target := sshTarget{
		credentialProtocol:   sshCredentialProtocol(endpoint.protocol),
		nodeTrustContext:     trustContext,
		credentialID:         credentialID,
		nodeID:               root.id,
		title:                root.name,
		host:                 endpoint.host,
		port:                 endpoint.port,
		username:             username,
		knownHostFingerprint: knownFingerprint,
		autoSudo:             autoSudo,
	}
	if tunnelSet && tunnelEnabled {
		target.tunnelConfigID = tunnelConfigID
	}
	return target, root.useInlinePassword, nil
}

type legacyRevealChoice struct {
	nodeID       string
	name         string
	protocol     int64
	username     string
	credentialID string
	inline       bool
}

func resolveLegacyRevealChoice(nodes map[string]*workspaceCredentialNode, nodeID string) (legacyRevealChoice, error) {
	root := nodes[nodeID]
	if root == nil || !root.kind.Valid || root.kind.Int64 != 1 {
		return legacyRevealChoice{}, errors.New("workspace connection was not found")
	}

	protocol := int64(0)
	protocolSet := false
	username := ""
	credentialID := ""
	credentialResolved := root.useInlinePassword.Valid && root.useInlinePassword.Int64 != 0
	identityBoundary := false
	seen := make(map[string]struct{})
	current := root
	for current != nil {
		if _, duplicate := seen[current.id]; duplicate {
			return legacyRevealChoice{}, errors.New("workspace connection tree contains a cycle")
		}
		seen[current.id] = struct{}{}
		if !protocolSet && current.protocol.Valid {
			protocol = current.protocol.Int64
			protocolSet = true
		}
		if !identityBoundary && username == "" && strings.TrimSpace(nullableString(current.username)) != "" {
			username = strings.TrimSpace(nullableString(current.username))
		}
		if !credentialResolved {
			if current.credentialMode.Valid {
				switch current.credentialMode.Int64 {
				case 1:
					credentialResolved = true
				case 2:
					credentialResolved = true
					credentialID = normalizeID(nullableString(current.credentialID))
					if credentialID != "" {
						identityBoundary = true
					}
				}
			} else if strings.TrimSpace(nullableString(current.credentialID)) != "" {
				credentialResolved = true
				credentialID = normalizeID(nullableString(current.credentialID))
				identityBoundary = true
			}
		}
		if current.parentID == "" {
			break
		}
		current = nodes[current.parentID]
	}

	return legacyRevealChoice{nodeID: root.id, name: root.name, protocol: protocol, username: username, credentialID: credentialID, inline: root.useInlinePassword.Valid && root.useInlinePassword.Int64 != 0}, nil
}

type legacyRevealMetadata struct {
	response workspaceCredentialRevealResponse
	ownerID  string
	source   string
	label    string
}

// The active Reveal path and migration capture share selection and identity
// composition. The caller supplies metadata only; this result has no secret.
func resolveLegacyRevealMetadata(nodes map[string]*workspaceCredentialNode, nodeID string, profile func(string) (workspaceCredentialProfile, bool, error)) (legacyRevealMetadata, error) {
	choice, err := resolveLegacyRevealChoice(nodes, nodeID)
	if err != nil {
		return legacyRevealMetadata{}, err
	}
	r := legacyRevealMetadata{response: workspaceCredentialRevealResponse{ConnectionName: choice.name}, source: "none"}
	if !workspaceProtocolCredentialValue(choice.protocol) {
		return r, nil
	}
	r.response.Username = choice.username
	if choice.inline {
		if choice.protocol == 0 || choice.protocol == 7 || choice.protocol == 1 || choice.protocol == smbProtocolValue {
			r.ownerID, r.source, r.label = choice.nodeID, "inline", "Password"
		}
		return r, nil
	}
	if choice.credentialID == "" {
		return r, nil
	}
	c, found, err := profile(choice.credentialID)
	if err != nil {
		return legacyRevealMetadata{}, err
	}
	if !found || !c.protocol.Valid || !workspaceCredentialProtocolMatches(choice.protocol, c.protocol.Int64) || (c.secretProvider.Valid && c.secretProvider.Int64 != 0) {
		return r, nil
	}
	if r.response.Username == "" {
		r.response.Username = strings.TrimSpace(nullableString(c.username))
	}
	r.response.Domain = strings.TrimSpace(nullableString(c.domain))
	r.response.CredentialName = strings.TrimSpace(nullableString(c.name))
	r.label = "Password"
	if (choice.protocol == 0 || choice.protocol == 7) && c.kind.Valid && c.kind.Int64 == 1 {
		r.label = "Key passphrase"
	} else if c.kind.Valid && c.kind.Int64 != 0 {
		return r, nil
	}
	r.ownerID, r.source = choice.credentialID, "saved"
	return r, nil
}
