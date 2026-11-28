// Package resolver specifies metadata-only connection resolution. Callers must
// authenticate the complete input chain and authorize the resulting choices
// before releasing a secret. Resolve never reads storage or decrypts a value.
package resolver

import (
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const Version = 1

var (
	ErrChain        = errors.New("vault_resolver_invalid_chain")
	ErrTarget       = errors.New("vault_resolver_invalid_target")
	ErrCredential   = errors.New("vault_resolver_invalid_credential")
	ErrTunnel       = errors.New("vault_resolver_invalid_tunnel")
	ErrImportedPins = errors.New("vault_resolver_imported_pins_required")
)

type Choice struct {
	Kind   string `json:"kind"` // none, inline, saved, slot, override
	ID     string `json:"id"`
	NodeID string `json:"nodeId"`
}

// Plan describes a choice, not a secret-release capability. Slot selection and
// user overrides still require their authenticated catalogs and Use permissions.
// The protocol adapter must validate/normalize the endpoint before launch.
type Plan struct {
	Version                 int    `json:"resolverVersion"`
	NodeID                  string `json:"nodeId"`
	Protocol                int    `json:"protocol"`
	Host                    string `json:"host"`
	Port                    int    `json:"port"`
	Username                string `json:"username"`
	Domain                  string `json:"domain"`
	Credential              Choice `json:"credential"`
	TunnelID                string `json:"tunnelId"`
	HostKeyFingerprint      string `json:"hostKeyFingerprint"`
	HTTPPath                string `json:"httpPath"`
	IgnoreCertificateErrors bool   `json:"ignoreCertificateErrors"`
	SSHAutoSudo             bool   `json:"sshAutoSudo"`
	GatewayMethod           int    `json:"gatewayMethod"`
	GatewayHost             string `json:"gatewayHost"`
	GatewaySameCredentials  bool   `json:"gatewaySameCredentials"`
	GatewayCredentialID     string `json:"gatewayCredentialId"`
	ExternalRDPClient       bool   `json:"externalRdpClient"`
}

func canonicalID(id string) bool {
	v, err := uuid.Parse(id)
	return err == nil && v != uuid.Nil && v.String() == id
}

func family(protocol int) int {
	if protocol == 7 {
		return 0
	}
	return protocol
}

func CredentialProtocol(protocol int) string {
	switch protocol {
	case 0, 7:
		return "ssh"
	case 1:
		return "rdp"
	case 6:
		return "vnc"
	}
	return ""
}

// Resolve consumes a complete leaf-to-root chain, including the terminal root.
// Empty strings are explicit values. Only nil inherits. Mode 0 ignores a legacy
// CredentialID; nil mode plus an ID selects saved. Mode 1 stops credential
// inheritance; modes 2/3 select saved/slot and stop identity inheritance above
// that row. Inline is leaf-only and also stops identity inheritance at the leaf.
func Resolve(chain []vaultstore.NodeMetadata, overrideCredentialID string) (Plan, error) {
	return resolve(chain, overrideCredentialID, false)
}

// ResolveImportedCandidate computes the current inherited settings. The caller
// must verify the attached import data against the signed leaf and apply its
// retained account for the requested path before using the candidate.
func ResolveImportedCandidate(chain []vaultstore.NodeMetadata, overrideCredentialID string) (Plan, error) {
	return resolve(chain, overrideCredentialID, true)
}

func resolve(chain []vaultstore.NodeMetadata, overrideCredentialID string, importedCandidate bool) (Plan, error) {
	if len(chain) == 0 || len(chain) > vaultstore.MaxNodeDepth || (overrideCredentialID != "" && !canonicalID(overrideCredentialID)) {
		return Plan{}, ErrChain
	}
	seen := make(map[string]bool, len(chain))
	for i, n := range chain {
		if n.Validate() != nil || seen[n.ID] || (i == 0 && n.Kind != 1) || (i > 0 && n.Kind != 0) {
			return Plan{}, ErrChain
		}
		seen[n.ID] = true
		if i+1 < len(chain) {
			if n.ParentID == nil || *n.ParentID != chain[i+1].ID {
				return Plan{}, ErrChain
			}
		} else if n.ParentID != nil {
			return Plan{}, ErrChain
		}
	}
	if imported := chain[0].Imported; imported != nil && imported.RetainedPins && !importedCandidate {
		return Plan{}, ErrImportedPins
	}
	protocolAt := make([]*int, len(chain))
	var inherited *int
	for i := len(chain) - 1; i >= 0; i-- {
		if chain[i].Protocol != nil {
			inherited = chain[i].Protocol
		}
		protocolAt[i] = inherited
	}
	if protocolAt[0] == nil {
		return Plan{}, ErrTarget
	}
	p := Plan{Version: Version, NodeID: chain[0].ID, Protocol: *protocolAt[0], Credential: Choice{Kind: "none"}}
	var host, username, domain, fingerprint, path, tunnelID, gatewayHost, gatewayID *string
	var port, gatewayMethod *int
	var tunnel, autoSudo, gatewaySame, external *bool
	portOwner := -1
	choiceOwner := -1
	identityBoundary := false
	choiceResolved := false
	inline := chain[0].UseInlinePassword != nil && *chain[0].UseInlinePassword
	if inline && p.Protocol != 0 && p.Protocol != 1 && p.Protocol != 7 {
		return Plan{}, ErrCredential
	}
	for i, n := range chain {
		first(&host, n.Host)
		first(&fingerprint, n.SshKnownHostFingerprint)
		first(&path, n.HTTPPath)
		first(&tunnel, n.TunnelEnabled)
		first(&tunnelID, n.TunnelConfigID)
		first(&autoSudo, n.SshAutoSudo)
		first(&gatewayMethod, n.RDPGatewayUsageMethod)
		first(&gatewayHost, n.RDPGatewayHostname)
		first(&gatewayID, n.RDPGatewayCredentialID)
		first(&gatewaySame, n.RDPGatewayUseSameCreds)
		first(&external, n.RDPUseExternalClient)
		if port == nil && n.Port != nil {
			port = n.Port
			portOwner = i
		}
		if !identityBoundary {
			first(&username, n.Username)
			first(&domain, n.RDPDomain)
		}
		if choiceResolved {
			continue
		}
		if i == 0 && inline {
			p.Credential = Choice{Kind: "inline", ID: n.ID, NodeID: n.ID}
			choiceResolved = true
			identityBoundary = true
			continue
		}
		mode := 0
		if n.CredentialMode != nil {
			mode = *n.CredentialMode
		} else if n.CredentialID != nil {
			mode = 2
		}
		switch mode {
		case 0:
		case 1:
			choiceResolved = true
		case 2, 3:
			kind, id := "saved", n.CredentialID
			if mode == 3 {
				kind, id = "slot", n.CredentialSlotID
			}
			if id == nil {
				return Plan{}, ErrCredential
			}
			p.Credential = Choice{Kind: kind, ID: *id, NodeID: n.ID}
			choiceOwner = i
			choiceResolved = true
			identityBoundary = true
		default:
			return Plan{}, ErrCredential
		}
	}
	p.Host = text(host)
	p.Username = text(username)
	p.Domain = text(domain)
	if p.Host == "" {
		return Plan{}, ErrTarget
	}
	if port != nil && (protocolAt[portOwner] == nil || family(*protocolAt[portOwner]) == family(p.Protocol)) {
		p.Port = *port
	}
	if p.Port == 0 {
		switch p.Protocol {
		case 0, 7:
			p.Port = 22
		case 1:
			p.Port = 3389
		case 3:
			p.Port = 80
		case 4:
			p.Port = 443
		case 6:
			p.Port = 5900
		}
	}
	if choiceOwner >= 0 && protocolAt[choiceOwner] != nil && family(*protocolAt[choiceOwner]) != family(p.Protocol) {
		p.Credential = Choice{Kind: "none"}
	}
	if overrideCredentialID != "" {
		if CredentialProtocol(p.Protocol) == "" {
			return Plan{}, ErrCredential
		}
		p.Credential = Choice{Kind: "override", ID: overrideCredentialID, NodeID: p.NodeID}
		p.Username = ""
		p.Domain = ""
	}
	if CredentialProtocol(p.Protocol) == "" {
		p.Credential = Choice{Kind: "none"}
		p.Username = ""
		p.Domain = ""
	}
	if boolean(tunnel) {
		p.TunnelID = text(tunnelID)
		if p.Protocol == 5 || p.TunnelID == "" {
			return Plan{}, ErrTunnel
		}
	}
	if p.Protocol == 5 {
		p.Port = 0
	}
	if p.Protocol == 0 || p.Protocol == 7 {
		p.HostKeyFingerprint = text(fingerprint)
		p.SSHAutoSudo = boolean(autoSudo)
	}
	if p.Protocol == 3 || p.Protocol == 4 {
		p.HTTPPath = text(path)
	}
	p.IgnoreCertificateErrors = p.Protocol == 4 && boolean(chain[0].HTTPIgnoreCertErrors)
	if p.Protocol == 1 {
		if gatewayMethod != nil {
			p.GatewayMethod = *gatewayMethod
		}
		p.ExternalRDPClient = boolean(external)
		if p.GatewayMethod != 0 {
			p.GatewayHost = text(gatewayHost)
			p.GatewaySameCredentials = boolean(gatewaySame)
			if p.GatewayMethod == 1 && p.GatewayHost == "" {
				return Plan{}, ErrTarget
			}
			if !p.GatewaySameCredentials {
				p.GatewayCredentialID = text(gatewayID)
			}
		}
	}
	return p, nil
}

func first[T any](target **T, value *T) {
	if *target == nil && value != nil {
		*target = value
	}
}
func text(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}
func boolean(value *bool) bool { return value != nil && *value }

// ApplyCredential checks protocol and supplies missing identity components.
// An explicit override owns both components, preventing a username from one
// account being paired with another account's secret. Provider metadata remains
// native; Bitwarden resolution can supply its dynamic identity in a later stage.
func ApplyCredential(plan Plan, credential vaultstore.CredentialMetadata) (Plan, error) {
	if plan.Credential.Kind != "saved" && plan.Credential.Kind != "override" {
		return Plan{}, ErrCredential
	}
	if plan.Credential.ID != credential.ID || credential.Protocol != CredentialProtocol(plan.Protocol) {
		return Plan{}, ErrCredential
	}
	if plan.Username == "" || plan.Credential.Kind == "override" {
		plan.Username = strings.TrimSpace(credential.Username)
	}
	if plan.Domain == "" || plan.Credential.Kind == "override" {
		plan.Domain = strings.TrimSpace(credential.Domain)
	}
	return plan, nil
}

// RDP's external-client setting means mstsc, not the native FreeRDP adapter on
// other platforms. AzureAD identities also require the Windows system client.
func RequiresExternalRDP(operatingSystem string, plan Plan) bool {
	return operatingSystem == "windows" && plan.Protocol == 1 && (plan.ExternalRDPClient ||
		strings.EqualFold(strings.TrimSpace(plan.Domain), "AzureAD") ||
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(plan.Username)), "azuread\\"))
}
