package resolver

import (
	"strings"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func DefaultPath(protocol int) string {
	switch protocol {
	case 0:
		return "ssh"
	case 7:
		return "sftp"
	case 1:
		return "rdp"
	case 6:
		return "vnc"
	default:
		return "reveal"
	}
}

func PathAllowed(protocol int, path string) bool {
	switch path {
	case "ssh", "sftp":
		return protocol == 0 || protocol == 7
	case "rdp", "rdp-gateway":
		return protocol == 1
	case "vnc":
		return protocol == 6
	case "reveal":
		return protocol == 0 || protocol == 1 || protocol == 3 || protocol == 4 || protocol == 5 || protocol == 6 || protocol == 7
	}
	return false
}

func KnownAccountPath(path string) bool {
	switch path {
	case "ssh", "sftp", "vnc", "rdp", "rdp-gateway", "reveal":
		return true
	}
	return false
}

// RetainedAccount selects an explicitly kept identity for this path. Validate
// compatibility against the resolved protocol, including inherited protocols.
// An account override also applies to a gateway configured to reuse it.
func RetainedAccount(plan Plan, path string, pins []EffectiveCredentialSnapshot) (*EffectiveCredentialSnapshot, error) {
	if !PathAllowed(plan.Protocol, path) {
		return nil, ErrCredential
	}
	var selected *EffectiveCredentialSnapshot
	for _, pin := range pins {
		if !PathAllowed(plan.Protocol, pin.ProtocolPath) {
			return nil, ErrImportedPins
		}
		if pin.ProtocolPath == path {
			selected = &pin
		}
	}
	if plan.Credential.Kind == "override" && (path != "rdp-gateway" || plan.GatewaySameCredentials) {
		return nil, nil
	}
	return selected, nil
}

// ApplyRetainedAccount preserves the exact historical identity. Credential
// metadata authenticates the selected profile separately and must not fill
// any blank component of a retained identity.
func ApplyRetainedAccount(plan Plan, pin EffectiveCredentialSnapshot) Plan {
	plan.Username, plan.Domain = pin.Username, pin.Domain
	plan.Credential = Choice{Kind: pin.SourceKind, ID: pin.CredentialID, NodeID: pin.NodeID}
	if pin.SourceKind == "system" {
		plan.Credential = Choice{Kind: "none"}
		plan.ExternalRDPClient = true
	}
	return plan
}

// GatewayCandidate selects the gateway account as a primary account for a
// gateway-only request. An independent gateway never inherits the main login.
func GatewayCandidate(plan Plan) Plan {
	if plan.GatewayMethod != 0 && plan.GatewaySameCredentials {
		return plan
	}
	plan.Username, plan.Domain = "", ""
	plan.Credential = Choice{Kind: "none"}
	if plan.GatewayMethod != 0 && plan.GatewayCredentialID != "" {
		plan.Credential = Choice{Kind: "saved", ID: plan.GatewayCredentialID, NodeID: plan.NodeID}
	}
	return plan
}

// AccountPaths returns the stable inventory used for both source capture and
// destination shadow resolution. Every allowed path is included once.
func AccountPaths(protocol int) []string {
	paths := make([]string, 0, 3)
	for _, path := range [...]string{"rdp", "rdp-gateway", "reveal", "sftp", "ssh", "vnc"} {
		if PathAllowed(protocol, path) {
			paths = append(paths, path)
		}
	}
	return paths
}

func SplitRDPIdentity(username string) (string, string) {
	username = strings.TrimSpace(username)
	slash := strings.IndexByte(username, '\\')
	if slash <= 0 || slash == len(username)-1 {
		return username, ""
	}
	return username[slash+1:], username[:slash]
}

// AccountSnapshot formats the identity used by one native protocol path. The
// input plan already includes its selected credential's authenticated metadata.
// Both shadow comparison and active resolution use this projection.
func AccountSnapshot(p Plan, path, operatingSystem string, credential func(string) (vaultstore.CredentialMetadata, error)) (EffectiveCredentialSnapshot, error) {
	s := EffectiveCredentialSnapshot{NodeID: p.NodeID, ProtocolPath: path, ResolverVersion: Version, SourceKind: p.Credential.Kind, CredentialID: p.Credential.ID, Username: p.Username, Domain: p.Domain}
	if !PathAllowed(p.Protocol, path) {
		return EffectiveCredentialSnapshot{}, ErrCredential
	}
	if s.SourceKind == "override" {
		s.SourceKind = "saved"
	}
	switch path {
	case "ssh", "sftp":
		s.Domain = ""
	case "vnc":
		s.Username, s.Domain = "", ""
	case "rdp", "rdp-gateway":
		if RequiresExternalRDP(operatingSystem, p) {
			s.SourceKind, s.CredentialID, s.Username, s.Domain = "system", "", "", ""
		} else {
			if s.Domain == "" {
				s.Username, s.Domain = SplitRDPIdentity(s.Username)
			}
			if path == "rdp-gateway" {
				s.Domain = ""
				if p.GatewayMethod == 0 || (!p.GatewaySameCredentials && p.GatewayCredentialID == "") {
					s.SourceKind, s.CredentialID, s.Username = "none", "", ""
				} else if !p.GatewaySameCredentials {
					if credential == nil {
						return EffectiveCredentialSnapshot{}, ErrCredential
					}
					c, err := credential(p.GatewayCredentialID)
					if err != nil || c.ID != p.GatewayCredentialID || c.Protocol != "rdp" {
						return EffectiveCredentialSnapshot{}, ErrCredential
					}
					s.SourceKind, s.CredentialID, s.Username = "saved", c.ID, strings.TrimSpace(c.Username)
					if domain := strings.TrimSpace(c.Domain); domain != "" && !strings.Contains(s.Username, "\\") {
						s.Username = domain + "\\" + s.Username
					}
				}
			}
		}
	case "reveal":
		if CredentialProtocol(p.Protocol) == "" {
			s.SourceKind, s.CredentialID, s.Username, s.Domain = "none", "", "", ""
		}
	}
	if err := s.Validate(); err != nil {
		return EffectiveCredentialSnapshot{}, err
	}
	return s, nil
}
