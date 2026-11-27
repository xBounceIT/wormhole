package resolver

import (
	"testing"

	"github.com/google/uuid"
)

func TestRetainedAccountDoesNotChangeAnotherPathOrAnExplicitOverride(t *testing.T) {
	id, cred := uuid.NewString(), uuid.NewString()
	original := Plan{NodeID: id, Protocol: 0, Host: "target.example", Port: 22, Username: "candidate",
		Domain: "candidate-domain", Credential: Choice{Kind: "saved", ID: cred}}
	pin := EffectiveCredentialSnapshot{NodeID: id, ProtocolPath: "ssh", Username: "historical", SourceKind: "saved", CredentialID: cred}
	selected, err := RetainedAccount(original, "ssh", []EffectiveCredentialSnapshot{pin})
	if err != nil || selected == nil || *selected != pin {
		t.Fatal("SSH did not select its exact pin", err)
	}
	plan := ApplyRetainedAccount(original, *selected)
	if plan.Username != pin.Username || plan.Domain != "" || plan.Credential != (Choice{Kind: "saved", ID: cred, NodeID: id}) ||
		plan.Host != original.Host || plan.Port != original.Port {
		t.Fatal("pin altered the target or inherited part of another identity")
	}
	if unpinned, err := RetainedAccount(original, "sftp", []EffectiveCredentialSnapshot{pin}); err != nil || unpinned != nil {
		t.Fatal("SSH pin was applied to SFTP", err)
	}
	if _, err := RetainedAccount(original, "vnc", nil); err != ErrCredential {
		t.Fatal("accepted a request for an incompatible protocol", err)
	}
	invalid := pin
	invalid.ProtocolPath = "vnc"
	if _, err := RetainedAccount(original, "ssh", []EffectiveCredentialSnapshot{invalid}); err != ErrImportedPins {
		t.Fatal("accepted a stale pin after inherited protocol changes", err)
	}
	original.Credential.Kind = "override"
	if chosen, err := RetainedAccount(original, "ssh", []EffectiveCredentialSnapshot{pin}); err != nil || chosen != nil {
		t.Fatal("retained identity displaced an override", err)
	}
}

func TestRetainedGatewayAccountAndSystemChoiceAreIndependent(t *testing.T) {
	id, cred := uuid.NewString(), uuid.NewString()
	base := Plan{NodeID: id, Protocol: 1, GatewayMethod: 1, GatewayCredentialID: cred,
		Credential: Choice{Kind: "override", ID: uuid.NewString()}, Username: "primary", Domain: "DOMAIN"}
	pin := EffectiveCredentialSnapshot{NodeID: id, ProtocolPath: "rdp-gateway", SourceKind: "system"}
	chosen, err := RetainedAccount(base, "rdp-gateway", []EffectiveCredentialSnapshot{pin})
	if err != nil || chosen == nil {
		t.Fatal("primary override displaced an independent gateway", err)
	}
	plan := ApplyRetainedAccount(base, *chosen)
	if !plan.ExternalRDPClient || plan.Credential != (Choice{Kind: "none"}) || plan.Username != "" || plan.Domain != "" {
		t.Fatal("system selection retained native credential material")
	}
	if candidate := GatewayCandidate(base); candidate.Credential != (Choice{Kind: "saved", ID: cred, NodeID: id}) ||
		candidate.Username != "" || candidate.Domain != "" {
		t.Fatal("independent candidate gateway inherited the primary identity")
	}
	base.GatewaySameCredentials = true
	if chosen, err := RetainedAccount(base, "rdp-gateway", []EffectiveCredentialSnapshot{pin}); err != nil || chosen != nil {
		t.Fatal("gateway could not reuse the explicit override", err)
	}
	if candidate := GatewayCandidate(base); candidate != base {
		t.Fatal("reused credentials changed on the gateway path")
	}
	base.GatewayMethod = 0
	if candidate := GatewayCandidate(base); candidate.Credential != (Choice{Kind: "none"}) || candidate.Username != "" || candidate.Domain != "" {
		t.Fatal("inactive gateway selected an account")
	}
}
