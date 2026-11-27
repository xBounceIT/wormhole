package resolver

import (
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"testing"
)

func TestAccountPathBoundsAndIdentityValidation(t *testing.T) {
	for protocol, want := range map[int]string{0: "ssh", 7: "sftp", 1: "rdp", 6: "vnc", 3: "reveal", 4: "reveal", 5: "reveal"} {
		if DefaultPath(protocol) != want || !PathAllowed(protocol, want) {
			t.Fatal(protocol)
		}
	}
	if PathAllowed(99, "reveal") || PathAllowed(0, "") {
		t.Fatal("invalid path accepted")
	}
	for _, username := range []string{" user ", `\user`, `domain\`} {
		_, domain := SplitRDPIdentity(username)
		if domain != "" {
			t.Fatal("incomplete domain split")
		}
	}
	p := Plan{NodeID: uuid.NewString(), Protocol: 0, Credential: Choice{Kind: "override", ID: uuid.NewString()}}
	if s, err := AccountSnapshot(p, "ssh", "linux", nil); err != nil || s.SourceKind != "saved" {
		t.Fatal(err)
	}
	p.NodeID = "invalid"
	if _, err := AccountSnapshot(p, "ssh", "linux", nil); err != ErrCredential {
		t.Fatal(err)
	}
	p.NodeID = uuid.NewString()
	p.Protocol = 1
	p.GatewayMethod = 1
	p.GatewayCredentialID = uuid.NewString()
	if _, err := AccountSnapshot(p, "rdp-gateway", "linux", nil); err != ErrCredential {
		t.Fatal(err)
	}
	if _, err := AccountSnapshot(p, "rdp-gateway", "linux", func(string) (vaultstore.CredentialMetadata, error) {
		return vaultstore.CredentialMetadata{ID: uuid.NewString(), Protocol: "rdp"}, nil
	}); err != ErrCredential {
		t.Fatal("substituted gateway", err)
	}
}

func TestAccountSnapshotProtocolIdentities(t *testing.T) {
	id, credential, gateway := uuid.NewString(), uuid.NewString(), uuid.NewString()
	base := Plan{Version: 1, NodeID: id, Protocol: 1, Username: `DOMAIN\user`, Credential: Choice{Kind: "saved", ID: credential}}
	lookup := func(id string) (vaultstore.CredentialMetadata, error) {
		if id != gateway {
			return vaultstore.CredentialMetadata{}, ErrCredential
		}
		return vaultstore.CredentialMetadata{ID: gateway, Protocol: "rdp", Username: "gateway-user", Domain: "EDGE"}, nil
	}
	tests := []struct {
		name, path, os, source, selected, username, domain string
		modify                                             func(*Plan)
	}{
		{"rdp split", "rdp", "windows", "saved", credential, "user", "DOMAIN", nil},
		{"same gateway", "rdp-gateway", "linux", "saved", credential, "user", "", func(p *Plan) { p.GatewayMethod = 1; p.GatewaySameCredentials = true }},
		{"separate gateway", "rdp-gateway", "linux", "saved", gateway, `EDGE\gateway-user`, "", func(p *Plan) { p.GatewayMethod = 1; p.GatewayCredentialID = gateway }},
		{"disabled gateway", "rdp-gateway", "linux", "none", "", "", "", nil},
		{"empty gateway", "rdp-gateway", "linux", "none", "", "", "", func(p *Plan) { p.GatewayMethod = 1 }},
		{"external windows", "rdp", "windows", "system", "", "", "", func(p *Plan) { p.ExternalRDPClient = true }},
		{"external gateway", "rdp-gateway", "windows", "system", "", "", "", func(p *Plan) { p.ExternalRDPClient = true }},
		{"azure windows", "rdp", "windows", "system", "", "", "", func(p *Plan) { p.Domain = "AzureAD" }},
		{"external linux", "rdp", "linux", "saved", credential, "user", "DOMAIN", func(p *Plan) { p.ExternalRDPClient = true }},
		{"reveal external", "reveal", "windows", "saved", credential, `DOMAIN\user`, "", func(p *Plan) { p.ExternalRDPClient = true }},
		{"vnc", "vnc", "linux", "saved", credential, "", "", func(p *Plan) { p.Protocol = 6 }},
		{"ssh", "ssh", "linux", "saved", credential, `DOMAIN\user`, "", func(p *Plan) { p.Protocol = 0; p.Domain = "ignored" }},
		{"sftp", "sftp", "linux", "saved", credential, `DOMAIN\user`, "", func(p *Plan) { p.Protocol = 7 }},
		{"web reveal", "reveal", "linux", "none", "", "", "", func(p *Plan) { p.Protocol = 4 }},
		{"inline", "rdp", "linux", "inline", id, "user", "DOMAIN", func(p *Plan) { p.Credential = Choice{Kind: "inline", ID: id} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := base
			if test.modify != nil {
				test.modify(&p)
			}
			got, err := AccountSnapshot(p, test.path, test.os, lookup)
			want := EffectiveCredentialSnapshot{NodeID: id, ProtocolPath: test.path, ResolverVersion: 1, SourceKind: test.source, CredentialID: test.selected, Username: test.username, Domain: test.domain}
			if err != nil || got != want {
				t.Fatal(got, want, err)
			}
		})
	}
	for _, path := range []string{"ssh", "sftp", "vnc", "unknown"} {
		if _, err := AccountSnapshot(base, path, "linux", lookup); err == nil {
			t.Fatal("wrong path accepted", path)
		}
	}
	base.Protocol = 0
	for _, path := range []string{"rdp", "rdp-gateway"} {
		if _, err := AccountSnapshot(base, path, "linux", lookup); err == nil {
			t.Fatal("wrong path accepted", path)
		}
	}
	base.Protocol, base.GatewayMethod, base.GatewayCredentialID = 1, 1, credential
	if _, err := AccountSnapshot(base, "rdp-gateway", "linux", lookup); err == nil {
		t.Fatal("missing gateway accepted")
	}
}
