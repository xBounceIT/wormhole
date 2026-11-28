package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func displayPtr[T any](value T) *T { return &value }

func TestVaultWorkspaceHandlerLifecycle(t *testing.T) {
	ctx := context.Background()
	if _, err := (&vaultFoundationHandler{}).Handle(ctx, "workspace", nil); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	h := vaultCredentialFixture(t)
	if _, err := h.Handle(ctx, "workspace", []byte(`{}`)); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	raw, err := h.Handle(ctx, "workspace", nil)
	if err != nil || string(raw) != `{"tree":[],"credentials":[],"credentialOptions":{"rdp":[],"ssh":[],"vnc":[]},"tunnels":[]}` {
		t.Fatal(string(raw), err)
	}
	c := vaultstore.CredentialMetadata{ID: uuid.NewString(), Name: "Account", Protocol: "rdp", Kind: "password", Provider: "local", Username: "account", Domain: "DOMAIN"}
	if _, err := h.owner.PutCredential(ctx, c, []localvault.SecretChange{{Field: "password", Value: []byte("workspace-private-password")}}, 0); err != nil {
		t.Fatal(err)
	}
	n := vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "RDP", Kind: 1, Protocol: displayPtr(1), Host: displayPtr("host.example"), CredentialID: &c.ID}
	if _, err := h.owner.PutNode(ctx, n, []localvault.SecretChange{{Field: "notes", Value: []byte("workspace-private-notes")}}, 0); err != nil {
		t.Fatal(err)
	}
	raw, err = h.Handle(ctx, "workspace", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"workspace-private-", "seal", "fields", "rootKey", "resolverMigration"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatal("native/secret field leaked", forbidden)
		}
	}
	var result workspaceSnapshot
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Tree) != 1 || result.Tree[0].RowVersion != "1" {
		t.Fatal("missing public edit revision")
	}
	if len(result.Tree) != 1 || result.Tree[0].Username != "account" || result.Tree[0].RDP.Domain != "DOMAIN" || result.Tree[0].Port != 3389 {
		t.Fatal("native resolution lost")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := h.Handle(canceled, "workspace", nil); err != context.Canceled {
		t.Fatal(err)
	}
	if err := h.owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "workspace", nil); !errors.Is(err, vaultstore.ErrClosed) || !errors.Is(err, vaultwire.ErrRetired) || !h.closed {
		t.Fatal(err)
	}
}

func TestVaultWorkspaceProjectionOrderingInheritanceAndSafeFields(t *testing.T) {
	ctx := context.Background()
	parent := vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "Folder", Kind: 0, SortOrder: 0, Protocol: displayPtr(1), RDPDomain: displayPtr("PARENT"), RDPScreenSize: displayPtr("1600x900"), RDPFullScreen: displayPtr(true)}
	child := vaultstore.NodeMetadata{ID: uuid.NewString(), ParentID: &parent.ID, Name: "RDP", Kind: 1, SortOrder: 3, Username: displayPtr("stored"), RDPFullScreen: displayPtr(false)}
	serial := vaultstore.NodeMetadata{ID: uuid.NewString(), ParentID: &parent.ID, Name: "Serial", Kind: 1, SortOrder: 1, Protocol: displayPtr(5), Host: displayPtr("COM9"), SerialBaudRate: displayPtr(115200), SerialDataBits: displayPtr(7), SerialStopBits: displayPtr(2), SerialParity: displayPtr(1), SerialFlowControl: displayPtr(2)}
	plain := vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "Incomplete", Kind: 1, SortOrder: -1}
	credentials := []vaultstore.Credential{}
	for i, provider := range []string{"local", "bitwarden", "local"} {
		credentials = append(credentials, vaultstore.Credential{CredentialMetadata: vaultstore.CredentialMetadata{ID: fmt.Sprintf("11111111-1111-4111-8111-%012d", i+1), Name: []string{"Z", "A", "A"}[i], Protocol: "ssh", Kind: "password", Provider: provider, Username: "user"}})
	}
	credentials[0].PrivateKeyName = "identity"
	credentials[0].CertificateName = "identity-cert.pub"
	credentials[0].Fields = []vaultstore.SecretField{{Field: "certificate", Version: 1, Present: true}}
	tunnels := []vaultstore.Tunnel{}
	for i, name := range []string{"Z", "A", "A"} {
		tunnels = append(tunnels, vaultstore.Tunnel{TunnelMetadata: vaultstore.TunnelMetadata{ID: fmt.Sprintf("22222222-2222-4222-8222-%012d", i+1), Name: name, Kind: 0}})
	}
	view := localvault.WorkspaceView{Catalog: localvault.Catalog{Nodes: []vaultstore.Node{{NodeMetadata: child}, {NodeMetadata: parent}, {NodeMetadata: serial}, {NodeMetadata: plain}}, Credentials: credentials, Tunnels: tunnels}, Resolutions: map[string]localvault.WorkspaceResolution{child.ID: {Host: "inherited.example", Port: 3389, ExternalRDPClient: true, Username: "pinned", Domain: "PINNED"}}}
	got, err := projectVaultWorkspace(ctx, view)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Tree) != 2 || got.Tree[0].ID != plain.ID || got.Tree[0].Protocol != "" || got.Tree[1].ID != parent.ID || len(got.Tree[1].Children) != 2 {
		t.Fatal("tree order")
	}
	rdp := got.Tree[1].Children[1]
	if rdp.ID != child.ID || rdp.Host != "inherited.example" || rdp.Username != "pinned" || rdp.RDP.Domain != "PINNED" || rdp.RDP.FullScreen || rdp.RDP.ScreenSize != "1600x900" || !rdp.RDP.UseExternalClient {
		t.Fatal("RDP inheritance or retained identity")
	}
	s := got.Tree[1].Children[0]
	if s.ID != serial.ID || s.Host != "COM9" || *s.SerialBaudRate != 115200 || *s.SerialDataBits != 7 || *s.SerialStopBits != 2 || *s.SerialParity != 1 || *s.SerialFlowControl != 2 {
		t.Fatal("serial settings")
	}
	if got.Credentials[0].ID != credentials[1].ID || got.Credentials[1].ID != credentials[2].ID || got.Credentials[0].Provider != "Bitwarden" || !got.Credentials[2].HasCertificate || got.Credentials[2].Certificate != nil || got.CredentialOptions["ssh"][0].ID != credentials[1].ID {
		t.Fatal("credential projection")
	}
	if got.Tunnels[0].ID != tunnels[1].ID || got.Tunnels[1].ID != tunnels[2].ID || got.Tunnels[0].Kind != "WireGuard" {
		t.Fatal("tunnel projection")
	}
	// Name, then ID, resolve sort-order ties deterministically.
	view.Catalog.Nodes = []vaultstore.Node{{NodeMetadata: plain}, {NodeMetadata: plain}, {NodeMetadata: plain}}
	for i := range view.Catalog.Nodes {
		view.Catalog.Nodes[i].ID = fmt.Sprintf("33333333-3333-4333-8333-%012d", i+1)
		view.Catalog.Nodes[i].Name = []string{"Z", "A", "A"}[i]
	}
	got, err = projectVaultWorkspace(ctx, view)
	if err != nil || got.Tree[0].ID != view.Catalog.Nodes[1].ID || got.Tree[1].ID != view.Catalog.Nodes[2].ID {
		t.Fatal("node ties", err)
	}
}

func TestVaultWorkspaceProjectionBudgetAndCancellation(t *testing.T) {
	ctx := context.Background()
	for _, domain := range []string{"credentials", "tunnels", "nodes"} {
		t.Run(domain, func(t *testing.T) {
			view := localvault.WorkspaceView{}
			for i := 0; i < 18000; i++ {
				id := fmt.Sprintf("11111111-1111-4111-8111-%012d", i+1)
				switch domain {
				case "credentials":
					view.Catalog.Credentials = append(view.Catalog.Credentials, vaultstore.Credential{CredentialMetadata: vaultstore.CredentialMetadata{ID: id, Name: strings.Repeat("a", 1024), Protocol: "ssh", Kind: "password", Provider: "local"}})
				case "tunnels":
					view.Catalog.Tunnels = append(view.Catalog.Tunnels, vaultstore.Tunnel{TunnelMetadata: vaultstore.TunnelMetadata{ID: id, Name: strings.Repeat("a", 128)}})
				case "nodes":
					view.Catalog.Nodes = append(view.Catalog.Nodes, vaultstore.Node{NodeMetadata: vaultstore.NodeMetadata{ID: id, Name: strings.Repeat("a", 256), Kind: 1, Host: displayPtr(strings.Repeat("a", 1024))}})
				}
			}
			if domain == "tunnels" { // Each tunnel name can contain 128 four-byte Unicode runes.
				for i := range view.Catalog.Tunnels {
					view.Catalog.Tunnels[i].Name = strings.Repeat("🧪", 128)
				}
			}
			got, err := projectVaultWorkspace(ctx, view)
			if err != vaultwire.ErrProtocol || len(got.Tree) != 0 || len(got.Credentials) != 0 || len(got.Tunnels) != 0 {
				t.Fatal("oversized partial response", err)
			}
		})
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	for _, view := range []localvault.WorkspaceView{{Catalog: localvault.Catalog{Credentials: []vaultstore.Credential{{}}}}, {Catalog: localvault.Catalog{Tunnels: []vaultstore.Tunnel{{}}}}, {Catalog: localvault.Catalog{Nodes: []vaultstore.Node{{}}}}} {
		if _, err := projectVaultWorkspace(canceled, view); err != context.Canceled {
			t.Fatal(err)
		}
	}
}

func TestVaultWorkspaceTunnelRevision(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	metadata := vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "Tunnel", Kind: 2}
	saved, err := h.owner.PutTunnel(ctx, metadata, []byte(`{"Host":"gateway","Password":"private-value"}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"1", "2"} {
		raw, err := h.Handle(ctx, "workspace", nil)
		if err != nil {
			t.Fatal(err)
		}
		var snapshot workspaceSnapshot
		if err := json.Unmarshal(raw, &snapshot); err != nil {
			t.Fatal(err)
		}
		if len(snapshot.Tunnels) != 1 || snapshot.Tunnels[0].RowVersion != version || bytes.Contains(raw, []byte("private-value")) {
			t.Fatal("invalid tunnel projection")
		}
		saved, err = h.owner.PutTunnel(ctx, metadata, nil, saved.RowVersion)
		if err != nil {
			t.Fatal(err)
		}
	}
}
