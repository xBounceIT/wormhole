package sharedpg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/workspaceimport"
)

func pairedRDPWireFixture(t *testing.T) (connectionFixture, map[string]any) {
	t.Helper()
	f, wire := releaseGraphFixture(t, "gateway", true, false)
	metadata := wire["metadata"].(map[string]any)
	gatewayMetadata := maps.Clone(metadata)
	base := metadata["plan"].(resolver.Plan)
	gateway, err := resolver.ApplyCredential(resolver.GatewayCandidate(base), f.records.Gateway.Credential.Record.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	base.GatewayCredentialID, gateway.GatewayCredentialID = "", ""
	chain := metadata["chain"].([]any)
	for i, row := range chain {
		chain[i] = append(row.([]any), nil)
	}
	for _, entry := range []struct {
		metadata map[string]any
		plan     resolver.Plan
		path     string
		profile  string
	}{{metadata, base, "rdp", "credential"}, {gatewayMetadata, gateway, "rdp-gateway", "gateway"}} {
		entry.metadata["credential"] = append(entry.metadata[entry.profile].([]any), nil)
		entry.metadata["gateway"], entry.metadata["tunnel"], entry.metadata["importedData"] = nil, nil, nil
		entry.metadata["path"], entry.metadata["formatVersion"], entry.metadata["plan"] = entry.path, 4, entry.plan
		required := map[string]bool{entry.metadata["credential"].([]any)[5].(string): true}
		for _, row := range chain {
			required[row.([]any)[5].(string)] = true
		}
		boundaries := []any{}
		for _, row := range entry.metadata["boundaries"].([]any) {
			if required[row.([]any)[1].(string)] {
				boundaries = append(boundaries, row)
			}
		}
		entry.metadata["boundaries"] = boundaries
	}
	half := func(i int, proof map[string]any) map[string]any {
		source := maps.Clone(wire)
		section := maps.Clone(wire["accounts"].([]any)[i].(map[string]any))
		copies := section["copies"].([]any)
		for j, row := range copies {
			copies[j] = append(row.([]any), nil)
		}
		section["account"] = "primary"
		source["metadata"], source["formatVersion"], source["nodeFields"], source["enrollment"] = proof, 5, nil, nil
		source["accounts"] = []any{section}
		roots := wire["roots"].([]any)
		for _, row := range roots {
			key := row.([]any)
			if key[3] == copies[0].([]any)[5] {
				source["roots"] = []any{append(key, nil)}
				return source
			}
		}
		t.Fatal("missing root for paired RDP fixture")
		return nil
	}
	return f, map[string]any{"formatVersion": 6, "primary": half(0, metadata), "gateway": half(1, gatewayMetadata)}
}

func TestPairedRDPRequiresBothRolesFromTheSameSnapshot(t *testing.T) {
	for _, mode := range []string{"valid", "missing-gateway", "standalone-primary", "wrong-gateway-path", "different-source", "nested-pair", "unexpected-property"} {
		t.Run(mode, func(t *testing.T) {
			f, wire := pairedRDPWireFixture(t)
			switch mode {
			case "missing-gateway":
				wire["gateway"] = nil
			case "standalone-primary":
				wire = wire["primary"].(map[string]any)
			case "wrong-gateway-path":
				wire["gateway"].(map[string]any)["metadata"].(map[string]any)["path"] = "rdp"
			case "different-source":
				wire["gateway"].(map[string]any)["metadata"].(map[string]any)["importedData"] = "7b7d"
			case "nested-pair":
				wire["primary"] = map[string]any{"formatVersion": 6, "primary": nil, "gateway": nil}
			case "unexpected-property":
				wire["extra"] = true
			}
			raw, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			req := AdmissionRequest{WorkspaceID: f.s.WorkspaceID, UserID: f.s.UserID}
			graph, err := parseCredentialRelease(raw, req, f.node(), 1, 7)
			if mode != "valid" {
				if err != ErrAdmissionResponse || graph != nil {
					t.Fatal("unexpected RDP release shape was admitted", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			next, release, err := f.s.VerifyCredentialRelease(ctx, f.node(), graph)
			if err != nil || release == nil || next.Revision <= f.s.Revision {
				t.Fatal("valid paired graph did not verify", err)
			}
			graph.rdpGateway.metadata.records.Credential.Credential.Seal.Signature[0] ^= 1
			next, release, err = f.s.VerifyCredentialRelease(ctx, f.node(), graph)
			if err == nil || release != nil || next.Revision <= f.s.Revision {
				t.Fatal("invalid gateway discarded primary observations or prepared a release", err)
			}
		})
	}
}

func TestPairedRDPRejectsInconsistentSharedCredentialValues(t *testing.T) {
	id := uuid.New()
	v := UnverifiedSharedValue{Binding: vault.SharedValueBinding{OwnerKind: "credential", OwnerID: id, Field: "password", Version: 1,
		DEK: vault.KeyRef{ID: uuid.New(), Version: 1}}, Envelope: vault.Envelope{Ciphertext: []byte{1}}}
	section := func(value UnverifiedSharedValue) *UnverifiedCredentialRelease {
		return &UnverifiedCredentialRelease{accounts: []credentialReleaseAccount{{values: []UnverifiedSharedValue{value}}}}
	}
	if !consistentRDPValues(section(v), section(v)) {
		t.Fatal("the same authenticated account cannot be used twice")
	}
	substitute := v
	substitute.Envelope.Ciphertext = []byte{2}
	if consistentRDPValues(section(v), section(substitute)) {
		t.Fatal("paired release accepted two values for one field revision")
	}
	substitute.Binding.OwnerID = uuid.New()
	if consistentRDPValues(section(v), section(substitute)) {
		t.Fatal("paired release reused one DEK for distinct account fields")
	}
}

func TestPairedRDPGatewayBorrowPreservesTheSelectedFieldAndIdentity(t *testing.T) {
	for _, tc := range []struct {
		kind, node, credential string
		values                 CredentialReleaseValues
		want                   string
		err                    error
	}{
		{"saved", "node", "account", CredentialReleaseValues{Primary: &BorrowedCredential{
			Metadata: vaultstore.CredentialMetadata{ID: "account", Username: "current-profile"}, Fields: map[string][]byte{"password": []byte("selected")}}}, "selected", nil},
		{"override", "node", "unrelated", CredentialReleaseValues{Primary: &BorrowedCredential{
			Metadata: vaultstore.CredentialMetadata{ID: "account"}}}, "", ErrAdmissionResponse},
		{"inline", "node", "", CredentialReleaseValues{Inline: &BorrowedNodeFields{
			NodeID: "node", Fields: map[string][]byte{"inlinePassword": []byte("stored-inline")}}}, "stored-inline", nil},
		{"inline", "node", "", CredentialReleaseValues{Inline: &BorrowedNodeFields{NodeID: "other"}}, "", ErrAdmissionResponse},
		{"inline", "node", "", CredentialReleaseValues{Inline: &BorrowedNodeFields{NodeID: "node"}}, "", nil},
		{"none", "node", "", CredentialReleaseValues{}, "", nil},
		{"unresolved", "node", "", CredentialReleaseValues{}, "", ErrAdmissionResponse},
	} {
		a := rdpReleaseAccount{Plan: resolver.Plan{Username: "historical", Domain: "SCOPE", Credential: resolver.Choice{Kind: tc.kind}}, Values: tc.values}
		borrowed, err := a.borrowedGateway(tc.node, tc.credential)
		if err != tc.err || (borrowed == nil) != (err != nil) {
			t.Fatal("incorrect gateway field selection", err)
		}
		if borrowed != nil && (borrowed.Metadata.Username != "historical" || borrowed.Metadata.Domain != "SCOPE" ||
			!bytes.Equal(borrowed.Fields["password"], []byte(tc.want))) {
			t.Fatal("gateway used the current profile instead of the authenticated selection")
		}
	}
}

func TestPairedRDPSystemPinCannotBecomeANativeCredential(t *testing.T) {
	for _, path := range []string{"rdp", "rdp-gateway"} {
		id := uuid.NewString()
		data := workspaceimport.NodeData{FormatVersion: 1, NodeID: id,
			Pins: []resolver.EffectiveCredentialSnapshot{{NodeID: id, ProtocolPath: path, SourceKind: "system"}}}
		raw, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		protocol := 1
		node := vaultstore.NodeMetadata{ID: id, Kind: 1, Protocol: &protocol,
			Imported: &vaultstore.NodeImportReference{Digest: hex.EncodeToString(digest[:]), RetainedPins: true}}
		graph := &UnverifiedCredentialRelease{pairedRDP: true, metadata: &UnverifiedConnectionSnapshot{
			records: CatalogConnectionRecords{Imported: raw, Chain: []UnverifiedChainRecord{{Node: UnverifiedTreeNode{Metadata: node}}}}}}
		release := &VerifiedCredentialRelease{graph: graph, plan: resolver.Plan{NodeID: id, Protocol: 1, ExternalRDPClient: true}}
		if path == "rdp-gateway" {
			release.plan.GatewayMethod = 1
			release.rdpGateway = &VerifiedCredentialRelease{plan: resolver.Plan{NodeID: id, Protocol: 1, ExternalRDPClient: true}}
		}
		if _, err := release.RDPPlan(false); err != vault.ErrPolicy {
			t.Fatal("a system pin could select native credentials", err)
		}
		plan, err := release.RDPPlan(true)
		if path == "rdp" && (err != nil || plan.ExternalRDPClient || plan.Credential.Kind != "none") {
			t.Fatal("manual primary was replaced by a saved system identity", err)
		}
		if path == "rdp-gateway" && err != vault.ErrPolicy {
			t.Fatal("manual primary bypassed a system gateway", err)
		}
	}
}
