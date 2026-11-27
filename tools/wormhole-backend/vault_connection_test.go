package main

import (
	"context"
	"encoding/json"
	"math"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func vaultConnectionInput(id, revision, protocol string) map[string]any {
	var rdp any
	if protocol == "rdp" {
		value, _ := normalizeWorkspaceRdpSettings(nil)
		rdp = value
	}
	host := "host.example"
	if protocol == "serial" {
		if runtime.GOOS == "windows" {
			host = "COM3"
		} else {
			host = "/dev/ttyUSB0"
		}
	}
	return map[string]any{"rowVersion": revision, "notesAction": "preserve", "password": []byte{}, "notes": []byte{}, "metadata": map[string]any{
		"id": id, "parentId": "", "name": " Connection ", "protocol": protocol, "host": host, "port": 0, "username": "alice", "inlinePasswordAction": "clear",
		"sshAutoSudo": nil, "httpIgnoreCertErrors": nil, "tunnelEnabled": nil, "tunnelConfigId": "", "credentialMode": 1, "credentialId": "",
		"serialBaudRate": 115200, "serialDataBits": 8, "serialStopBits": 1, "serialParity": 0, "serialFlowControl": 0, "rdp": rdp,
	}}
}

func TestVaultConnectionEditorCannotSilentlyOverrideMigrationPins(t *testing.T) {
	h, ctx := vaultCredentialFixture(t), context.Background()
	input := vaultConnectionInput("", "0", "ssh")
	metadata := input["metadata"].(map[string]any)
	metadata["inlinePasswordAction"] = "set"
	input["password"] = []byte("native-fixture")
	node := saveVaultConnectionFixture(t, h, input)
	descriptor, err := describeVaultSlots(h.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	var before, after []resolver.EffectiveCredentialSnapshot
	for _, path := range []string{"ssh", "sftp", "reveal"} {
		old := resolver.EffectiveCredentialSnapshot{NodeID: node.ID, ProtocolPath: path, CredentialID: node.ID, Username: "kept-identity", SourceKind: "inline"}
		next := old
		next.Username = "new-identity"
		next.ResolverVersion = resolver.Version
		before = append(before, old)
		after = append(after, next)
	}
	plan, err := resolver.BuildMigration(descriptor.VaultID, before, after)
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := h.owner.ImportResolverMigration(ctx, node.ID, plan, node.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	metadata["id"], metadata["username"], input["rowVersion"] = node.ID, "new-identity", "2"
	if _, err := h.Handle(ctx, "connection-save", vaultInput(t, input)); err != vault.ErrPolicy {
		t.Fatal("editor acknowledged a choice overridden by a migration pin", err)
	}
	unchanged, err := h.owner.ReadNode(ctx, node.ID, 0)
	if err != nil || !reflect.DeepEqual(unchanged, pinned) {
		t.Fatal("refusal modified pinned connection", err)
	}
	choices := []resolver.MigrationDecision{}
	for _, path := range []string{"ssh", "sftp", "reveal"} {
		choices = append(choices, resolver.MigrationDecision{NodeID: node.ID, ProtocolPath: path, Choice: "new"})
	}
	decided, err := h.owner.DecideResolverMigration(ctx, node.ID, 2, plan.Fingerprint, choices)
	if err != nil {
		t.Fatal(err)
	}
	input["rowVersion"] = "3"
	metadata["inlinePasswordAction"] = "preserve"
	input["password"] = []byte{}
	saved := saveVaultConnectionFixture(t, h, input)
	if saved.RowVersion != 4 || !reflect.DeepEqual(saved.Fields, decided.Fields) {
		t.Fatal("editor did not retain migration provenance", saved.Fields)
	}
}

func TestVaultConnectionEditorAuthenticatesInheritedIdentityAndReferences(t *testing.T) {
	h, ctx := vaultCredentialFixture(t), context.Background()
	sshID, rdpID := uuid.NewString(), uuid.NewString()
	for id, protocol := range map[string]string{sshID: "ssh", rdpID: "rdp"} {
		if _, err := h.Handle(ctx, "credential-save", vaultInput(t, map[string]any{"rowVersion": "0", "changes": []any{}, "metadata": map[string]any{"id": id, "name": "Credential " + protocol, "protocol": protocol, "kind": "password", "provider": "local", "username": "AzureAD\\user"}})); err != nil {
			t.Fatal(err)
		}
	}
	mode := 2
	parent, err := h.owner.PutNode(ctx, vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "Parent", Kind: 0, CredentialMode: &mode, CredentialID: &rdpID}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	input := vaultConnectionInput("", "0", "rdp")
	m := input["metadata"].(map[string]any)
	m["parentId"], m["credentialMode"], m["username"] = parent.ID, 0, ""
	created := saveVaultConnectionFixture(t, h, input)
	if *created.RDPUseExternalClient != (runtime.GOOS == "windows") {
		t.Fatal("inherited AzureAD was not enforced")
	}
	for _, gateway := range []string{uuid.NewString(), sshID, rdpID} {
		settings := m["rdp"].(workspaceRdpSettings)
		settings.GatewayHostname = "gateway.example"
		settings.GatewayUsageMethod = 1
		settings.GatewayUseSameCreds = false
		settings.GatewayCredentialID = gateway
		m["rdp"] = settings
		_, err := h.Handle(ctx, "connection-save", vaultInput(t, input))
		if (err == nil) != (gateway == rdpID) {
			t.Fatal("gateway identity validation", err)
		}
	}
	for _, credential := range []string{uuid.NewString(), sshID, rdpID} {
		m["credentialMode"], m["credentialId"] = 2, credential
		_, err := h.Handle(ctx, "connection-save", vaultInput(t, input))
		if (err == nil) != (credential == rdpID) {
			t.Fatal("credential identity validation", err)
		}
	}
	// A connection cannot be reused as a parent, including an otherwise valid ID.
	m["parentId"] = created.ID
	if _, err := h.Handle(ctx, "connection-save", vaultInput(t, input)); err == nil {
		t.Fatal("connection parent accepted")
	}
	m["id"], input["rowVersion"] = parent.ID, "1"
	if _, err := h.Handle(ctx, "connection-save", vaultInput(t, input)); err != vaultstore.ErrConflict {
		t.Fatal("folder converted", err)
	}
	m["id"] = uuid.NewString()
	if _, err := h.Handle(ctx, "connection-save", vaultInput(t, input)); err == nil {
		t.Fatal("missing edited node")
	}
	cycle := created.NodeMetadata
	cycle.ParentID = &cycle.ID
	if _, err := h.previewConnection(ctx, cycle); err == nil {
		t.Fatal("cycle accepted")
	}
	if _, err := h.owner.PutNode(ctx, vaultstore.NodeMetadata{ID: uuid.NewString(), Kind: 0, Name: "Last", SortOrder: math.MaxInt64}, nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "connection-save", vaultInput(t, vaultConnectionInput("", "0", "ssh"))); err != vaultstore.ErrConflict {
		t.Fatal("sort overflow", err)
	}
	if err := h.owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.saveConnection(ctx, vaultInput(t, vaultConnectionInput(created.ID, "1", "ssh"))); err == nil {
		t.Fatal("closed owner")
	}
}

func saveVaultConnectionFixture(t *testing.T, h *vaultFoundationHandler, input map[string]any) vaultstore.Node {
	t.Helper()
	raw, err := h.Handle(context.Background(), "connection-save", vaultInput(t, input))
	if err != nil {
		t.Fatal(err)
	}
	var reply struct {
		NodeID     string `json:"nodeId"`
		RowVersion string `json:"rowVersion"`
		Updated    bool   `json:"updated"`
	}
	if json.Unmarshal(raw, &reply) != nil || !reply.Updated || !vaultCredentialID(reply.NodeID) || len(strings.Split(string(raw), ":")) != 4 {
		t.Fatal(string(raw))
	}
	node, err := h.owner.ReadNode(context.Background(), reply.NodeID, 0)
	if err != nil {
		t.Fatal(err)
	}
	return node
}

func TestVaultConnectionEditorProtocolsAndNormalization(t *testing.T) {
	h := vaultCredentialFixture(t)
	for protocol, number := range map[string]int{"ssh": 0, "sftp": 7, "rdp": 1, "http": 3, "https": 4, "vnc": 6, "serial": 5} {
		input := vaultConnectionInput("", "0", protocol)
		metadata := input["metadata"].(map[string]any)
		if protocol == "https" {
			metadata["host"] = "https://example.com:8443/path?q=1"
			metadata["httpIgnoreCertErrors"] = true
		}
		if protocol == "rdp" {
			rdp := metadata["rdp"].(workspaceRdpSettings)
			rdp.Domain = "AzureAD"
			metadata["rdp"] = rdp
		}
		n := saveVaultConnectionFixture(t, h, input)
		if n.Kind != 1 || *n.Protocol != number || n.Name != "Connection" || n.RowVersion != 1 {
			t.Fatal(n)
		}
		if protocol == "https" && (*n.Host != "example.com" || *n.Port != 8443 || *n.HTTPPath != "/path" || !*n.HTTPIgnoreCertErrors) {
			t.Fatal(n)
		}
		if protocol == "serial" && (*n.SerialBaudRate != 115200 || *n.TunnelEnabled || n.Username != nil) {
			t.Fatal(n)
		}
		if protocol == "rdp" && *n.RDPUseExternalClient != (runtime.GOOS == "windows") {
			t.Fatal(n)
		}
	}
}

func TestVaultConnectionEditorSecretActionsAndAtomicRevision(t *testing.T) {
	h, ctx := vaultCredentialFixture(t), context.Background()
	input := vaultConnectionInput("", "0", "ssh")
	m := input["metadata"].(map[string]any)
	m["inlinePasswordAction"] = "set"
	input["password"] = []byte("only-native-password")
	input["notesAction"] = "set"
	input["notes"] = []byte("only-native-notes")
	created := saveVaultConnectionFixture(t, h, input)
	if !*created.UseInlinePassword {
		t.Fatal(created)
	}
	m["id"], m["name"], m["inlinePasswordAction"] = created.ID, "Renamed", "preserve"
	input["rowVersion"], input["notesAction"], input["password"], input["notes"] = "1", "preserve", []byte{}, []byte{}
	renamed := saveVaultConnectionFixture(t, h, input)
	if renamed.SortOrder != created.SortOrder || renamed.CreatedAt != created.CreatedAt || !reflect.DeepEqual(renamed.Fields, created.Fields) {
		t.Fatal("preserve changed authenticated fields")
	}
	for field, want := range map[string]string{"notes": "only-native-notes", "inlinePassword": "only-native-password"} {
		if err := h.owner.WithNodeField(ctx, created.ID, field, 2, func(value []byte) error {
			if string(value) != want {
				t.Fatal("secret changed")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.Handle(ctx, "connection-save", vaultInput(t, input)); err != vaultstore.ErrConflict {
		t.Fatal("stale update", err)
	}
	input["rowVersion"] = "2"
	m["parentId"] = uuid.NewString()
	m["inlinePasswordAction"] = "clear"
	input["notesAction"] = "clear"
	if _, err := h.Handle(ctx, "connection-save", vaultInput(t, input)); err == nil {
		t.Fatal("missing parent")
	}
	unchanged, err := h.owner.ReadNode(ctx, created.ID, 0)
	if err != nil || !reflect.DeepEqual(renamed, unchanged) {
		t.Fatal("failed write changed secrets", err)
	}
	m["parentId"] = ""
	cleared := saveVaultConnectionFixture(t, h, input)
	if *cleared.UseInlinePassword {
		t.Fatal("inline flag retained")
	}
	for _, f := range cleared.Fields {
		if f.Present {
			t.Fatal("field not removed")
		}
	}
	input["rowVersion"] = "3"
	m["inlinePasswordAction"] = "preserve"
	if _, err := h.Handle(ctx, "connection-save", vaultInput(t, input)); err != vaultwire.ErrProtocol {
		t.Fatal("preserve nonexistent password", err)
	}
}

func TestVaultConnectionEditorStrictMetadataAndBytes(t *testing.T) {
	h, ctx := vaultCredentialFixture(t), context.Background()
	for key, values := range map[string][]any{"id": {"bad"}, "parentId": {"bad"}, "credentialId": {"bad", uuid.NewString()}, "tunnelConfigId": {"bad"}, "name": {"", strings.Repeat("x", 257)}, "protocol": {"unknown"}, "port": {-1, 65536}, "host": {"", "https://user:pass@example.com"}, "inlinePasswordAction": {"", "set", "preserve", "unknown"}, "rdp": {map[string]any{}}, "notes": {"unapproved"}} {
		for _, value := range values {
			input := vaultConnectionInput("", "0", "https")
			input["metadata"].(map[string]any)[key] = value
			if _, err := h.Handle(ctx, "connection-save", vaultInput(t, input)); err == nil {
				t.Fatalf("accepted %s", key)
			}
		}
	}
	for key, values := range map[string][]any{"rowVersion": {nil, 0, "01", "1", "9223372036854775807"}, "notesAction": {"unknown", "clear"}, "password": {nil, []int{1}, "!", []byte("unexpected"), []byte{0xff}, []byte(strings.Repeat("x", 4097))}, "notes": {nil, []int{1}, "!", []byte{0}, []byte(strings.Repeat("x", 16385))}, "secret": {"unknown"}} {
		for _, value := range values {
			input := vaultConnectionInput("", "0", "ssh")
			if key == "notesAction" {
				input["notes"] = []byte("unexpected")
			}
			input[key] = value
			if _, err := h.Handle(ctx, "connection-save", vaultInput(t, input)); err != vaultwire.ErrProtocol {
				t.Fatalf("accepted %s: %v", key, err)
			}
		}
	}
	valid := vaultInput(t, vaultConnectionInput("", "0", "ssh"))
	for _, raw := range [][]byte{nil, []byte(`null`), []byte(`{}`), []byte(strings.Repeat(" ", 256*1024+1)), []byte(strings.Replace(string(valid), `"notesAction":`, `"notesAction":"preserve","notesAction":`, 1)), []byte(strings.Replace(string(valid), `"name":`, `"name":"duplicate","name":`, 1))} {
		if _, err := h.Handle(ctx, "connection-save", raw); err != vaultwire.ErrProtocol {
			t.Fatal(err)
		}
	}
	if _, err := (&vaultFoundationHandler{}).Handle(ctx, "connection-save", valid); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	for _, mutate := range []func(map[string]any){func(m map[string]any) { m["rdp"] = nil }, func(m map[string]any) { m["rdp"] = map[string]any{} }, func(m map[string]any) {
		v := m["rdp"].(workspaceRdpSettings)
		v.GatewayCredentialID = "bad"
		m["rdp"] = v
	}, func(m map[string]any) { v := m["rdp"].(workspaceRdpSettings); v.ColorDepth = 17; m["rdp"] = v }} {
		input := vaultConnectionInput("", "0", "rdp")
		mutate(input["metadata"].(map[string]any))
		if _, err := h.Handle(ctx, "connection-save", vaultInput(t, input)); err != vaultwire.ErrProtocol {
			t.Fatal(err)
		}
	}
}
