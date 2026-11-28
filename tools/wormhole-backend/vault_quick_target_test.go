package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestVaultQuickWebAddressUsesNativeBrowserRules(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	for _, tc := range []struct {
		host, path, protocol string
		port                 int
		want                 string
	}{
		{"web.example", "", "https", 0, "https://web.example:443/"},
		{"http://web.example:8080/path%2Fpart?q=1#page", "", "https", 8443, "https://web.example:8443/path%2Fpart?q=1#page"},
		{"HTTPS://[::1]:8080/?q=1#page", "", "http", 0, "http://[::1]:8080/?q=1#page"},
		{"::1", "", "https", 0, "https://[::1]:443/"},
		{"web.example", "/path%2Fpart?q=1#page", "https", 0, "https://web.example:443/path%2Fpart?q=1#page"},
		{"web.example?", "", "https", 0, "https://web.example:443/?"},
	} {
		packet := quickTargetPacket()
		packet["target"] = localvault.QuickConnectionTarget{Protocol: tc.protocol, Host: tc.host, Port: tc.port, HTTPPath: tc.path, IgnoreCertificateErrors: tc.protocol == "https"}
		raw, err := h.Handle(ctx, "quick-target-register", vaultInput(t, packet))
		if err != nil {
			t.Fatal(tc.host, err)
		}
		var ref localvault.QuickTargetRef
		if json.Unmarshal(raw, &ref) != nil {
			t.Fatal("receipt")
		}
		q := map[string]any{"nodeId": ref.ID, "credentialOverride": "", "sessionId": ref.SessionID, "requestId": uuid.NewString(), "epoch": "1"}
		raw, err = h.Handle(ctx, "web-plan", vaultInput(t, q))
		if err != nil {
			t.Fatal(tc.host, err)
		}
		var plan vaultWebPlan
		if json.Unmarshal(raw, &plan) != nil || plan.Target.URL != tc.want || plan.Target.IgnoreCertErrors != (tc.protocol == "https") {
			t.Fatalf("target: %s %v", raw, err)
		}
		if _, err = h.owner.ReadNode(ctx, ref.ID, 0); !errors.Is(err, vaultstore.ErrMissing) {
			t.Fatal("temporary URL persisted", err)
		}
		if err = h.owner.ReleaseQuickTarget(ctx, ref); err != nil {
			t.Fatal(err)
		}
		if _, err = h.Handle(ctx, "web-plan", vaultInput(t, q)); err == nil {
			t.Fatal("released target reusable")
		}
	}
	for _, target := range []localvault.QuickConnectionTarget{
		{Protocol: "https", Host: "https://user:password@web.example/path"},
		{Protocol: "https", Host: "web.example/path", HTTPPath: "/other"},
		{Protocol: "https", Host: strings.Repeat("a", 4097)},
		{Protocol: "https", Host: "bad host"},
		{Protocol: "https", Host: "web.example:65536"},
		{Protocol: "https", Host: "[notipv6]"},
		{Protocol: "https", Host: "web.example/%%"},
		{Protocol: "https", Host: "web.example", CredentialID: uuid.NewString()},
		{Protocol: "https", Host: "web.example", TunnelID: "bad"},
		{Protocol: "http", Host: "web.example", IgnoreCertificateErrors: true},
	} {
		packet := quickTargetPacket()
		packet["target"] = target
		if _, err := h.Handle(ctx, "quick-target-register", vaultInput(t, packet)); err == nil {
			t.Fatal("invalid public browser target admitted")
		}
	}
}

func quickTargetPacket() map[string]any {
	return map[string]any{"sessionId": uuid.NewString(), "epoch": "1", "target": localvault.QuickConnectionTarget{Protocol: "ssh", Host: "quick.example"}}
}
func TestVaultQuickTargetRegistrationTrustAndRetirement(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	packet := quickTargetPacket()
	raw, err := h.Handle(ctx, "quick-target-register", vaultInput(t, packet))
	if err != nil {
		t.Fatal(err)
	}
	var ref localvault.QuickTargetRef
	if json.Unmarshal(raw, &ref) != nil || ref.ID == "" || ref.SessionID != packet["sessionId"] {
		t.Fatal("invalid target receipt")
	}
	q := map[string]any{"nodeId": ref.ID, "credentialOverride": "", "sessionId": ref.SessionID, "requestId": uuid.NewString(), "epoch": "1", "route": nil}
	raw, err = h.Handle(ctx, "ssh-host-plan", vaultInput(t, q))
	if err != nil {
		t.Fatal(err)
	}
	var plan localvault.SSHHostPlan
	if json.Unmarshal(raw, &plan) != nil {
		t.Fatal("plan response")
	}
	action := cloneSFTPPacket(q)
	action["expected"], action["received"] = plan, sealedSSHFixturePayload().Fingerprint
	if _, err = h.Handle(ctx, "ssh-host-trust", vaultInput(t, action)); err == nil {
		t.Fatal("generic trust admitted temporary source")
	}
	raw, err = h.Handle(ctx, "ssh-quick-host-trust", vaultInput(t, action))
	if err != nil {
		t.Fatal(err)
	}
	var trusted localvault.SSHHostPlan
	if json.Unmarshal(raw, &trusted) != nil || trusted.Fingerprint != action["received"] || trusted.Revision == plan.Revision {
		t.Fatal("ephemeral trust receipt")
	}
	if _, err = h.owner.ReadNode(ctx, ref.ID, 0); !errors.Is(err, vaultstore.ErrMissing) {
		t.Fatal("temporary target persisted", err)
	}
	release := map[string]any{"workspaceId": ref.WorkspaceID, "id": ref.ID, "sessionId": ref.SessionID, "epoch": "1"}
	raw, err = h.Handle(ctx, "quick-target-release", vaultInput(t, release))
	if err != nil || !bytes.Contains(raw, []byte("true")) {
		t.Fatal("retirement", err)
	}
	if _, err = h.Handle(ctx, "ssh-host-plan", vaultInput(t, q)); err == nil {
		t.Fatal("retired target reusable")
	}
	if _, err = h.Handle(ctx, "quick-target-release", vaultInput(t, release)); err != nil {
		t.Fatal("idempotent retirement", err)
	}
	for _, operation := range []string{"quick-target-register", "quick-target-release", "ssh-quick-host-trust"} {
		if !h.ExitOnCancel(operation) {
			t.Fatal("cancel retained temporary authority", operation)
		}
	}
	if !vaultFreshAction("ssh-quick-host-trust") || vaultFreshAction("quick-target-register") || vaultFreshAction("quick-target-release") {
		t.Fatal("fresh authentication classification")
	}
}
func TestVaultQuickTargetStrictNativeSchemas(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	makePacket := func() map[string]any {
		raw := vaultInput(t, quickTargetPacket())
		var value map[string]any
		if json.Unmarshal(raw, &value) != nil {
			t.Fatal("fixture")
		}
		return value
	}
	for _, field := range []string{"sessionId", "epoch", "target"} {
		for _, null := range []bool{false, true} {
			value := makePacket()
			if null {
				value[field] = nil
			} else {
				delete(value, field)
			}
			if _, err := h.Handle(ctx, "quick-target-register", vaultInput(t, value)); err == nil {
				t.Fatal("missing/null root", field)
			}
		}
	}
	for _, field := range []string{"protocol", "host", "port", "credentialId", "tunnelId", "sshAutoSudo", "httpPath", "ignoreCertificateErrors", "rdp"} {
		value := makePacket()
		delete(value["target"].(map[string]any), field)
		if _, err := h.Handle(ctx, "quick-target-register", vaultInput(t, value)); err == nil {
			t.Fatal("missing target", field)
		}
		if field != "rdp" {
			value = makePacket()
			value["target"].(map[string]any)[field] = nil
			if _, err := h.Handle(ctx, "quick-target-register", vaultInput(t, value)); err == nil {
				t.Fatal("null target", field)
			}
		}
	}
	for _, mutate := range []func(map[string]any){
		func(p map[string]any) { p["extra"] = true }, func(p map[string]any) { p["epoch"] = "01" }, func(p map[string]any) { p["epoch"] = "-1" }, func(p map[string]any) { p["epoch"] = 1 }, func(p map[string]any) { p["sessionId"] = "bad" },
		func(p map[string]any) { p["target"].(map[string]any)["password"] = "private" }, func(p map[string]any) { p["target"].(map[string]any)["username"] = "private" },
		func(p map[string]any) { p["target"].(map[string]any)["rdp"] = map[string]any{} },
	} {
		value := makePacket()
		mutate(value)
		if _, err := h.Handle(ctx, "quick-target-register", vaultInput(t, value)); err == nil {
			t.Fatal("invalid native input")
		}
	}
	raw := vaultInput(t, quickTargetPacket())
	duplicate := bytes.Replace(raw, []byte("\"epoch\":\"1\""), []byte("\"epoch\":\"1\",\"epoch\":\"1\""), 1)
	if _, err := h.Handle(ctx, "quick-target-register", duplicate); err == nil {
		t.Fatal("duplicate epoch")
	}
	for _, mode := range []string{"locked", "shared", "nil", "large", "unknown"} {
		handler, contextValue, operation, body := h, ctx, "quick-target-register", raw
		switch mode {
		case "locked":
			handler = &vaultFoundationHandler{}
		case "shared":
			handler = &vaultFoundationHandler{owner: h.owner, shared: &vaultSharedSession{}}
		case "nil":
			contextValue = nil
		case "large":
			body = make([]byte, 32769)
		case "unknown":
			operation = "unexpected"
		}
		if _, err := handler.quickTarget(contextValue, operation, body); err == nil {
			t.Fatal("unowned native request", mode)
		}
	}
	if _, err := h.Handle(ctx, "quick-target-release", vaultInput(t, map[string]any{"id": "bad", "sessionId": uuid.NewString(), "epoch": "1"})); err == nil {
		t.Fatal("invalid retirement")
	}
	// Both consumers use the exact same complete RDP allowlist.
	settingsRaw, _ := json.Marshal(vault.DefaultRDPSettings())
	var settings map[string]any
	_ = json.Unmarshal(settingsRaw, &settings)
	for field := range settings {
		value := makePacket()
		target := value["target"].(map[string]any)
		target["protocol"] = "rdp"
		clone := cloneSFTPPacket(settings)
		delete(clone, field)
		target["rdp"] = clone
		if _, err := h.Handle(ctx, "quick-target-register", vaultInput(t, value)); err == nil {
			t.Fatal("missing RDP option", field)
		}
	}
	value := makePacket()
	target := value["target"].(map[string]any)
	target["protocol"] = "rdp"
	target["rdp"] = settings
	if _, err := h.Handle(ctx, "quick-target-register", vaultInput(t, value)); err != nil {
		t.Fatal("complete RDP settings", err)
	}
	target["rdp"] = cloneSFTPPacket(settings)
	target["rdp"].(map[string]any)["gatewayCredentialId"] = "invalid"
	if _, err := h.Handle(ctx, "quick-target-register", vaultInput(t, value)); err == nil {
		t.Fatal("invalid gateway")
	}
}
func TestVaultQuickSSHTrustRequiresFreshStandardAuthentication(t *testing.T) {
	ctx := context.Background()
	doc, key := localSlotFixture(t)
	defer vault.Wipe(key)
	password, err := vault.CreatePasswordSlot(ctx, doc.VaultID, uuid.NewString(), 1, key, []byte("synthetic-password"), nil, vault.KDFV1)
	if err != nil {
		t.Fatal(err)
	}
	doc.Slots = append(doc.Slots, password)
	doc.Initializing = true
	path := filepath.Join(t.TempDir(), "vault.db")
	owner, err := initializeVaultFiles(ctx, path, doc, key)
	if err != nil {
		t.Fatal(err)
	}
	h := &vaultFoundationHandler{databasePath: path, owner: owner}
	t.Cleanup(func() { h.Close() })
	policy, err := owner.ReadLocalPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	policy.Policy.Sequence++
	policy.Policy.Profile = vault.Standard
	if _, err = owner.PutLocalPolicy(ctx, policy.Policy, vault.Default, policy.Policy.Sequence-1); err != nil {
		t.Fatal(err)
	}
	packet := quickTargetPacket()
	raw, err := h.Handle(ctx, "quick-target-register", vaultInput(t, packet))
	if err != nil {
		t.Fatal(err)
	}
	var ref localvault.QuickTargetRef
	_ = json.Unmarshal(raw, &ref)
	q := map[string]any{"nodeId": ref.ID, "credentialOverride": "", "sessionId": ref.SessionID, "requestId": uuid.NewString(), "epoch": "1", "route": nil}
	raw, err = h.Handle(ctx, "ssh-host-plan", vaultInput(t, q))
	if err != nil {
		t.Fatal(err)
	}
	var plan localvault.SSHHostPlan
	_ = json.Unmarshal(raw, &plan)
	q["expected"], q["received"] = plan, sealedSSHFixturePayload().Fingerprint
	if _, err = h.Handle(ctx, "ssh-quick-host-trust", vaultInput(t, q)); err == nil {
		t.Fatal("initial unlock authorized host trust")
	}
	if _, err = h.Handle(ctx, "fresh-action", freshActionInput(t, "ssh-quick-host-trust", vaultInput(t, q), bytes.Repeat([]byte{0x32}, 32))); err != nil {
		t.Fatal("fresh ephemeral trust", err)
	}
}
