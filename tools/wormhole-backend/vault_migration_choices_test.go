package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func vaultMigrationChoicesFixture(t *testing.T, h *vaultFoundationHandler) (*vaultFoundationHandler, vaultstore.Node, resolver.MigrationPlan) {
	t.Helper()
	if h == nil {
		h = vaultCredentialFixture(t)
	}
	ctx := context.Background()
	input := vaultConnectionInput("", "0", "ssh")
	input["metadata"].(map[string]any)["inlinePasswordAction"] = "set"
	input["password"] = []byte("private-password")
	n := saveVaultConnectionFixture(t, h, input)
	descriptor, err := describeVaultSlots(h.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	var old, next []resolver.EffectiveCredentialSnapshot
	for _, path := range []string{"ssh", "sftp", "reveal"} {
		a := resolver.EffectiveCredentialSnapshot{NodeID: n.ID, ProtocolPath: path, CredentialID: n.ID, Username: "private-old-identity", SourceKind: "inline"}
		b := a
		b.Username = "private-new-identity"
		b.ResolverVersion = resolver.Version
		old = append(old, a)
		next = append(next, b)
	}
	plan, err := resolver.BuildMigration(descriptor.VaultID, old, next)
	if err != nil {
		t.Fatal(err)
	}
	n, err = h.owner.ImportResolverMigration(ctx, n.ID, plan, 1)
	if err != nil {
		t.Fatal(err)
	}
	return h, n, plan
}

func TestVaultMigrationChoicesReportAndAtomicDecision(t *testing.T) {
	h, n, plan := vaultMigrationChoicesFixture(t, nil)
	ctx := context.Background()
	selection := map[string]any{"nodeId": n.ID, "rowVersion": "2"}
	raw, err := h.Handle(ctx, "migration-report", vaultInput(t, selection))
	if err != nil {
		t.Fatal(err)
	}
	var view struct {
		localvault.ResolverMigrationReport
		CanDecide bool `json:"canDecide"`
	}
	if json.Unmarshal(raw, &view) != nil || len(view.Entries) != 3 || view.Fingerprint == nil || *view.Fingerprint != plan.Fingerprint || !view.CanDecide {
		t.Fatal("invalid report")
	}
	for _, private := range []string{"private-old-identity", "private-new-identity", "private-password", `"legacy"`, `"candidate"`, `"username"`} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("private report field")
		}
	}
	request := map[string]any{"nodeId": n.ID, "rowVersion": "2", "fingerprint": plan.Fingerprint, "choices": []map[string]any{{"protocolPath": "ssh", "choice": "new"}, {"protocolPath": "rdp", "choice": "new"}}}
	if _, err = h.Handle(ctx, "migration-decide", vaultInput(t, request)); err == nil {
		t.Fatal("unknown path accepted")
	}
	unchanged, err := h.owner.ReadNode(ctx, n.ID, 2)
	if err != nil || !reflect.DeepEqual(unchanged, n) {
		t.Fatal("partial write", err)
	}
	request["choices"] = []map[string]any{{"protocolPath": "ssh", "choice": "new"}}
	raw, err = h.Handle(ctx, "migration-decide", vaultInput(t, request))
	if err != nil {
		t.Fatal(err)
	}
	var updated map[string]any
	if json.Unmarshal(raw, &updated) != nil || len(updated) != 3 || updated["rowVersion"] != "3" || updated["nodeId"] != n.ID || updated["updated"] != true {
		t.Fatal("bad acknowledgement")
	}
	if _, err = h.Handle(ctx, "migration-decide", vaultInput(t, request)); err != vaultstore.ErrConflict {
		t.Fatal("stale overwrite", err)
	}
	if _, err = h.Handle(ctx, "migration-report", vaultInput(t, selection)); err != vaultstore.ErrConflict {
		t.Fatal("stale report", err)
	}
	selection["rowVersion"] = "3"
	raw, err = h.Handle(ctx, "migration-report", vaultInput(t, selection))
	if err != nil || json.Unmarshal(raw, &view) != nil {
		t.Fatal(err)
	}
	for _, entry := range view.Entries {
		want := "keep"
		if entry.ProtocolPath == "ssh" {
			want = "new"
		}
		if entry.Choice != want {
			t.Fatal("unrequested path changed")
		}
	}
	request["rowVersion"] = "3"
	request["fingerprint"] = strings.Repeat("a", 64)
	if _, err = h.Handle(ctx, "migration-decide", vaultInput(t, request)); err != resolver.ErrMigrationStale {
		t.Fatal("wrong provenance", err)
	}
	request["fingerprint"] = plan.Fingerprint
	request["choices"] = []map[string]any{{"protocolPath": "ssh", "choice": "keep"}}
	if _, err = h.Handle(ctx, "migration-decide", vaultInput(t, request)); err != nil {
		t.Fatal("keep previous", err)
	}
	empty := saveVaultConnectionFixture(t, h, vaultConnectionInput("", "0", "ssh"))
	raw, err = h.Handle(ctx, "migration-report", vaultInput(t, map[string]any{"nodeId": empty.ID, "rowVersion": "1"}))
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &view) != nil || view.Fingerprint != nil || len(view.Entries) != 0 {
		t.Fatal("nonmigrated report")
	}
	request["nodeId"], request["rowVersion"] = empty.ID, "1"
	if _, err = h.Handle(ctx, "migration-decide", vaultInput(t, request)); err != vaultstore.ErrMissing {
		t.Fatal("created unsolicited pin", err)
	}
}

func TestVaultMigrationChoicesBounds(t *testing.T) {
	h, n, plan := vaultMigrationChoicesFixture(t, nil)
	ctx := context.Background()
	base := map[string]any{"nodeId": n.ID, "rowVersion": "2", "fingerprint": plan.Fingerprint, "choices": []map[string]any{{"protocolPath": "ssh", "choice": "new"}}}
	for field, values := range map[string][]any{
		"nodeId": {nil, "bad", uuid.Nil.String()}, "rowVersion": {nil, 2, "0", "02", "9223372036854775807", "9223372036854775808"}, "fingerprint": {nil, "bad", strings.Repeat("A", 64)},
		"choices": {nil, []any{}, []any{nil}, []any{1}, []any{map[string]any{"protocolPath": "unknown", "choice": "new"}}, []any{map[string]any{"protocolPath": "ssh", "choice": "bad"}}, []any{map[string]any{"protocolPath": "ssh", "choice": "new", "username": "private"}}, []any{map[string]any{"protocolPath": "ssh", "choice": "new"}, map[string]any{"protocolPath": "ssh", "choice": "keep"}}, []any{1, 2, 3, 4}},
	} {
		for _, value := range values {
			request := map[string]any{}
			for k, v := range base {
				request[k] = v
			}
			request[field] = value
			if _, err := h.Handle(ctx, "migration-decide", vaultInput(t, request)); err == nil {
				t.Fatal("accepted malformed", field)
			}
		}
	}
	for _, raw := range []string{"null", "{}", strings.Repeat(" ", 4097), `{"nodeId":"x","nodeId":"x"}`} {
		for _, operation := range []string{"migration-report", "migration-decide"} {
			if _, err := h.Handle(ctx, operation, []byte(raw)); err == nil {
				t.Fatal("accepted malformed")
			}
		}
	}
	if _, err := h.migrationChoices(ctx, "invalid", vaultInput(t, map[string]any{"nodeId": n.ID, "rowVersion": "2"})); err == nil {
		t.Fatal("operation")
	}
	if _, err := (&vaultFoundationHandler{}).migrationChoices(ctx, "migration-report", vaultInput(t, base)); err == nil {
		t.Fatal("locked")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := h.Handle(cancelled, "migration-report", vaultInput(t, base)); err == nil {
		t.Fatal("cancelled")
	}
}

func TestVaultMigrationChoicesNativeFixture(t *testing.T) {
	path := os.Getenv("WORMHOLE_TEST_MIGRATION_DATABASE")
	if path == "" {
		path = filepath.Join(t.TempDir(), "vault.db")
	}
	doc, key := localSlotFixture(t)
	defer vault.Wipe(key)
	doc.Initializing = true
	owner, err := initializeVaultFiles(context.Background(), path, doc, key)
	if err != nil {
		t.Fatal(err)
	}
	h := &vaultFoundationHandler{databasePath: path, owner: owner}
	defer h.Close()
	_, node, _ := vaultMigrationChoicesFixture(t, h)
	report, err := h.Handle(context.Background(), "migration-report", vaultInput(t, map[string]any{"nodeId": node.ID, "rowVersion": "2"}))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path+".migration-report.json", report, 0600); err != nil {
		t.Fatal(err)
	}
}
