package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func tunnelImportRequest(t *testing.T, kind int, format string, contents []byte) (map[string]any, *ecdh.PrivateKey) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "selected.profile")
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	return map[string]any{"editorId": uuid.NewString(), "importId": uuid.NewString(), "tunnelId": "", "rowVersion": "0", "kind": kind, "format": format, "path": path, "publicKey": key.PublicKey().Bytes()}, key
}
func openImportedProjection(t *testing.T, raw []byte, key *ecdh.PrivateKey) map[string]any {
	t.Helper()
	var response vaultTunnelImportDisplay
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	info := []byte("wormhole/v1/tunnel-import")
	for _, value := range []string{response.WorkspaceID, response.EditorID, response.ImportID, strconv.Itoa(response.Kind)} {
		info = binary.BigEndian.AppendUint32(info, uint32(len(value)))
		info = append(info, value...)
	}
	private, _ := hpke.NewDHKEMPrivateKey(key)
	recipient, err := hpke.NewRecipient(response.Bundle.Enc, private, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := recipient.Open(nil, response.Bundle.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(plain)
	var projection map[string]any
	if err = json.Unmarshal(plain, &projection); err != nil {
		t.Fatal(err)
	}
	return projection
}

func TestVaultTunnelImportProfilesRemainNative(t *testing.T) {
	profile := "client\nremote vpn.example 443\n<key>\nunique-import-key\n</key>\n"
	bundle := testWatchguardBundle(t, map[string]string{"client.ovpn": "client\nremote firebox.example 444\nca ca.crt\ncert client.crt\nkey client.pem\n", "ca.crt": "CA", "client.crt": "CERT", "client.pem": "unique-import-key"})
	samples := []struct {
		kind         int
		format       string
		contents     []byte
		patch        string
		privateField string
	}{
		{1, "openvpn", []byte(profile), `{}`, "ProfileOvpn"},
		{4, "openvpn", []byte(profile), `{}`, "ProfileOvpn"},
		{3, "openvpn", []byte(profile), `{"Server":"firebox.example","Username":"alice","Password":"password"}`, "ProfileOvpn"},
		{3, "watchguard", bundle, `{"Username":"alice","Password":"password"}`, "ProfileOvpn"},
		{5, "azure", []byte(azureVPNClientExportFixture()), `{}`, "ServerSecretHex"},
		{6, "cisco", []byte(`<AnyConnectProfile><ServerList><HostEntry><HostName>Corporate</HostName><HostAddress>vpn.example:444</HostAddress><UserGroup>staff</UserGroup></HostEntry></ServerList></AnyConnectProfile>`), `{"Username":"alice","Password":"password"}`, ""},
	}
	for _, sample := range samples {
		t.Run(sample.format+strconv.Itoa(sample.kind), func(t *testing.T) {
			h := vaultCredentialFixture(t)
			ctx := context.Background()
			request, key := tunnelImportRequest(t, sample.kind, sample.format, sample.contents)
			before, err := os.ReadDir(filepath.Dir(h.databasePath))
			if err != nil {
				t.Fatal(err)
			}
			raw, err := h.Handle(ctx, "tunnel-import-stage", vaultInput(t, request))
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"unique-import-key", strings.Repeat("ab", 256), "firebox.example", "Corporate", "primary.vpn.azure.com"} {
				if bytes.Contains(raw, []byte(secret)) {
					t.Fatal("import response exposed contents")
				}
			}
			after, err := os.ReadDir(filepath.Dir(h.databasePath))
			if err != nil {
				t.Fatal(err)
			}
			if len(before) != len(after) {
				t.Fatal("preview created auxiliary files")
			}
			for i := range before {
				if before[i].Name() != after[i].Name() {
					t.Fatal("preview changed vault directory")
				}
			}
			projection := openImportedProjection(t, raw, key)
			settings := projection["settings"].(map[string]any)
			if sample.privateField != "" {
				if _, ok := settings[sample.privateField]; ok {
					t.Fatal("private field displayed")
				}
				found := false
				for _, field := range projection["present"].([]any) {
					found = found || field == sample.privateField
				}
				if !found {
					t.Fatal("presence absent")
				}
			}
			rows, err := h.owner.ListTunnels(ctx, "", 100)
			if err != nil || len(rows) != 0 {
				t.Fatal("preview persisted tunnel", err)
			}
			// The save must use the captured snapshot even if the selected file changes.
			if err = os.WriteFile(request["path"].(string), []byte("changed after preview"), 0600); err != nil {
				t.Fatal(err)
			}
			input := tunnelEditorInput(sample.kind, sample.patch)
			input["editorId"], input["importId"] = request["editorId"], request["importId"]
			saved := saveTunnelEditor(t, h, input)
			actual := vaultTestTunnelEditorSettings(t, h, saved.ID)
			if sample.privateField != "" && actual[sample.privateField] == nil {
				t.Fatal("imported factor absent")
			}
			if sample.format == "openvpn" && actual["ProfileOvpn"] != profile {
				t.Fatal("file reread or profile altered")
			}
			if sample.format == "azure" && actual["ServerSecretHex"] != strings.Repeat("ab", 256) {
				t.Fatal("Azure key escaped native import")
			}
			if sample.format == "watchguard" && actual["AuthMode"] != float64(1) {
				t.Fatal("manual profile mode lost")
			}
			if _, err = h.owner.ReadTunnelImport(ctx, request["editorId"].(string), request["importId"].(string), localvault.TunnelImportTarget{Kind: sample.kind}); err != vaultstore.ErrMissing {
				t.Fatal("committed stage replayable", err)
			}
		})
	}
}

func TestVaultTunnelImportFailureRetryReplacementAndDiscard(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	request, _ := tunnelImportRequest(t, 1, "openvpn", []byte("original imported profile"))
	if _, err := h.Handle(ctx, "tunnel-import-stage", vaultInput(t, request)); err != nil {
		t.Fatal(err)
	}
	input := tunnelEditorInput(1, `{"ProfileOvpn":null}`)
	input["editorId"], input["importId"] = request["editorId"], request["importId"]
	if _, err := h.Handle(ctx, "tunnel-edit", vaultInput(t, input)); err != vaultwire.ErrProtocol {
		t.Fatal("removed required profile saved", err)
	}
	input["patch"] = []byte(`{"Username":"alice"}`)
	wrong := freshActionInput(t, "tunnel-edit", vaultInput(t, input), bytes.Repeat([]byte{8}, 32))
	if _, err := h.Handle(ctx, "fresh-action", wrong); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal(err)
	}
	// Failed preview must preserve the pending stage.
	old := request["importId"].(string)
	request["importId"] = uuid.NewString()
	request["publicKey"] = []byte{1}
	if _, err := h.Handle(ctx, "tunnel-import-stage", vaultInput(t, request)); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	saved := saveTunnelEditor(t, h, input)
	if vaultTestTunnelEditorSettings(t, h, saved.ID)["ProfileOvpn"] != "original imported profile" {
		t.Fatal("failed preview replaced stage")
	}
	// Discard is editor-bound and idempotent.
	request, key := tunnelImportRequest(t, 1, "openvpn", []byte("next profile"))
	request["importId"] = old
	if _, err := h.Handle(ctx, "tunnel-import-stage", vaultInput(t, request)); err != nil {
		t.Fatal(err)
	}
	discard := map[string]any{"editorId": uuid.NewString(), "importId": old}
	if _, err := h.Handle(ctx, "tunnel-import-discard", vaultInput(t, discard)); err != nil {
		t.Fatal(err)
	}
	target := localvault.TunnelImportTarget{Kind: 1}
	plain, err := h.owner.ReadTunnelImport(ctx, request["editorId"].(string), old, target)
	vault.Wipe(plain)
	if err != nil {
		t.Fatal("foreign discard", err)
	}
	request["importId"] = uuid.NewString()
	request["publicKey"] = key.PublicKey().Bytes()
	if _, err = h.Handle(ctx, "tunnel-import-stage", vaultInput(t, request)); err != nil {
		t.Fatal(err)
	}
	if _, err = h.owner.ReadTunnelImport(ctx, request["editorId"].(string), old, target); err != vaultstore.ErrMissing {
		t.Fatal("replacement retained old stage", err)
	}
	discard["editorId"] = request["editorId"]
	discard["importId"] = ""
	for i := 0; i < 2; i++ {
		raw, err := h.Handle(ctx, "tunnel-import-discard", vaultInput(t, discard))
		if err != nil || string(raw) != `{"discarded":true}` {
			t.Fatal(err)
		}
	}
	if _, err = h.owner.ReadTunnelImport(ctx, request["editorId"].(string), request["importId"].(string), target); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
}

func TestVaultTunnelImportMergeUsesExplicitModesAndRevision(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	input := tunnelEditorInput(3, `{"Server":"old.example","AuthMode":2}`)
	saved := saveTunnelEditor(t, h, input)
	if _, err := h.owner.PutTunnel(ctx, saved.TunnelMetadata, []byte(`{"Server":"old.example","UseSingleSignOn":true}`), 1); err != nil {
		t.Fatal(err)
	}
	request, _ := tunnelImportRequest(t, 3, "openvpn", []byte("client profile"))
	request["tunnelId"], request["rowVersion"] = saved.ID, "2"
	if _, err := h.Handle(ctx, "tunnel-import-stage", vaultInput(t, request)); err != nil {
		t.Fatal(err)
	}
	input["rowVersion"] = "2"
	input["editorId"], input["importId"] = request["editorId"], request["importId"]
	input["patch"] = []byte(`{"Username":"alice","Password":"replacement"}`)
	saved = saveTunnelEditor(t, h, input)
	settings := vaultTestTunnelEditorSettings(t, h, saved.ID)
	if settings["AuthMode"] != float64(1) || settings["Username"] != "alice" || settings["ProfileOvpn"] != "client profile" || settings["Server"] != "old.example" {
		t.Fatal("import merge or explicit mode lost")
	}
	request["importId"] = uuid.NewString()
	if _, err := h.Handle(ctx, "tunnel-import-stage", vaultInput(t, request)); err != vaultstore.ErrConflict {
		t.Fatal("stale preview accepted", err)
	}
	request["rowVersion"] = strconv.FormatUint(saved.RowVersion, 10)
	if _, err := h.Handle(ctx, "tunnel-import-stage", vaultInput(t, request)); err != nil {
		t.Fatal(err)
	}
	input["importId"] = request["importId"]
	input["editorId"] = uuid.NewString()
	input["patch"] = []byte(`{}`)
	if _, err := h.Handle(ctx, "tunnel-edit", vaultInput(t, input)); err != vaultstore.ErrConflict || h.closed {
		t.Fatal("cross editor import", err)
	}
	input["editorId"] = request["editorId"]
	input["patch"] = []byte(`{"ProfileOvpn":"explicit replacement","AuthMode":2}`)
	saveTunnelEditor(t, h, input)
	settings = vaultTestTunnelEditorSettings(t, h, saved.ID)
	if settings["ProfileOvpn"] != "explicit replacement" || settings["Password"] != nil {
		t.Fatal("explicit patch did not override import")
	}
}

func TestVaultTunnelImportInputAndFileBounds(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	request, _ := tunnelImportRequest(t, 1, "openvpn", []byte("profile"))
	for _, raw := range [][]byte{nil, []byte(`{}`), bytes.Repeat([]byte{'x'}, 16*1024+1), []byte(`{"editorId":"bad","editorId":"duplicate"}`)} {
		if _, err := h.Handle(ctx, "tunnel-import-stage", raw); err != vaultwire.ErrProtocol {
			t.Fatal(err)
		}
	}
	for field, values := range map[string][]any{"editorId": {"bad", ""}, "importId": {"bad"}, "tunnelId": {"bad", uuid.NewString()}, "rowVersion": {"1", "-1", "9223372036854775807"}, "publicKey": {[]byte{1}, "bad!", true}, "kind": {9, 0}, "format": {"unknown"}, "path": {"relative", "", strings.Repeat("p", 8193), request["path"].(string) + string(rune(0)), t.TempDir(), filepath.Join(t.TempDir(), "absent")}} {
		for _, value := range values {
			copy := map[string]any{}
			for key, item := range request {
				copy[key] = item
			}
			copy[field] = value
			if _, err := h.Handle(ctx, "tunnel-import-stage", vaultInput(t, copy)); err == nil {
				t.Fatalf("accepted %s", field)
			}
		}
	}
	for _, format := range []string{"openvpn", "watchguard", "azure", "cisco"} {
		if _, _, err := readVaultTunnelImport(request["path"].(string), format, 8); err != vaultwire.ErrProtocol {
			t.Fatal(err)
		}
	}
	for _, sample := range []struct {
		kind     int
		format   string
		contents []byte
	}{
		{1, "openvpn", nil}, {1, "openvpn", []byte(" \t\r\n")}, {1, "openvpn", []byte{0xff}}, {1, "openvpn", []byte{'a', 0, 'b'}}, {1, "openvpn", bytes.Repeat([]byte{'x'}, maxImportedProfileBytes+1)},
		{3, "watchguard", []byte("bad archive")}, {5, "azure", []byte("bad XML")}, {6, "cisco", []byte("bad XML")},
		{5, "azure", []byte(strings.Replace(azureVPNClientExportFixture(), "<name>Example_Profile</name>", "<name>"+strings.Repeat("x", 129)+"</name>", 1))},
		{6, "cisco", []byte(`<AnyConnectProfile><ServerList><HostEntry><HostAddress>vpn.example</HostAddress><HostName>` + strings.Repeat("x", 129) + `</HostName></HostEntry></ServerList></AnyConnectProfile>`)},
	} {
		q, _ := tunnelImportRequest(t, sample.kind, sample.format, sample.contents)
		if _, err := h.Handle(ctx, "tunnel-import-stage", vaultInput(t, q)); err == nil {
			t.Fatal("malformed file accepted", sample.format)
		}
	}
	// JSON expansion can exceed the native record cap even when source bytes fit.
	expanded, _ := tunnelImportRequest(t, 1, "openvpn", bytes.Repeat([]byte{'\n'}, maxImportedProfileBytes/2+1))
	if _, err := h.Handle(ctx, "tunnel-import-stage", vaultInput(t, expanded)); err != vaultwire.ErrProtocol {
		t.Fatal("expanded profile accepted", err)
	}
	// Public projection has its own smaller limit.
	oversized, _ := tunnelImportRequest(t, 6, "cisco", []byte(`<AnyConnectProfile><ServerList><HostEntry><HostAddress>vpn.example</HostAddress><UserGroup>`+strings.Repeat("g", 512*1024)+`</UserGroup></HostEntry></ServerList></AnyConnectProfile>`))
	if _, err := h.Handle(ctx, "tunnel-import-stage", vaultInput(t, oversized)); err != vaultwire.ErrProtocol {
		t.Fatal("oversized preview accepted", err)
	}
	if _, err := (&vaultFoundationHandler{}).Handle(ctx, "tunnel-import-stage", vaultInput(t, request)); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{nil, []byte(`{}`), bytes.Repeat([]byte{'x'}, 513), vaultInput(t, map[string]any{"editorId": "bad", "importId": ""}), vaultInput(t, map[string]any{"editorId": uuid.NewString(), "importId": "bad"})} {
		if _, err := h.Handle(ctx, "tunnel-import-discard", raw); err != vaultwire.ErrProtocol {
			t.Fatal(err)
		}
	}
	if _, err := (&vaultFoundationHandler{}).Handle(ctx, "tunnel-import-discard", vaultInput(t, map[string]any{"editorId": uuid.NewString(), "importId": ""})); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	// Nonzero low-order public key cannot establish a usable recipient or stage.
	request["publicKey"] = make([]byte, 32)
	if _, err := h.Handle(ctx, "tunnel-import-stage", vaultInput(t, request)); err == nil {
		t.Fatal("invalid recipient accepted")
	}
	if h.closed {
		t.Fatal("input errors retired owner")
	}
	if err := h.owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.stageTunnelImport(ctx, vaultInput(t, request)); !errors.Is(err, vaultwire.ErrRetired) {
		t.Fatal("closed owner accepted", err)
	}
}

func TestVaultTunnelImportCannotInstallHostPins(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	editor, id := uuid.NewString(), uuid.NewString()
	target := localvault.TunnelImportTarget{Kind: 8}
	if err := h.owner.StageTunnelImport(ctx, editor, id, target, []byte(`{"HostKeySha256":"injected"}`)); err != nil {
		t.Fatal(err)
	}
	input := tunnelEditorInput(8, `{"Mode":"manual","Host":"jump","Port":22,"Username":"alice"}`)
	input["editorId"], input["importId"] = editor, id
	if _, err := h.Handle(ctx, "tunnel-edit", vaultInput(t, input)); err != vaultwire.ErrProtocol {
		t.Fatal("import established trust", err)
	}
	for _, change := range []map[string]any{{"editorId": "bad", "importId": id}, {"editorId": editor, "importId": ""}, {"editorId": "", "importId": id}} {
		for key, value := range change {
			input[key] = value
		}
		if _, err := h.Handle(ctx, "tunnel-edit", vaultInput(t, input)); err != vaultwire.ErrProtocol {
			t.Fatal(err)
		}
	}
}
