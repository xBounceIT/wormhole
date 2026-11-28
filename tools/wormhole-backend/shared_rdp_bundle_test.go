package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"runtime"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func installSharedRDPGatewayFixture(t *testing.T, wire map[string]any, account *sharedpg.UnverifiedAccountKeys) {
	t.Helper()
	metadata := wire["metadata"].(map[string]any)
	workspace := uuid.MustParse(metadata["workspaceId"].(string))
	id := uuid.NewString()
	editSharedConnectionFixture(t, workspace, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, c *sharedcatalog.CredentialRecord) {
		method := 1
		host := "gateway.example"
		n.RDPGatewayUsageMethod = &method
		n.RDPGatewayHostname = &host
		n.RDPGatewayCredentialID = &id
	})
	row := append([]any{}, metadata["credential"].([]any)...)
	var credential sharedcatalog.CredentialRecord
	_ = json.Unmarshal([]byte(row[4].(string)), &credential)
	credential.Metadata.ID, credential.Metadata.Username, credential.Metadata.Domain = id, "gateway-user", "EDGE"
	signing := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{34}, 32))
	defer vault.Wipe(signing)
	seal, err := sharedcatalog.SignCredential(workspace, uuid.MustParse(row[5].(string)), credential, 2, account.State.Signing, signing)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(credential)
	row[1], row[4], row[6], row[11] = id, string(body), "2", hex.EncodeToString(seal.Signature)
	metadata["gateway"] = row
	primary := wire["accounts"].([]any)[0].(map[string]any)
	originalCopy := primary["copies"].([]any)[0].([]any)
	copyRow := append([]any{}, originalCopy...)
	root := vault.KeyRef{ID: uuid.MustParse(copyRow[5].(string)), Version: 1}
	dek := vault.KeyRef{ID: uuid.New(), Version: 1}
	rootPrivate, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{4}, 32))
	secret := bytes.Repeat([]byte{25}, 32)
	binding := vault.KeyCopyBinding{WorkspaceID: workspace, Key: dek, Holder: root, Issuer: account.State.Signing}
	seed := signing.Seed()
	defer vault.Wipe(seed)
	wrapped, err := vault.SealKeyCopy(secret, binding, rootPrivate.PublicKey().Bytes(), seed)
	if err != nil {
		t.Fatal(err)
	}
	copyRow[3], copyRow[4], copyRow[8], copyRow[9], copyRow[12] = dek.ID.String(), "1", hex.EncodeToString(wrapped.Envelope.Enc), hex.EncodeToString(wrapped.Envelope.Ciphertext), hex.EncodeToString(wrapped.Signature)
	value, err := vault.SealSharedValue(secret, vault.SharedValueBinding{WorkspaceID: workspace, OwnerKind: "credential", OwnerID: uuid.MustParse(id), Field: "password", Version: 9, DEK: dek}, []byte("independent-gateway-secret"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := vault.EncodeSharedEnvelope(value)
	wire["accounts"] = append(wire["accounts"].([]any), map[string]any{"account": "gateway", "values": []any{[]any{workspace.String(), id, "1", "9", "password", "9", dek.ID.String(), "1", hex.EncodeToString(raw)}}, "copies": []any{copyRow}})
}
func TestSharedRDPBundlesAuthenticatePrimaryGatewayAndOptions(t *testing.T) {
	for _, mode := range []string{"saved", "empty", "absent", "none", "gateway", "inline", "inline-gateway", "same"} {
		t.Run(mode, func(t *testing.T) {
			c, _, o, _, account, _, node, wire := credentialControllerFixture(t, vault.Default)
			editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, credential *sharedcatalog.CredentialRecord) {
				protocol := 1
				size := "1600x900"
				clip := false
				n.Protocol = &protocol
				n.RDPScreenSize = &size
				n.RDPRedirectClipboard = &clip
				credential.Metadata.Protocol = "rdp"
				credential.Metadata.Domain = "PRIMARY"
				if mode == "none" {
					none := 1
					n.CredentialMode = &none
					n.CredentialID = nil
				}
				if mode == "absent" {
					credential.Fields = []vaultstore.CredentialField{}
				}
			})
			if mode == "same" {
				editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, _ *sharedcatalog.CredentialRecord) {
					same, method, host := true, 1, "gateway.example"
					n.RDPGatewayUseSameCreds = &same
					n.RDPGatewayUsageMethod = &method
					n.RDPGatewayHostname = &host
				})
			}
			if mode == "gateway" || mode == "inline-gateway" {
				installSharedRDPGatewayFixture(t, wire, account)
			}
			if mode == "empty" {
				setSharedVNCPassword(t, wire, []byte{})
			}
			if mode == "none" {
				wire["metadata"].(map[string]any)["credential"] = nil
				wire["accounts"], wire["roots"] = []any{}, []any{}
			}
			if mode == "absent" {
				entry := wire["accounts"].([]any)[0].(map[string]any)
				entry["values"], entry["copies"] = []any{}, []any{}
				wire["roots"] = []any{}
			}
			if mode == "inline" || mode == "inline-gateway" {
				installSharedInlineFixture(t, c, wire, account.State.Signing, "password")
			}
			h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c}}
			t.Cleanup(func() { _ = h.Close() })
			q, key := sharedSSHRequest(node)
			request := sharedPlanPayload(q)
			request["publicKey"] = q.PublicKey
			response, err := h.Handle(context.Background(), "rdp-bundle", vaultInput(t, request))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(response, []byte("native-connection-secret")) || bytes.Contains(response, []byte("independent-gateway-secret")) {
				t.Fatal("plaintext in relay")
			}
			var result localvault.RDPConnectionBundle
			if json.Unmarshal(response, &result) != nil {
				t.Fatal("bundle shape")
			}
			frame, err := vault.OpenBundle(key, result.Binding, result.Bundle)
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(frame)
			payload, err := vault.DecodeRDPBundle(frame)
			if err != nil {
				t.Fatal(err)
			}
			want := "native-connection-secret"
			present := true
			if mode == "empty" || mode == "none" || mode == "absent" {
				want = ""
			}
			if mode == "none" || mode == "absent" {
				present = false
			}
			if mode == "inline" || mode == "inline-gateway" {
				want = "inline-native-secret"
			}
			if string(payload.Password) != want || payload.PasswordProvided != present || payload.Settings.ScreenSize != "1600x900" || payload.Settings.RedirectClipboard || result.Binding.Protocol != "rdp" {
				t.Fatal("RDP primary/settings changed", mode)
			}
			if (mode == "gateway" || mode == "inline-gateway") && (string(payload.GatewayPassword) != "independent-gateway-secret" || payload.GatewayUsername != "gateway-user" || payload.GatewayDomain != "EDGE") {
				t.Fatal("gateway account changed")
			}
		})
	}
}
func TestSharedRDPRoutesAndPolicyCheckedBeforePrivateKeys(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(map[bool]string{false: "routed", true: "strict"}[strict], func(t *testing.T) {
			c, _, h, q, key, wire := sharedRoutedFixture(t, 1)
			if strict {
				row := wire["metadata"].(map[string]any)["chain"].([]any)[0].([]any)
				// Existing fixture uses the same pinned account signing reference.
				signing := vault.KeyRef{ID: uuid.MustParse(row[13].(string)), Version: 1}
				editSharedConnectionFixture(t, c.trustBinding.WorkspaceID, signing, wire, func(n *vaultstore.NodeMetadata, _ *sharedcatalog.CredentialRecord) {
					level := 1
					n.RDPServerAuthentication = &level
				})
			}
			route := sharedRoutedPlan(t, h, q)
			request := localvault.TunnelBundleRequest{NodeID: q.NodeID, SessionID: q.SessionID, RequestID: q.RequestID, Epoch: q.Epoch, PublicKey: q.PublicKey}
			if strict {
				_ = c.privateKeys.Close()
				if _, err := c.SealRoutedRDPConnection(context.Background(), request, route, "127.0.0.1:19050", h.shared.fileID, "ui"); err != vault.ErrPolicy {
					t.Fatal("settings not checked before private keys", err)
				}
				return
			}
			packet := sharedPlanPayload(q)
			packet["publicKey"] = q.PublicKey
			packet["route"] = route
			packet["endpoint"] = "127.0.0.1:19050"
			response, err := h.Handle(context.Background(), "rdp-route-bundle", vaultInput(t, packet))
			var result localvault.RoutedRDPConnectionBundle
			if err != nil || json.Unmarshal(response, &result) != nil {
				t.Fatal(err)
			}
			raw, err := vault.OpenRoutedBundle(key, route, "127.0.0.1:19050", result.Bundle)
			if err != nil {
				t.Fatal(err)
			}
			vault.Wipe(raw)
			if _, err := vault.OpenBundle(key, route.BundleBinding, result.Bundle); err == nil {
				t.Fatal("routed packet became direct")
			}
			if _, err := c.SealRDPConnection(context.Background(), request, "ui"); err != vault.ErrPolicy {
				t.Fatal("selected tunnel bypassed", err)
			}
		})
	}
}
func TestRDPBundleHandlerRejectsMalformedAndUnownedRequests(t *testing.T) {
	if _, err := (&vaultFoundationHandler{}).rdpBundle(context.Background(), "rdp-bundle", nil); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	var absent *sharedpg.VerifiedCredentialRelease
	if _, err := absent.RDPSettings(); err == nil {
		t.Fatal("nil RDP settings")
	}
	c, _, o, _, account, _, node, wire := credentialControllerFixture(t, vault.Default)
	editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, credential *sharedcatalog.CredentialRecord) {
		protocol := 1
		n.Protocol = &protocol
		credential.Metadata.Protocol = "rdp"
	})
	defer c.Close(context.Background())
	q, _ := sharedSSHRequest(node)
	request := localvault.TunnelBundleRequest{NodeID: q.NodeID, SessionID: q.SessionID, RequestID: q.RequestID, Epoch: q.Epoch, PublicKey: q.PublicKey}
	bad := request
	bad.CredentialOverride = uuid.NewString()
	if _, err := c.SealRDPConnection(context.Background(), bad, "ui"); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	if _, err := c.SealRDPConnection(nil, request, "ui"); err == nil {
		t.Fatal("nil context")
	}
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c}}
	for _, value := range []map[string]any{{"unknown": true}, {"nodeId": node.String(), "epoch": "07"}, {"password": "forbidden"}} {
		if _, err := h.rdpBundle(context.Background(), "rdp-bundle", vaultInput(t, value)); err != vaultwire.ErrProtocol {
			t.Fatal(err)
		}
	}
	valid := sharedPlanPayload(q)
	valid["publicKey"] = q.PublicKey
	valid["epoch"] = "07"
	if _, err := h.rdpBundle(context.Background(), "rdp-bundle", vaultInput(t, valid)); err != vaultwire.ErrProtocol {
		t.Fatal("noncanonical epoch accepted", err)
	}
	if _, err := h.rdpBundle(context.Background(), "rdp-route-bundle", vaultInput(t, map[string]any{"nodeId": q.NodeID, "credentialOverride": "", "sessionId": q.SessionID, "requestId": q.RequestID, "epoch": "7", "publicKey": q.PublicKey, "route": map[string]any{}, "endpoint": "127.0.0.1:1080"})); err == nil {
		t.Fatal("malformed route accepted")
	}
	if _, err := h.rdpBundle(context.Background(), "unexpected", nil); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	if _, err := c.SealRoutedRDPConnection(context.Background(), request, vault.TunnelBundleBinding{}, "remote:123", uuid.NewString(), "ui"); !errors.Is(err, vault.ErrFormat) {
		t.Fatal(err)
	}
}

func TestSharedRDPRejectsUnsafePolicyAndBrokenCiphertexts(t *testing.T) {
	for _, mode := range []string{"external", "settings", "provider", "ciphertext"} {
		t.Run(mode, func(t *testing.T) {
			c, _, o, _, account, _, node, wire := credentialControllerFixture(t, vault.Default)
			defer c.Close(context.Background())
			editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, credential *sharedcatalog.CredentialRecord) {
				protocol := 1
				n.Protocol = &protocol
				credential.Metadata.Protocol = "rdp"
				switch mode {
				case "external":
					enabled := true
					n.RDPUseExternalClient = &enabled
				case "settings":
					size := "invalid"
					n.RDPScreenSize = &size
				case "provider":
					credential.Fields = []vaultstore.CredentialField{}
					credential.Metadata.Provider = "bitwarden"
					credential.Metadata.BitwardenItemID = uuid.NewString()
				}
			})
			if mode == "provider" {
				entry := wire["accounts"].([]any)[0].(map[string]any)
				entry["values"], entry["copies"] = []any{}, []any{}
				wire["roots"] = []any{}
			}
			if mode == "settings" || (mode == "external" && runtime.GOOS == "windows") {
				_ = c.privateKeys.Close()
			}
			if mode == "ciphertext" {
				corruptSharedCiphertext(t, wire, "primary")
			}
			ssh, private := sharedSSHRequest(node)
			q := localvault.TunnelBundleRequest{NodeID: ssh.NodeID, SessionID: ssh.SessionID, RequestID: ssh.RequestID, Epoch: ssh.Epoch, PublicKey: ssh.PublicKey}
			result, err := c.SealRDPConnection(context.Background(), q, "ui")
			if mode == "external" && runtime.GOOS != "windows" {
				if err != nil {
					t.Fatal("Windows preference disabled FreeRDP", err)
				}
				raw, err := vault.OpenBundle(private, result.Binding, result.Bundle)
				if err != nil {
					t.Fatal(err)
				}
				defer vault.Wipe(raw)
				payload, err := vault.DecodeRDPBundle(raw)
				if err != nil || payload.Settings.UseExternalClient {
					t.Fatal("external preference was not normalized", err)
				}
				return
			}
			if err == nil || len(result.Bundle.Ciphertext) != 0 {
				t.Fatal("unsafe RDP release succeeded", mode)
			}
			if mode == "settings" && err.Error() != "RDP text settings are invalid" {
				t.Fatal("settings read private keys first", err)
			}
			if mode == "external" && err != vault.ErrPolicy {
				t.Fatal("external client read private keys first", err)
			}
		})
	}
}
