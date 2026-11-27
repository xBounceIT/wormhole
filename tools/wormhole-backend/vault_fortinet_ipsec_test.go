package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVaultIPsecEditorSecretsModesAndFallback(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	input := tunnelEditorInput(9, `{"Host":"vpn.test","PreSharedKey":"vault-psk-fixture","UserAuth":2,"Username":"alice","Password":"vault-login-fixture","AutoProposals":true,"Phase2Lifetime":3600}`)
	saved := saveTunnelEditor(t, h, input)
	config := vaultTestTunnelEditorSettings(t, h, saved.ID)
	encoded, _ := json.Marshal(config)
	projected, err := projectVaultTunnelEditor(saved, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(projected, []byte("vault-psk-fixture")) || bytes.Contains(projected, []byte("vault-login-fixture")) || !bytes.Contains(projected, []byte(`"PreSharedKey"`)) {
		t.Fatal("secret projection")
	}
	input["patch"] = []byte(`{"UserAuth":0}`)
	saveTunnelEditor(t, h, input)
	config = vaultTestTunnelEditorSettings(t, h, saved.ID)
	if _, ok := config["Password"]; ok {
		t.Fatal("inactive login retained")
	}
	if _, ok := config["Username"]; ok {
		t.Fatal("inactive account retained")
	}
	cert, key := ipsecFixtureCertificate(t)
	patch, _ := json.Marshal(map[string]any{"AuthMethod": 1, "ClientCert": cert, "ClientKey": key, "CaCert": cert})
	input["patch"] = patch
	saved = saveTunnelEditor(t, h, input)
	config = vaultTestTunnelEditorSettings(t, h, saved.ID)
	if _, ok := config["PreSharedKey"]; ok {
		t.Fatal("incompatible PSK retained")
	}
	encoded, _ = json.Marshal(config)
	exe, payload, err := sealedTunnelSidecarConfig(9, encoded)
	if err != nil || exe != "wormhole-fortiipsecproxy" || !bytes.Contains(payload, []byte("client_key")) {
		t.Fatal("certificate native handoff", err)
	}
	vault.Wipe(payload)
	input["patch"] = []byte(`{"AuthMethod":0,"PreSharedKey":"replacement-fixture"}`)
	saved = saveTunnelEditor(t, h, input)
	config = vaultTestTunnelEditorSettings(t, h, saved.ID)
	if _, ok := config["ClientKey"]; ok {
		t.Fatal("incompatible certificate retained")
	}
	sslInput := tunnelEditorInput(2, `{"Host":"ssl.test","Username":"u","Password":"p"}`)
	sslInput["metadata"].(map[string]any)["name"] = "SSL fallback"
	ssl := saveTunnelEditor(t, h, sslInput)
	for _, id := range []string{uuid.NewString(), saved.ID} {
		input["patch"] = []byte(`{"FallbackTunnelId":"` + id + `"}`)
		if _, err := h.Handle(ctx, "tunnel-edit", vaultInput(t, input)); err == nil {
			t.Fatal("unsafe fallback accepted")
		}
	}
	wrongInput := tunnelEditorInput(1, `{"ProfileOvpn":"profile"}`)
	wrongInput["metadata"].(map[string]any)["name"] = "Other provider"
	wrong := saveTunnelEditor(t, h, wrongInput)
	input["patch"] = []byte(`{"FallbackTunnelId":"` + wrong.ID + `"}`)
	if _, err := h.Handle(ctx, "tunnel-edit", vaultInput(t, input)); err == nil {
		t.Fatal("wrong fallback provider")
	}
	input["patch"] = []byte(`{"FallbackTunnelId":"` + ssl.ID + `"}`)
	saved = saveTunnelEditor(t, h, input)
	if err := h.owner.DeleteTunnel(ctx, ssl.ID, ssl.RowVersion); err != nil {
		t.Fatal(err)
	}
	input["patch"] = []byte(`{"Description":"changed"}`)
	if _, err := h.Handle(ctx, "tunnel-edit", vaultInput(t, input)); err == nil {
		t.Fatal("deleted fallback accepted")
	}
	input["patch"] = []byte(`{"FallbackTunnelId":null}`)
	saveTunnelEditor(t, h, input)
	for _, raw := range []string{`{"HasPreSharedKey":true}`, `{"ReplaceClientKey":true}`, `{"SamlToken":"cached"}`, `{"AuthMethod":"0"}`, `{"Pfs":1}`, `{"IkeVersion":2.5}`, `{"PreSharedKey":false}`} {
		input["patch"] = []byte(raw)
		if _, err := h.Handle(ctx, "tunnel-edit", vaultInput(t, input)); err == nil {
			t.Fatal("invalid patch accepted", raw)
		}
	}
}

func TestVaultIPsecRawSaveCannotBypassFallbackValidation(t *testing.T) {
	h := vaultCredentialFixture(t)
	input := map[string]any{"metadata": map[string]any{"id": uuid.NewString(), "name": "raw IPsec", "kind": 9}, "rowVersion": "0", "configuration": []byte(`{"Host":"vpn.test","UserAuth":0,"PreSharedKey":"private-fixture","FallbackTunnelId":"` + uuid.NewString() + `"}`)}
	if _, err := h.Handle(context.Background(), "tunnel-save", vaultInput(t, input)); err == nil {
		t.Fatal("raw save bypassed authenticated fallback")
	}
	input["configuration"] = []byte(`{"Host":"vpn.test","UserAuth":0,"PreSharedKey":"private-fixture"}`)
	if _, err := h.Handle(context.Background(), "tunnel-save", vaultInput(t, input)); err != nil {
		t.Fatal(err)
	}
}

func TestVaultIPsecPEMImportBoundaries(t *testing.T) {
	cert, key := ipsecFixtureCertificate(t)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecRaw, _ := x509.MarshalECPrivateKey(ec)
	for _, raw := range [][]byte{[]byte(key), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecRaw})} {
		if err := readVaultIPsecPEM(raw, "ClientKey"); err != nil {
			t.Fatal(err)
		}
	}
	for _, field := range []string{"ClientCert", "CaCert"} {
		if err := readVaultIPsecPEM([]byte(cert+cert), field); err != nil {
			t.Fatal(err)
		}
	}
	for _, sample := range []struct{ raw, field string }{{"", "ClientKey"}, {strings.Repeat("x", 131073), "ClientKey"}, {"garbage" + cert, "ClientCert"}, {cert + "garbage", "ClientCert"}, {cert, "ClientKey"}, {key, "ClientCert"}, {key + key, "ClientKey"}, {cert, "unknown"}, {"-----BEGIN PRIVATE KEY-----\nAAA=\n-----END PRIVATE KEY-----", "ClientKey"}, {"-----BEGIN CERTIFICATE-----\nAAA=\n-----END CERTIFICATE-----", "CaCert"}, {"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAA=\n-----END ENCRYPTED PRIVATE KEY-----", "ClientKey"}, {"-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\nAAA=\n-----END CERTIFICATE-----", "ClientCert"}, {"-----BEGIN CERTIFICATE-----", "ClientCert"}} {
		if readVaultIPsecPEM([]byte(sample.raw), sample.field) == nil {
			t.Fatal("invalid PEM accepted", sample.field)
		}
	}
	root := t.TempDir()
	for format, field := range map[string]string{"ipsec-cert": "ClientCert", "ipsec-key": "ClientKey", "ipsec-ca": "CaCert"} {
		raw := cert
		if field == "ClientKey" {
			raw = key
		}
		path := filepath.Join(root, format+".pem")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		_, settings, err := readVaultTunnelImport(path, format, 9)
		if err != nil || tunnelSettingString(settings, field) != raw {
			t.Fatal("import", err)
		}
		clearTunnelSettingsMap(settings)
		if _, _, err := readVaultTunnelImport(path, format, 2); err == nil {
			t.Fatal("foreign format accepted")
		}
		if err := os.WriteFile(path, []byte("invalid"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readVaultTunnelImport(path, format, 9); err == nil {
			t.Fatal("invalid file accepted")
		}
	}
}

func TestVaultIPsecSealedProviderGate(t *testing.T) {
	for _, raw := range []string{`{"Host":"vpn.test","PreSharedKey":"private-fixture","UserAuth":0}`, `{"Host":"vpn.test","PreSharedKey":"private-fixture","UserAuth":2,"Username":"user","Password":"password-fixture"}`} {
		exe, config, err := sealedTunnelSidecarConfig(9, []byte(raw))
		if err != nil || exe != "wormhole-fortiipsecproxy" || !bytes.Contains(config, []byte("private-fixture")) {
			t.Fatal(err)
		}
		vault.Wipe(config)
	}
	for _, raw := range []string{`{"Host":"vpn.test","PreSharedKey":"key"}`, `{"UserAuth":1}`, `{"UserAuth":3}`, `{"UserAuth":0,"FallbackTunnelId":"` + uuid.NewString() + `"}`} {
		if _, _, err := sealedTunnelSidecarConfig(9, []byte(raw)); err != vault.ErrPolicy {
			t.Fatal("interactive/fallback gate", err)
		}
	}
	if _, _, err := sealedTunnelSidecarConfig(9, []byte(`{"UserAuth":0}`)); err != vault.ErrFormat {
		t.Fatal("invalid native config", err)
	}
	if _, _, err := sealedTunnelSidecarConfig(9, []byte(`{"UserAuth":0,"Host":"vpn.test","PreSharedKey":"k","SamlToken":"legacy"}`)); err == nil {
		t.Fatal("legacy token persisted")
	}
	if validateVaultTunnelConfiguration([]byte(`{"Host":"vpn.test","PreSharedKey":"k","UserAuth":0}`), 9) != nil {
		t.Fatal("migration config refused")
	}
	if readVaultIPsecPEM([]byte("bad"), "ClientKey") != vaultwire.ErrProtocol {
		t.Fatal("wrong import error")
	}
}

func TestVaultIPsecSequentialImportsAreAtomicAndNative(t *testing.T) {
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	cert, key := ipsecFixtureCertificate(t)
	editor := uuid.NewString()
	recipient, _ := ecdh.X25519().GenerateKey(rand.Reader)
	dir := t.TempDir()
	var last string
	for _, format := range []string{"ipsec-cert", "ipsec-key", "ipsec-ca"} {
		raw := cert
		if format == "ipsec-key" {
			raw = key
		}
		path := filepath.Join(dir, format+".pem")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		id := uuid.NewString()
		request := map[string]any{"editorId": editor, "importId": id, "tunnelId": "", "rowVersion": "0", "kind": 9, "format": format, "path": path, "publicKey": recipient.PublicKey().Bytes()}
		response, err := h.Handle(ctx, "tunnel-import-stage", vaultInput(t, request))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(response, []byte(key)) || bytes.Contains(response, []byte(cert)) {
			t.Fatal("PEM leaked through projection")
		}
		last = id
	}
	target := localvault.TunnelImportTarget{Kind: 9}
	data, err := h.owner.ReadTunnelImport(ctx, editor, last, target)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := decodeVaultTunnelSettings(data)
	vault.Wipe(data)
	if err != nil {
		t.Fatal(err)
	}
	defer clearTunnelSettingsMap(settings)
	if tunnelSettingString(settings, "ClientCert") != cert || tunnelSettingString(settings, "ClientKey") != key || tunnelSettingString(settings, "CaCert") != cert {
		t.Fatal("sequential import lost a previous PEM")
	}
	if _, err := h.owner.CurrentTunnelImport(ctx, editor, localvault.TunnelImportTarget{Kind: 1}); err == nil {
		t.Fatal("provider switch reused old secret stage")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := h.owner.CurrentTunnelImport(cancelled, uuid.NewString(), target); err != context.Canceled {
		t.Fatal("canceled import read", err)
	}
	absent, err := h.owner.CurrentTunnelImport(ctx, uuid.NewString(), target)
	if err != nil || absent != nil {
		t.Fatal("foreign editor material returned")
	}
	if _, err := h.owner.CurrentTunnelImport(ctx, "bad", target); err == nil {
		t.Fatal("invalid editor")
	}
	path := filepath.Join(dir, "invalid.pem")
	if err := os.WriteFile(path, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"editorId": editor, "importId": uuid.NewString(), "tunnelId": "", "rowVersion": "0", "kind": 9, "format": "ipsec-key", "path": path, "publicKey": recipient.PublicKey().Bytes()}
	if _, err := h.Handle(ctx, "tunnel-import-stage", vaultInput(t, request)); err == nil {
		t.Fatal("invalid replacement accepted")
	}
	data, err = h.owner.ReadTunnelImport(ctx, editor, last, target)
	vault.Wipe(data)
	if err != nil {
		t.Fatal("failed replacement retired previous stage")
	}
	input := tunnelEditorInput(9, `{"Host":"vpn.test","UserAuth":0}`)
	input["editorId"] = editor
	input["importId"] = last
	saved := saveTunnelEditor(t, h, input)
	if saved.Kind != 9 {
		t.Fatal("wrong provider")
	}
	if _, err := h.owner.ReadTunnelImport(ctx, editor, last, target); err == nil {
		t.Fatal("committed stage retained")
	}
}
