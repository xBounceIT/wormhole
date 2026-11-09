package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func ipsecFixtureCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "client.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"client.test"}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
}

func TestFortinetIPsecNonSAMLAuthentication(t *testing.T) {
	for _, mode := range []int{0, 1, 2} {
		t.Run(string(rune('0'+mode)), func(t *testing.T) {
			settings := ipsecTestSettings()
			settings["UserAuth"] = mode
			settings["IkeVersion"] = 1
			if mode == 2 {
				settings["Username"] = "saved-user"
				settings["Password"] = "saved-password"
			}
			raw, _ := json.Marshal(settings)
			prompts := 0
			ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, p tunnelPrompt) (string, error) {
				if p.Browser {
					t.Fatal("non-SAML profile opened a browser")
				}
				prompts++
				if p.Secret {
					return "prompt-password", nil
				}
				return "prompt-user", nil
			})
			prepared, err := prepareFortinetIPsecAuthentication(ctx, raw)
			if err != nil {
				t.Fatal(err)
			}
			if (mode == 1 && prompts != 2) || (mode != 1 && prompts != 0) {
				t.Fatal("incorrect prompt count", prompts)
			}
			_, payload, err := tunnelSidecarCommand(9, prepared)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(payload, []byte("saml_uid")) {
				t.Fatal("non-SAML payload contains SAML credentials")
			}
			var cfg map[string]any
			json.Unmarshal(payload, &cfg)
			if mode == 2 && cfg["password"] != "saved-password" {
				t.Fatal("saved credentials lost")
			}
			if mode == 1 && cfg["password"] != "prompt-password" {
				t.Fatal("prompt credentials lost")
			}
		})
	}
	for _, answer := range []string{"", "bad\nvalue", strings.Repeat("a", 4097)} {
		settings := ipsecTestSettings()
		settings["UserAuth"] = 1
		raw, _ := json.Marshal(settings)
		ctx := withTunnelPromptHandler(context.Background(), func(context.Context, tunnelPrompt) (string, error) { return answer, nil })
		if _, err := prepareFortinetIPsecAuthentication(ctx, raw); err == nil {
			t.Fatal("invalid prompt answer accepted")
		}
	}
	settings := ipsecTestSettings()
	settings["UserAuth"] = 1
	settings["Username"] = "user"
	raw, _ := json.Marshal(settings)
	for _, handler := range []tunnelPromptHandler{func(context.Context, tunnelPrompt) (string, error) { return "", errors.New("cancelled") }, func(context.Context, tunnelPrompt) (string, error) { return "", nil }} {
		ctx := withTunnelPromptHandler(context.Background(), handler)
		if _, err := prepareFortinetIPsecAuthentication(ctx, raw); err == nil {
			t.Fatal("cancelled password accepted")
		}
	}
}

func TestFortinetIPsecCertificatePersistence(t *testing.T) {
	cert, key := ipsecFixtureCertificate(t)
	settings := map[string]any{"Host": "vpn.test", "AuthMethod": 1, "UserAuth": 0, "IkeVersion": 2, "ClientCert": cert, "ClientKey": key, "CaCert": cert}
	raw, _ := json.Marshal(settings)
	path := filepath.Join(t.TempDir(), "wormhole.db")
	created, err := createTunnel(path, tunnelWriteRequest{Name: "Certificate", Kind: 9, Settings: raw})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(created.Settings, []byte("BEGIN")) || bytes.Contains(created.Settings, []byte(`"ClientKey"`)) {
		t.Fatal("private certificate reached editor")
	}
	if !bytes.Contains(created.Settings, []byte(`"HasClientKey":true`)) {
		t.Fatal("missing key marker")
	}
	if _, err = updateTunnel(path, tunnelWriteRequest{ID: created.ID, Name: "Preserved", Kind: 9, Settings: created.Settings}); err != nil {
		t.Fatal(err)
	}
	stored, err := readTunnelUnlocked(path, tunnelReadRequest{ID: created.ID})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(stored.Settings, []byte("PRIVATE KEY")) {
		t.Fatal("certificate private key lost")
	}
	prepared, err := prepareFortinetIPsecAuthentication(context.Background(), stored.Settings)
	if err != nil {
		t.Fatal(err)
	}
	_, payload, err := tunnelSidecarCommand(9, prepared)
	if err != nil || !bytes.Contains(payload, []byte("PRIVATE KEY")) || bytes.Contains(payload, []byte("pre_shared_key")) {
		t.Fatal("certificate sidecar payload invalid", err)
	}
	settings["ClientKey"] = "invalid"
	bad, _ := json.Marshal(settings)
	var decoded map[string]json.RawMessage
	json.Unmarshal(bad, &decoded)
	if validateFortinetIPsecSettings(decoded) == nil {
		t.Fatal("invalid certificate accepted")
	}
	settings["ClientKey"] = key
	settings["CaCert"] = "invalid"
	bad, _ = json.Marshal(settings)
	json.Unmarshal(bad, &decoded)
	if validateFortinetIPsecSettings(decoded) == nil {
		t.Fatal("invalid CA accepted")
	}
}

func TestFortinetIPsecAdvancedValidation(t *testing.T) {
	valid := ipsecTestSettings()
	valid["UserAuth"] = 0
	valid["IkeVersion"] = 1
	for key, value := range map[string]any{"AuthMethod": 0, "ExchangeMode": 1, "AddressAssignment": 1, "ManualAddress": "10.1.0.2", "ManualDns": "10.1.0.1,2001:db8::1", "RemoteGateways": "backup.test,192.0.2.1", "DhGroups": "1,2,5,14,15,16,17,18,19,20,21", "Phase1Encryption": 3, "Phase1Authentication": 0, "Phase2Encryption": 3, "Phase2Authentication": 1, "Phase1Lifetime": 2800, "Phase2Lifetime": 3600, "Phase2LifetimeKb": 5120, "Pfs": true, "PfsGroup": 2, "ReplayDetection": false, "NatTraversal": true, "EnableLocalLan": false, "DeadPeerDetection": false, "Phase2TimeLifetime": true, "Phase2ByteLifetime": true, "Description": "Legacy profile"} {
		valid[key] = value
	}
	validate := func(value map[string]any) error {
		raw, _ := json.Marshal(value)
		var settings map[string]json.RawMessage
		json.Unmarshal(raw, &settings)
		return validateFortinetIPsecSettings(settings)
	}
	if err := validate(valid); err != nil {
		t.Fatal(err)
	}
	for key, bad := range map[string][]any{"AuthMethod": {-1, 2, nil}, "UserAuth": {-1, 4}, "IkeVersion": {0, 3}, "ExchangeMode": {2}, "AddressAssignment": {3}, "Phase1Encryption": {4}, "Phase2Authentication": {5}, "Phase1Lifetime": {0, "100"}, "Phase2LifetimeKb": {-1}, "PfsGroup": {3, 22}, "DhGroups": {"3", "2,2", "bad"}, "ManualAddress": {"bad", "2001:db8::1"}, "ManualDns": {"bad"}, "RemoteGateways": {"bad/host", "bad host", "a,,b", strings.Repeat("a,", 9) + "b"}, "ReplayDetection": {"true", nil}, "Username": {nil, "bad\nvalue"}, "Description": {strings.Repeat("x", 4097)}, "Unknown": {"bad"}} {
		for _, value := range bad {
			copy := make(map[string]any)
			for k, v := range valid {
				copy[k] = v
			}
			copy[key] = value
			if validate(copy) == nil {
				t.Fatalf("invalid %s accepted", key)
			}
		}
	}
	for _, mutation := range []map[string]any{{"UserAuth": 3, "IkeVersion": 1}, {"AuthMethod": 1, "UserAuth": 3}, {"UserAuth": 2}} {
		copy := ipsecTestSettings()
		for key, value := range mutation {
			copy[key] = value
		}
		if validate(copy) == nil {
			t.Fatal("invalid authentication combination accepted")
		}
	}
}
