package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func routedSSHTestBinding() vault.TunnelBundleBinding {
	b := sealedSSHFixtureBinding()
	b.TunnelConfigID = uuid.NewString()
	return vault.TunnelBundleBinding{BundleBinding: b, FileID: uuid.NewString(), Kind: 6, RowVersion: 2, ConfigurationVersion: 1}
}

func TestRoutedSSHProcess(t *testing.T) {
	for _, tamper := range []bool{false, true} {
		t.Run(map[bool]string{false: "route", true: "substitution"}[tamper], func(t *testing.T) {
			b := routedSSHTestBinding()
			entered := make(chan struct{})
			child := startSealedSSHTestChild(t, func(ctx context.Context, target sshTarget, columns, rows uint16) (*sshNativeSession, string, error) {
				if tamper {
					t.Error("substituted endpoint reached dial")
					return nil, "", io.EOF
				}
				if target.socksEndpoint != "127.0.0.1:2345" || target.tunnelConfigID != b.TunnelConfigID || target.host != b.Host || target.password != "sealed-password" || columns != 80 || rows != 24 {
					t.Error("routed target lost authenticated context")
				}
				close(entered)
				<-ctx.Done()
				return nil, "", ctx.Err()
			})
			plain, err := vault.EncodeSSHBundle(sealedSSHFixturePayload())
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(plain)
			sealed, err := vault.SealRoutedBundle(child.public, b, "127.0.0.1:2345", plain)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := "127.0.0.1:2345"
			if tamper {
				endpoint = "127.0.0.1:2346"
			}
			child.send(t, vaultInput(t, map[string]any{"binding": b, "bundle": sealed, "endpoint": endpoint, "columns": 80, "rows": 24}))
			if tamper {
				if child.wait(t) == nil {
					t.Fatal("endpoint substitution accepted")
				}
				return
			}
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("routed dial did not start")
			}
			child.send(t, vaultInput(t, map[string]any{"type": "app-lock", "sessionId": b.SessionID}))
			child.wait(t)
		})
	}
}

func TestRoutedSSHOpeningValidation(t *testing.T) {
	b := routedSSHTestBinding()
	packet := map[string]any{"binding": b, "bundle": vault.SealedBundle{FormatVersion: 1, SuiteID: 2, Enc: make([]byte, 32), Ciphertext: make([]byte, 16)}, "endpoint": "127.0.0.1:2345", "columns": 80, "rows": 24}
	opening, err := decodeSealedSSHOpening(vaultInput(t, packet))
	if err != nil || opening.route == nil || *opening.route != b || opening.endpoint != packet["endpoint"] {
		t.Fatalf("valid route: %v", err)
	}
	for field, values := range map[string][]any{
		"sftpOnly": {nil, false, 1, "true"},
		"endpoint": {nil, "", "localhost:2345", "127.0.0.1:0", "127.0.0.1:65536"},
		"columns":  {0, 501, -1, "80"}, "rows": {0, 501, nil},
		"binding": {nil, map[string]any{}, func() vault.TunnelBundleBinding { x := b; x.Protocol = "rdp"; return x }()},
		"bundle":  {nil, map[string]any{"extra": true}}, "extra": {true},
	} {
		for _, value := range values {
			changed := make(map[string]any)
			for k, v := range packet {
				changed[k] = v
			}
			changed[field] = value
			if _, err := decodeSealedSSHOpening(vaultInput(t, changed)); err == nil {
				t.Errorf("accepted %s=%v", field, value)
			}
		}
	}
	raw := vaultInput(t, packet)
	var value map[string]json.RawMessage
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("fixture")
	}
	for field := range value {
		changed := make(map[string]any)
		for k, v := range value {
			if k != field {
				changed[k] = v
			}
		}
		if _, err := decodeSealedSSHOpening(vaultInput(t, changed)); err == nil {
			t.Errorf("accepted missing %s", field)
		}
	}
}
func TestFileOnlySSHModeIsAuthenticatedBeforeDial(t *testing.T) {
	for _, routed := range []bool{false, true} {
		for _, tamper := range []string{"none", "strip", "inject"} {
			t.Run(fmt.Sprintf("route-%v/%s", routed, tamper), func(t *testing.T) {
				b := routedSSHTestBinding()
				if !routed {
					b.TunnelConfigID = ""
				}
				entered := make(chan struct{})
				child := startSealedSSHTestChild(t, func(ctx context.Context, target sshTarget, _, _ uint16) (*sshNativeSession, string, error) {
					if tamper != "none" {
						t.Error("altered file mode reached dial")
					}
					if !target.sftpOnly || target.autoSudo || target.password != "sealed-password" {
						t.Error("file mode lost")
					}
					close(entered)
					<-ctx.Done()
					return nil, "", ctx.Err()
				})
				payload := sealedSSHFixturePayload()
				payload.SFTPOnly = tamper != "inject"
				plain, err := vault.EncodeSSHBundle(payload)
				if err != nil {
					t.Fatal(err)
				}
				defer vault.Wipe(plain)
				var sealed vault.SealedBundle
				packet := map[string]any{"columns": 80, "rows": 24}
				if routed {
					sealed, err = vault.SealRoutedBundle(child.public, b, "127.0.0.1:4321", plain)
					packet["binding"] = b
					packet["endpoint"] = "127.0.0.1:4321"
				} else {
					sealed, err = vault.SealBundle(child.public, b.BundleBinding, plain)
					packet["binding"] = b.BundleBinding
				}
				if err != nil {
					t.Fatal(err)
				}
				packet["bundle"] = sealed
				if tamper != "strip" {
					packet["sftpOnly"] = true
				}
				child.send(t, vaultInput(t, packet))
				if tamper == "none" {
					select {
					case <-entered:
					case <-time.After(5 * time.Second):
						t.Fatal("file dial did not start")
					}
					child.send(t, vaultInput(t, map[string]any{"type": "app-lock", "sessionId": b.SessionID}))
				}
				err = child.wait(t)
				if tamper != "none" && err == nil {
					t.Fatal("mode substitution accepted")
				}
			})
		}
	}
}
