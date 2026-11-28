package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestVaultVNCManualNativeBoundary(t *testing.T) {
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	protocol, port, host := 6, 5900, "manual.example"
	node, err := h.owner.PutNode(ctx, vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "Manual VNC", Kind: 1, Protocol: &protocol, Port: &port, Host: &host}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	plan := map[string]any{"nodeId": node.ID, "credentialOverride": "", "sessionId": uuid.NewString(), "requestId": uuid.NewString(), "epoch": "1"}
	raw, err := h.Handle(ctx, "vnc-plan", vaultInput(t, plan))
	if err != nil {
		t.Fatal(err)
	}
	var planned struct {
		Binding vault.BundleBinding `json:"binding"`
	}
	if json.Unmarshal(raw, &planned) != nil {
		t.Fatal("invalid plan")
	}
	inner, err := vault.SealManualVNCPassword(key.PublicKey().Bytes(), planned.Binding, nil, "", []byte("manual-native-password"))
	if err != nil {
		t.Fatal(err)
	}
	request := cloneSFTPPacket(plan)
	request["publicKey"] = key.PublicKey().Bytes()
	request["binding"] = planned.Binding
	request["manual"] = inner
	raw, err = h.Handle(ctx, "vnc-manual-bundle", vaultInput(t, request))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("manual-native-password")) {
		t.Fatal("plaintext response")
	}
	var result localvault.VNCConnectionBundle
	if json.Unmarshal(raw, &result) != nil {
		t.Fatal("invalid bundle")
	}
	outer, err := vault.OpenBundle(key.Bytes(), planned.Binding, result.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(outer)
	envelope, err := vault.DecodeVNCManualAuthorization(outer)
	if err != nil || !bytes.Equal(envelope.Enc, inner.Enc) || !bytes.Equal(envelope.Ciphertext, inner.Ciphertext) {
		t.Fatal("manual ciphertext changed", err)
	}
	for _, operation := range []string{"vnc-plan", "vnc-manual-bundle", "vnc-manual-route-bundle"} {
		for _, field := range []string{"password", "host", "workspaceId", "publicKeyOverride"} {
			bad := cloneSFTPPacket(plan)
			bad[field] = "injected"
			if _, err := h.Handle(ctx, operation, vaultInput(t, bad)); err == nil {
				t.Fatal("injected fields accepted")
			}
		}
	}
	for field := range request {
		bad := cloneSFTPPacket(request)
		delete(bad, field)
		if _, err := h.Handle(ctx, "vnc-manual-bundle", vaultInput(t, bad)); err == nil {
			t.Fatal("missing field accepted", field)
		}
	}
	for _, field := range []string{"binding", "manual"} {
		bad := cloneSFTPPacket(request)
		bad[field] = map[string]any{}
		if _, err := h.Handle(ctx, "vnc-manual-bundle", vaultInput(t, bad)); err == nil {
			t.Fatal("bad inner object", field)
		}
	}
	for _, epoch := range []string{"01", "0", "-1", "bad"} {
		bad := cloneSFTPPacket(plan)
		bad["epoch"] = epoch
		if _, err := h.Handle(ctx, "vnc-plan", vaultInput(t, bad)); err == nil {
			t.Fatal("bad epoch")
		}
	}
	if _, err := h.vncManual(ctx, "unknown", vaultInput(t, plan)); err == nil {
		t.Fatal("unknown operation")
	}
	if _, err := h.vncManual(ctx, "vnc-plan", make([]byte, 32*1024+1)); err == nil {
		t.Fatal("oversized input")
	}
	if _, err := (&vaultFoundationHandler{}).vncManual(ctx, "vnc-plan", nil); err == nil {
		t.Fatal("locked owner")
	}
	tunnel, err := h.owner.PutTunnel(ctx, vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "VPN", Kind: 6}, []byte("native-route"), 0)
	if err != nil {
		t.Fatal(err)
	}
	meta := node.NodeMetadata
	enabled := true
	meta.TunnelEnabled = &enabled
	meta.TunnelConfigID = &tunnel.ID
	if _, err := h.owner.PutNode(ctx, meta, nil, node.RowVersion); err != nil {
		t.Fatal(err)
	}
	q := localvault.TunnelPlanRequest{NodeID: node.ID, SessionID: plan["sessionId"].(string), RequestID: plan["requestId"].(string), Epoch: 1}
	route, err := h.owner.PlanConnectionTunnel(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "127.0.0.1:2345"
	inner, err = vault.SealManualVNCPassword(key.PublicKey().Bytes(), route.BundleBinding, &route, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	routed := cloneSFTPPacket(plan)
	routed["publicKey"], routed["route"], routed["endpoint"], routed["manual"] = key.PublicKey().Bytes(), route, endpoint, inner
	raw, err = h.Handle(ctx, "vnc-manual-route-bundle", vaultInput(t, routed))
	if err != nil {
		t.Fatal(err)
	}
	var resultRoute localvault.RoutedVNCConnectionBundle
	if json.Unmarshal(raw, &resultRoute) != nil || resultRoute.Binding != route || resultRoute.Endpoint != endpoint {
		t.Fatal("route lost")
	}
	routed["route"] = map[string]any{}
	if _, err := h.Handle(ctx, "vnc-manual-route-bundle", vaultInput(t, routed)); err == nil {
		t.Fatal("bad route")
	}
	request["binding"] = planned.Binding
	if _, err := h.Handle(ctx, "vnc-manual-bundle", vaultInput(t, request)); err == nil {
		t.Fatal("routed target bypassed tunnel")
	}
}

func manualVNCProcessPacket(t *testing.T, public []byte, b vault.BundleBinding, route *vault.TunnelBundleBinding, endpoint string, password []byte, mutate func(*vault.SealedBundle)) []byte {
	t.Helper()
	inner, err := vault.SealManualVNCPassword(public, b, route, endpoint, password)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(&inner)
	}
	authorization, err := vault.EncodeVNCManualAuthorization(inner)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(authorization)
	var bundle vault.SealedBundle
	packet := map[string]any{}
	if route == nil {
		bundle, err = vault.SealBundle(public, b, authorization)
		packet["binding"] = b
	} else {
		bundle, err = vault.SealRoutedBundle(public, *route, endpoint, authorization)
		packet["binding"] = *route
		packet["endpoint"] = endpoint
	}
	if err != nil {
		t.Fatal(err)
	}
	packet["bundle"] = bundle
	return vaultInput(t, packet)
}
func TestSealedVNCManualModesAndSubstitution(t *testing.T) {
	for _, mode := range []string{"manual", "route", "saved-rejects-manual", "manual-rejects-saved", "wrong-recipient", "ciphertext"} {
		t.Run(mode, func(t *testing.T) {
			manual := mode != "saved-rejects-manual"
			b := sealedVNCBinding()
			var route *vault.TunnelBundleBinding
			endpoint := ""
			if mode == "route" {
				b.TunnelConfigID = uuid.NewString()
				route = &vault.TunnelBundleBinding{BundleBinding: b, FileID: uuid.NewString(), Kind: 6, RowVersion: 1, ConfigurationVersion: 1}
				endpoint = "127.0.0.1:2345"
			}
			entered := make(chan struct{})
			child := startSealedVNCTestChild(t, func(ctx context.Context, ep, address string) (net.Conn, error) {
				if mode != "manual" && mode != "route" {
					t.Error("invalid manual payload reached dial")
				}
				if ep != endpoint || address != net.JoinHostPort(b.Host, "22") {
					t.Error("target lost")
				}
				close(entered)
				<-ctx.Done()
				return nil, ctx.Err()
			}, manual)
			public := child.public
			if mode == "wrong-recipient" {
				key, _ := ecdh.X25519().GenerateKey(rand.Reader)
				public = key.PublicKey().Bytes()
			}
			var packet []byte
			if mode == "manual-rejects-saved" {
				packet = sealedVNCPacket(t, child.public, b)
			} else if mode == "wrong-recipient" {
				inner, _ := vault.SealManualVNCPassword(public, b, nil, "", nil)
				raw, _ := vault.EncodeVNCManualAuthorization(inner)
				defer vault.Wipe(raw)
				outer, _ := vault.SealBundle(child.public, b, raw)
				packet = vaultInput(t, map[string]any{"binding": b, "bundle": outer})
			} else {
				var mutate func(*vault.SealedBundle)
				if mode == "ciphertext" {
					mutate = func(s *vault.SealedBundle) { s.Ciphertext[0] ^= 1 }
				}
				packet = manualVNCProcessPacket(t, child.public, b, route, endpoint, nil, mutate)
			}
			child.send(t, packet)
			if mode == "manual" || mode == "route" {
				<-entered
				child.send(t, vaultInput(t, map[string]any{"type": "app-lock", "sessionId": b.SessionID}))
				if err := child.wait(t); err != nil {
					t.Fatal(err)
				}
			} else {
				if child.wait(t) == nil {
					t.Fatal("invalid mode accepted")
				}
			}
		})
	}
}
func TestSealedVNCManualRealCLIAuthentication(t *testing.T) {
	for _, password := range []string{"", "one-use-password"} {
		t.Run(map[bool]string{true: "explicit-empty", false: "password"}[password == ""], func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			serverDone := make(chan error, 1)
			go func() {
				serverDone <- serveFakeVncWithFormat(listener, make(chan string, 2), [16]byte{32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0}, password, true)
			}()
			child := startSealedVNCTestChild(t, nil, true)
			b := sealedVNCBinding()
			b.Host = "127.0.0.1"
			b.Port = uint16(listener.Addr().(*net.TCPAddr).Port)
			child.send(t, manualVNCProcessPacket(t, child.public, b, nil, "", []byte(password), nil))
			vncChildEvent(t, child, "connecting")
			vncChildEvent(t, child, "connected")
			vncChildEvent(t, child, "frame")
			child.send(t, vaultInput(t, map[string]any{"type": "pointer", "sessionId": b.SessionID, "x": 0, "y": 0, "buttons": 1}))
			child.send(t, vaultInput(t, map[string]any{"type": "key", "sessionId": b.SessionID, "keysym": 0xff0d, "down": true}))
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
			child.wait(t)
		})
	}
}

func TestSealedVNCManualErrorCLI(t *testing.T) {
	var output, diagnostics bytes.Buffer
	if code := runBackendCLI([]string{"--operation", "vnc-manual-sealed"}, bytes.NewBufferString("invalid\n"), &output, &diagnostics); code != 1 || diagnostics.String() != "sealed_vnc_stopped\n" {
		t.Fatal("manual CLI error leaked", code, diagnostics.String())
	}
	if err := serveSealedVNC(io.NopCloser(bytes.NewReader(nil)), io.Discard, nil); err == nil {
		t.Fatal("empty saved opening")
	}
}
