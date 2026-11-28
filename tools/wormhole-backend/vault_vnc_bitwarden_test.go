package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestVaultVNCBitwardenHandoff(t *testing.T) {
	for _, mode := range []string{"direct", "routed", "wrong-protocol"} {
		t.Run(mode, func(t *testing.T) {
			h := vaultCredentialFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			credential := vaultstore.CredentialMetadata{
				ID: uuid.NewString(), Name: "Bitwarden VNC", Protocol: "vnc", Provider: "bitwarden",
				Kind: "password", BitwardenItemID: uuid.NewString(), BitwardenFieldPath: "login.password",
			}
			c, err := h.owner.PutCredential(ctx, credential, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			selected, protocol, host, enabled := 2, 6, "vnc.example", true
			node := vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "VNC", Kind: 1, Host: &host,
				Protocol: &protocol, CredentialID: &c.ID, CredentialMode: &selected}
			if mode == "routed" {
				tunnel, err := h.owner.PutTunnel(ctx, vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "VPN", Kind: 6}, []byte(`{"Host":"vpn","Username":"u","Password":"fixture"}`), 0)
				if err != nil {
					t.Fatal(err)
				}
				node.TunnelEnabled, node.TunnelConfigID = &enabled, &tunnel.ID
			}
			if _, err := h.owner.PutNode(ctx, node, nil, 0); err != nil {
				t.Fatal(err)
			}
			target, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			q := map[string]any{"nodeId": node.ID, "credentialOverride": "", "sessionId": uuid.NewString(), "requestId": uuid.NewString(), "epoch": "8"}
			var route vault.TunnelBundleBinding
			const endpoint = "127.0.0.1:23456"
			if mode == "routed" {
				raw, err := h.Handle(ctx, "connection-route", vaultInput(t, q))
				if err != nil || json.Unmarshal(raw, &route) != nil {
					t.Fatal("route unavailable", err)
				}
				q["route"], q["endpoint"] = route, endpoint
			}
			q["publicKey"] = target.PublicKey().Bytes()
			prepare := func() (localvault.BitwardenPreparation, []byte, error) {
				raw, err := h.Handle(ctx, "vnc-bitwarden-prepare", vaultInput(t, q))
				var p localvault.BitwardenPreparation
				if err == nil {
					err = json.Unmarshal(raw, &p)
				}
				return p, raw, err
			}
			probe, _, err := prepare()
			if err != nil || !probe.Required || probe.Revision == "" || probe.Ticket != nil {
				t.Fatal("probe read session state or changed selection", err)
			}
			if mode == "direct" {
				q["endpoint"] = endpoint
				if _, _, err := prepare(); err == nil {
					t.Fatal("unrouted endpoint accepted")
				}
				delete(q, "endpoint")
				q["sftpOnly"] = true
				if _, _, err := prepare(); err == nil {
					t.Fatal("VNC accepted SSH-only fields")
				}
				delete(q, "sftpOnly")
				local, err := h.owner.PutCredential(ctx, vaultstore.CredentialMetadata{
					ID: uuid.NewString(), Name: "Ordinary VNC", Protocol: "vnc", Provider: "local", Kind: "password",
				}, []localvault.SecretChange{{Field: "password", Value: []byte("ordinary-fixture")}}, 0)
				if err != nil {
					t.Fatal(err)
				}
				q["credentialOverride"] = local.ID
				ordinary, _, err := prepare()
				if err != nil || ordinary.Required || ordinary.Ticket != nil {
					t.Fatal("ordinary credential selected the external resolver", err)
				}
				q["credentialOverride"] = ""
			}
			workspace, err := h.owner.WorkspaceID(ctx)
			if err != nil {
				t.Fatal(err)
			}
			session := []byte(`{"path":"fixture","region":0,"key":"sensitive-fixture-session"}`)
			password := []byte("sensitive-fixture-VNC")
			input, sender := io.Pipe()
			receiver, output := io.Pipe()
			defer sender.Close()
			defer receiver.Close()
			worker := "vnc"
			if mode == "wrong-protocol" {
				worker = "ssh"
			}
			done := make(chan error, 1)
			go func() {
				defer output.Close()
				done <- serveVaultConnectionBitwarden(ctx, input, output, worker, func(_ context.Context, payload []byte, id string) (*bitwardenCliLoginItem, error) {
					if worker != "vnc" || id != credential.BitwardenItemID || !bytes.Equal(payload, session) {
						t.Error("credential escaped its worker or selection")
						return nil, vault.ErrAuthentication
					}
					return &bitwardenCliLoginItem{ID: id, Username: "irrelevant", Password: string(password)}, nil
				})
			}()
			reader := bufio.NewReader(receiver)
			line, err := reader.ReadBytes('\n')
			var recipient struct{ PublicKey []byte }
			if err != nil || json.Unmarshal(line, &recipient) != nil {
				t.Fatal("worker recipient unavailable", err)
			}
			q["resolverPublicKey"], q["revision"] = recipient.PublicKey, "stale"
			if _, _, err := prepare(); err == nil {
				t.Fatal("stale release accepted")
			}
			q["revision"] = probe.Revision
			if _, _, err := prepare(); err == nil {
				t.Fatal("session released before enrollment")
			}
			if _, err := h.owner.PutLocalState(ctx, "bitwarden-cli", workspace, session, 0); err != nil {
				t.Fatal(err)
			}
			if mode == "routed" {
				changed := route
				changed.ConfigurationVersion++
				q["route"] = changed
				if _, _, err := prepare(); err == nil {
					t.Fatal("changed tunnel accepted")
				}
				q["route"] = route
			}
			release, raw, err := prepare()
			if err != nil || release.Ticket == nil || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(session))) {
				t.Fatal("unsafe ticket release", err)
			}
			if err := json.NewEncoder(sender).Encode(release.Ticket); err != nil {
				t.Fatal(err)
			}
			line, err = reader.ReadBytes('\n')
			if mode == "wrong-protocol" {
				if err != io.EOF || len(line) != 0 || <-done == nil {
					t.Fatal("SSH worker opened a VNC ticket")
				}
				return
			}
			if err != nil || bytes.Contains(line, password) || bytes.Contains(line, session) {
				t.Fatal("unsafe worker result", err)
			}
			var clear []byte
			if mode == "routed" {
				var targetBundle localvault.RoutedVNCConnectionBundle
				if json.Unmarshal(line, &targetBundle) != nil || targetBundle.Binding != route || targetBundle.Endpoint != endpoint {
					t.Fatal("worker changed the route")
				}
				clear, err = vault.OpenRoutedBundle(target.Bytes(), route, endpoint, targetBundle.Bundle)
			} else {
				var targetBundle localvault.VNCConnectionBundle
				if json.Unmarshal(line, &targetBundle) != nil || targetBundle.Binding != release.Ticket.Binding {
					t.Fatal("worker changed the destination")
				}
				clear, err = vault.OpenBundle(target.Bytes(), targetBundle.Binding, targetBundle.Bundle)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(clear)
			targetPassword, err := vault.DecodeVNCBundle(clear)
			if err != nil || !targetPassword.PasswordProvided || !bytes.Equal(targetPassword.Password, password) {
				t.Fatal("wrong VNC password", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
