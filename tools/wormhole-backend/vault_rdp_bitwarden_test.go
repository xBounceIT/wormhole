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

func TestVaultRDPBitwardenHandoff(t *testing.T) {
	for _, mode := range []string{"primary", "gateway", "both", "same-item", "reused", "routed", "missing-item", "manual-gateway", "manual-reused"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			h := vaultCredentialFixture(t)
			workspace, err := h.owner.WorkspaceID(ctx)
			if err != nil {
				t.Fatal(err)
			}
			manual := mode == "manual-gateway" || mode == "manual-reused"
			primaryExternal := mode != "gateway"
			gatewayExternal := mode == "gateway" || mode == "both" || mode == "same-item" || mode == "missing-item" || manual
			primaryItem, gatewayItem := uuid.NewString(), uuid.NewString()
			if mode == "same-item" {
				gatewayItem = primaryItem
			}
			const primaryLocal, gatewayLocal = "fixture-primary-local", "fixture-gateway-local"
			makeCredential := func(username, domain, item, password string, external bool) vaultstore.Credential {
				t.Helper()
				c := vaultstore.CredentialMetadata{ID: uuid.NewString(), Name: domain, Protocol: "rdp", Provider: "local", Kind: "password", Username: username, Domain: domain}
				input := []localvault.SecretChange{{Field: "password", Value: []byte(password)}}
				if external {
					c.Provider, c.BitwardenItemID, c.BitwardenFieldPath = "bitwarden", item, "login.password"
					input = nil
				}
				v, err := h.owner.PutCredential(ctx, c, input, 0)
				if err != nil {
					t.Fatal(err)
				}
				return v
			}
			gatewayUser := "configured-edge"
			if mode == "gateway" || mode == "manual-gateway" {
				gatewayUser = ""
			}
			primary := makeCredential("configured-main", "PRIMARY", primaryItem, primaryLocal, primaryExternal)
			gateway := makeCredential(gatewayUser, "EDGE", gatewayItem, gatewayLocal, gatewayExternal)
			routed, reused := mode == "routed", mode == "reused" || mode == "manual-reused"
			protocol, credentialMode, method, enabled, server := 1, 2, 1, true, "rdp.example"
			gatewayHost := "gateway.example"
			node := vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "RDP", Kind: 1, Protocol: &protocol, Host: &server, CredentialMode: &credentialMode, CredentialID: &primary.ID}
			if !routed {
				node.RDPGatewayUsageMethod, node.RDPGatewayHostname = &method, &gatewayHost
				node.RDPGatewayCredentialID, node.RDPGatewayUseSameCreds = &gateway.ID, &reused
			} else {
				tunnel, err := h.owner.PutTunnel(ctx, vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "VPN", Kind: 6}, []byte(`{"Host":"vpn","Username":"u","Password":"fixture"}`), 0)
				if err != nil {
					t.Fatal(err)
				}
				node.TunnelEnabled, node.TunnelConfigID = &enabled, &tunnel.ID
			}
			if _, err := h.owner.PutNode(ctx, node, nil, 0); err != nil {
				t.Fatal(err)
			}
			rdpKey, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			q := map[string]any{"nodeId": node.ID, "credentialOverride": "", "sessionId": uuid.NewString(), "requestId": uuid.NewString(), "epoch": "1"}
			endpoint := ""
			var route *vault.TunnelBundleBinding
			if routed {
				b, err := h.Handle(ctx, "connection-route", vaultInput(t, q))
				route = new(vault.TunnelBundleBinding)
				if err != nil || json.Unmarshal(b, route) != nil {
					t.Fatal("route unavailable", err)
				}
				endpoint = "127.0.0.1:23456"
				q["route"], q["endpoint"] = route, endpoint
			}
			q["publicKey"] = rdpKey.PublicKey().Bytes()
			operation := "rdp-bitwarden-prepare"
			const temporaryPassword = "fixture-temporary-primary"
			var submitted vault.SealedBundle
			var expected vault.BundleBinding
			sealDocument := func(password string) vault.SealedBundle {
				t.Helper()
				inner, err := vault.SealManualRDPCredentials(rdpKey.PublicKey().Bytes(), expected, nil, "", vault.RDPManualCredentials{
					Username: "temporary-user", Domain: "TEMP", Password: []byte(password),
				})
				if err != nil {
					t.Fatal(err)
				}
				return inner
			}
			if manual {
				plan := cloneSFTPPacket(q)
				delete(plan, "publicKey")
				raw, err := h.Handle(ctx, "rdp-plan", vaultInput(t, plan))
				var target struct{ Binding vault.BundleBinding }
				if err != nil || json.Unmarshal(raw, &target) != nil {
					t.Fatal("temporary RDP plan unavailable", err)
				}
				expected = target.Binding
				submitted = sealDocument(temporaryPassword)
				q["binding"], q["manual"] = expected, submitted
				operation = "rdp-manual-bitwarden-prepare"
			}
			prepare := func() (localvault.BitwardenPreparation, []byte, error) {
				raw, err := h.Handle(ctx, operation, vaultInput(t, q))
				var p localvault.BitwardenPreparation
				if err == nil {
					err = json.Unmarshal(raw, &p)
				}
				return p, raw, err
			}
			probe, _, err := prepare()
			if mode == "manual-reused" {
				if err != nil || probe.Required || probe.Ticket != nil || probe.RDPBase != nil {
					t.Fatal("manual primary should continue to supply the reused gateway", err)
				}
				if raw, err := h.Handle(ctx, "rdp-manual-bundle", vaultInput(t, q)); err != nil || len(raw) == 0 {
					t.Fatal("ordinary manual authorization unavailable", err)
				}
				return
			}
			if err != nil || !probe.Required || probe.Ticket != nil || probe.RDPBase != nil {
				t.Fatal("probe read or denied a credential", err)
			}
			if manual {
				malformed := submitted
				malformed.Ciphertext = make([]byte, 16)
				for name, fields := range map[string]map[string]any{
					"short document": {"manual": malformed},
					"override":       {"credentialOverride": primary.ID},
					"route":          {"route": expected, "endpoint": "127.0.0.1:12345"},
					"short key":      {"resolverPublicKey": []byte{1}, "revision": probe.Revision},
				} {
					invalid := cloneSFTPPacket(q)
					for key, value := range fields {
						invalid[key] = value
					}
					if _, err := h.Handle(ctx, operation, vaultInput(t, invalid)); err == nil {
						t.Errorf("manual RDP accepted %s", name)
					}
				}
				shared := vaultFoundationHandler{shared: &vaultSharedSession{}}
				if _, err := shared.rdpManual(ctx, operation, vaultInput(t, q)); err == nil {
					t.Fatal("shared owner accepted local Bitwarden preparation")
				}
			}
			session := []byte(`{"key":"fixture-session","region":0,"path":"fixture"}`)
			input, sender := io.Pipe()
			receiver, output := io.Pipe()
			defer sender.Close()
			defer receiver.Close()
			done := make(chan error, 1)
			var ids []string
			const bwPrimary, bwGateway = "fixture-primary-Bitwarden", "fixture-gateway-Bitwarden"
			go func() {
				defer output.Close()
				done <- serveVaultConnectionBitwarden(ctx, input, output, "rdp", func(_ context.Context, stored []byte, id string) (*bitwardenCliLoginItem, error) {
					if !bytes.Equal(stored, session) {
						t.Error("wrong encrypted session")
						return nil, vault.ErrAuthentication
					}
					ids = append(ids, id)
					if id == primaryItem {
						if manual {
							t.Error("saved primary credentials reached the manual resolver")
							return nil, vault.ErrAuthentication
						}
						return &bitwardenCliLoginItem{ID: id, Username: "live-main", Password: bwPrimary}, nil
					}
					if id == gatewayItem && mode != "missing-item" {
						return &bitwardenCliLoginItem{ID: id, Username: "live-edge", Password: bwGateway}, nil
					}
					return nil, vault.ErrAuthentication
				})
			}()
			reader := bufio.NewReader(receiver)
			line, err := reader.ReadBytes('\n')
			var recipient struct{ PublicKey []byte }
			if err != nil || json.Unmarshal(line, &recipient) != nil {
				t.Fatal("worker recipient unavailable", err)
			}
			q["resolverPublicKey"], q["revision"] = recipient.PublicKey, probe.Revision
			if _, _, err := prepare(); err == nil {
				t.Fatal("missing CLI session accepted")
			}
			if _, err := h.owner.PutLocalState(ctx, "bitwarden-cli", workspace, session, 0); err != nil {
				t.Fatal(err)
			}
			if manual {
				q["manual"] = sealDocument("replaced-after-probe")
				if _, _, err := prepare(); err == nil {
					t.Fatal("replacement document envelope accepted")
				}
				q["manual"] = submitted
				wrongBinding := expected
				wrongBinding.Host = "foreign.example"
				q["binding"] = wrongBinding
				if _, _, err := prepare(); err == nil {
					t.Fatal("replacement RDP binding accepted")
				}
				q["binding"] = expected
			}
			if mode == "both" {
				gateway.Username = "replacement-edge"
				if _, err := h.owner.PutCredential(ctx, gateway.CredentialMetadata, nil, gateway.RowVersion); err != nil {
					t.Fatal(err)
				}
				if _, _, err := prepare(); err == nil {
					t.Fatal("gateway changed without invalidating the release")
				}
				delete(q, "resolverPublicKey")
				delete(q, "revision")
				current, _, err := prepare()
				if err != nil || !current.Required || current.Revision == probe.Revision {
					t.Fatal("missing revised gateway receipt", err)
				}
				q["resolverPublicKey"], q["revision"] = recipient.PublicKey, current.Revision
				gatewayUser = gateway.Username
			}
			resolved, raw, err := prepare()
			if err != nil || resolved.Ticket == nil || resolved.RDPBase == nil {
				t.Fatal("could not prepare both ciphertexts", err)
			}
			for _, secret := range [][]byte{session, []byte(primaryLocal), []byte(gatewayLocal), []byte(temporaryPassword)} {
				if bytes.Contains(raw, secret) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(secret))) {
					t.Fatal("unsealed native data")
				}
			}
			if err := json.NewEncoder(sender).Encode(resolved.Ticket); err != nil {
				t.Fatal(err)
			}
			line, err = reader.ReadBytes('\n')
			if mode == "missing-item" {
				if err != io.EOF || len(line) != 0 || <-done == nil {
					t.Fatal("partial lookup produced an account handoff")
				}
				return
			}
			var patch vault.SealedBundle
			if err != nil || json.Unmarshal(line, &patch) != nil || bytes.Contains(line, []byte(bwPrimary)) || bytes.Contains(line, []byte(bwGateway)) {
				t.Fatal("unsafe worker handoff", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			b := resolved.Ticket.Binding
			var frame []byte
			if route == nil {
				frame, err = vault.OpenBundle(rdpKey.Bytes(), b, *resolved.RDPBase)
			} else {
				frame, err = vault.OpenRoutedBundle(rdpKey.Bytes(), *route, endpoint, *resolved.RDPBase)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(frame)
			if _, err := vault.DecodeRDPBundle(frame); err == nil {
				t.Fatal("a Bitwarden base authorized RDP without its paired accounts")
			}
			if manual {
				if _, _, err := vault.OpenRDPBitwardenAccounts(rdpKey.Bytes(), b, route, endpoint, frame, patch); err == nil {
					t.Fatal("saved RDP accepted temporary authorization")
				}
				base, inner, accounts, err := vault.OpenManualRDPBitwardenAccounts(rdpKey.Bytes(), b, frame, patch)
				defer vault.Wipe(accounts)
				if err != nil || !base.GatewayPasswordProvided || string(base.GatewayPassword) != bwGateway ||
					base.PasswordProvided || base.Username != "" || base.Settings.Domain != "" || len(ids) != 1 || ids[0] != gatewayItem ||
					rdpProfileFromBundle(b, base).GatewayUsername != "EDGE\\live-edge" {
					t.Fatal("manual account and Bitwarden gateway were mixed", err)
				}
				p, err := vault.OpenManualRDPCredentials(rdpKey.Bytes(), b, nil, "", inner)
				defer vault.Wipe(p)
				if err != nil {
					t.Fatal(err)
				}
				credentials, err := vault.DecodeRDPManualCredentials(p)
				if err != nil || credentials.Username != "temporary-user" || credentials.Domain != "TEMP" || string(credentials.Password) != temporaryPassword {
					t.Fatal("temporary credential changed", err)
				}
				return
			}
			all, borrowed, err := vault.OpenRDPBitwardenAccounts(rdpKey.Bytes(), b, route, endpoint, frame, patch)
			defer vault.Wipe(borrowed)
			if err != nil {
				t.Fatal(err)
			}
			wantMain, wantGateway, wantCalls := primaryLocal, gatewayLocal, 1
			if primaryExternal {
				wantMain = bwPrimary
			}
			if gatewayExternal {
				wantGateway = bwGateway
				if primaryExternal && mode != "same-item" {
					wantCalls++
				}
			}
			if mode == "same-item" {
				wantGateway = bwPrimary
			}
			if reused || routed {
				wantGateway = ""
			}
			if string(all.Password) != wantMain || string(all.GatewayPassword) != wantGateway || len(ids) != wantCalls ||
				all.Username != "configured-main" || all.Settings.Domain != "PRIMARY" {
				t.Fatal("mixed identities or account selection changed")
			}
			if mode == "gateway" {
				gatewayUser = "live-edge"
			}
			if wantGateway != "" && rdpProfileFromBundle(b, all).GatewayUsername != "EDGE\\"+gatewayUser {
				t.Fatal("independent gateway domain or username changed")
			}
		})
	}
}
