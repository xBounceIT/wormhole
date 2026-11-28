package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestLegacyTunnelRouteUsesCurrentMachineFloor(t *testing.T) {
	policyReadError := errors.New("machine policy unavailable")
	for _, tc := range []struct {
		name       string
		initial    vault.Profile
		current    vault.Profile
		initialErr error
		currentErr error
		want       string
		wantErr    error
	}{
		{name: "Hardened uses configured VPN", initial: vault.Hardened, want: "tunnel"},
		{name: "Paranoid uses configured VPN", initial: vault.Paranoid, want: "tunnel"},
		{name: "unreadable policy", initialErr: policyReadError, wantErr: policyReadError},
		{name: "Standard permits direct", initial: vault.Standard, current: vault.Standard, want: "direct"},
		{name: "policy tightens", initial: vault.Default, current: vault.Hardened, wantErr: vault.ErrPolicy},
		{name: "policy becomes unreadable", initial: vault.Default, currentErr: policyReadError, wantErr: policyReadError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var output bytes.Buffer
			manager := newVncManager(nil, newBackendLineWriter(&output))
			reads := 0
			manager.readRouteFloor = func(context.Context) (vault.Profile, error) {
				reads++
				if reads == 1 {
					return tc.initial, tc.initialErr
				}
				return tc.current, tc.currentErr
			}
			route := manager.routeTunnel("lease", "progress", "Target", "VPN")
			if tc.initialErr != nil || !tc.initial.AllowsDirectRoute() {
				if got, err := route(ctx); got != tc.want || err != tc.wantErr || reads != 1 || output.Len() != 0 {
					t.Fatalf("route = %q, %v, reads = %d, output = %q", got, err, reads, output.String())
				}
				return
			}

			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			deadline, _ := ctx.Deadline()
			if err := client.SetReadDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			manager.output = newBackendLineWriter(server)
			type result struct {
				route string
				err   error
			}
			done := make(chan result, 1)
			go func() {
				got, err := route(ctx)
				done <- result{got, err}
			}()
			wire := json.NewDecoder(client)
			prompt := readTunnelEvent(t, wire, "tunnel.route")
			go manager.handle(backendCommand{ID: "answer", Action: "tunnel.route-response", SessionID: "lease", PromptID: prompt.PromptID, Value: "direct"})
			if response := readTunnelResponse(t, wire, "answer"); !response.OK {
				t.Fatal(response)
			}
			readTunnelEvent(t, wire, "tunnel.route-closed")
			got := <-done
			if got.route != tc.want || got.err != tc.wantErr || reads != 2 {
				t.Fatalf("route = %q, %v, reads = %d", got.route, got.err, reads)
			}
		})
	}
}

func TestSharedDirectRouteDeniesPlanAndCredentialRelease(t *testing.T) {
	for _, profile := range []vault.Profile{vault.Hardened, vault.Paranoid} {
		t.Run(string(profile)+"/plan", func(t *testing.T) {
			c, _, _, _, _, _, node, _ := credentialControllerFixture(t)
			// Exercise the route boundary independently of profile admission.
			c.runtimeProfile = profile
			plan, err := c.PlanConnection(context.Background(), node)
			if !errors.Is(err, vault.ErrPolicy) || plan.Plan.Host != "" || c.Unlocked() {
				t.Fatalf("direct plan = %#v, %v, unlocked = %t", plan, err, c.Unlocked())
			}
		})
		t.Run(string(profile)+"/credentials", func(t *testing.T) {
			c, _, _, _, _, _, node, _ := credentialControllerFixture(t)
			c.runtimeProfile = profile
			err := c.WithConnectionCredentials(context.Background(), node, "ui", func(resolver.Plan, sharedpg.CredentialReleaseValues) error {
				t.Fatal("released credentials for a direct connection")
				return nil
			})
			if !errors.Is(err, vault.ErrPolicy) || c.Unlocked() {
				t.Fatalf("direct release = %v, unlocked = %t", err, c.Unlocked())
			}
		})
		t.Run(string(profile)+"/vpn", func(t *testing.T) {
			c, _, o, _, account, _, node, wire := credentialControllerFixture(t)
			c.runtimeProfile = profile
			enabled, id := true, uuid.NewString()
			editSharedConnectionFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire, func(n *vaultstore.NodeMetadata, _ *sharedcatalog.CredentialRecord) {
				n.TunnelEnabled, n.TunnelConfigID = &enabled, &id
			})
			installSharedTunnelPlanFixture(t, o.Binding.WorkspaceID, account.State.Signing, wire)
			plan, err := c.PlanConnection(context.Background(), node)
			if err != nil || plan.Plan.TunnelID != id || !c.Unlocked() {
				t.Fatalf("VPN plan = %#v, %v, unlocked = %t", plan, err, c.Unlocked())
			}
		})
	}
}
