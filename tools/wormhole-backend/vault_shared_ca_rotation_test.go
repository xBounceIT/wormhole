package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type workspaceCARotationProbe struct {
	*credentialReleaseProbe
	t *testing.T
}

func (p workspaceCARotationProbe) PublishWorkspaceCAOverlap(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, []byte, []byte, []byte, time.Time) (*sharedpg.VerifiedTLSBundle, error) {
	p.t.Fatal("unmanaged session attempted to stage a CA")
	return nil, sharedpg.ErrConfiguration
}

func (p workspaceCARotationProbe) PublishWorkspaceCARetirement(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, sharedpg.Settings, []byte, []byte) (*sharedpg.VerifiedTLSBundle, error) {
	p.t.Fatal("unmanaged session attempted to retire a CA")
	return nil, sharedpg.ErrConfiguration
}

func TestVaultWorkspaceCARequiresOwnedVerifiedSession(t *testing.T) {
	ctx := context.Background()
	controller, probe, _, _, _, _, _, _ := credentialControllerFixture(t)
	controller.session = workspaceCARotationProbe{credentialReleaseProbe: probe, t: t}
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: controller}}
	for _, request := range []struct {
		operation string
		valid     []byte
		invalid   []byte
	}{
		{"shared-ca-status", nil, []byte(`{}`)},
		{"shared-ca-rotate", []byte(`{"csr":"public"}`), []byte(`{"csr":"public","workspaceId":"foreign"}`)},
		{"shared-ca-retire", nil, []byte(`{"force":true}`)},
	} {
		raw, err := h.Handle(ctx, request.operation, request.valid)
		var result sharedWorkspaceCAResult
		if err != nil || json.Unmarshal(raw, &result) != nil || result.Status != "unavailable" || result.Reconnect || result.ServerPEM != "" {
			t.Fatal("unmanaged transport or payload leaked rotation state", result, err)
		}
		if _, err := h.Handle(ctx, request.operation, request.invalid); !errors.Is(err, vaultwire.ErrProtocol) || !controller.Unlocked() {
			t.Fatal("unexpected rotation payload affected the owner", err)
		}
		locked := &vaultFoundationHandler{shared: &vaultSharedSession{}}
		if _, err := locked.Handle(ctx, request.operation, request.valid); !errors.Is(err, vaultwire.ErrProtocol) {
			t.Fatal("locked device accessed CA rotation", err)
		}
	}
	controller.session = probe
	if _, err := h.Handle(ctx, "shared-ca-status", nil); !errors.Is(err, vaultwire.ErrRetired) {
		t.Fatal("unsupported native implementation was used", err)
	}
}
