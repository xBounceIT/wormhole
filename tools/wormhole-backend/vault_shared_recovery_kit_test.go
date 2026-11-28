package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type recoveryKitRefreshProbe struct {
	*credentialReleaseProbe
	t *testing.T
}

func (p recoveryKitRefreshProbe) RefreshWorkspaceRecoveryKit(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, []byte, []byte, []byte) ([]byte, error) {
	p.t.Fatal("borrowed recovery keys from an unmanaged workspace")
	return nil, sharedpg.ErrConfiguration
}

func TestVaultRecoveryKitRefreshRejectsUnmanagedLockedAndInvalidRequests(t *testing.T) {
	ctx := context.Background()
	const operation = "shared-recovery-kit-refresh"
	controller, probe, _, _, _, _, _, _ := credentialControllerFixture(t)
	controller.session = recoveryKitRefreshProbe{credentialReleaseProbe: probe, t: t}
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: controller}}
	directory := t.TempDir()
	source, destination := filepath.Join(directory, "old.whrecovery"), filepath.Join(directory, "new.whrecovery")
	payload, err := json.Marshal(map[string]string{"source": source, "destination": destination})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{
		nil,
		[]byte(`{"source":"old.whrecovery","destination":"new.whrecovery"}`),
		[]byte(`{"source":null,"destination":"new.whrecovery"}`),
		[]byte(`{"source":"old.whrecovery","destination":"new.whrecovery","recoveryCode":"arbitrary"}`),
	} {
		if _, err := h.Handle(ctx, operation, raw); !errors.Is(err, vaultwire.ErrProtocol) {
			t.Fatal("invalid recovery kit paths reached the native owner", err)
		}
	}
	for _, authentication := range []any{nil, true, "", []byte(`{"vaultId":"v","slotId":"s","recoveryCode":"YmFk"}`)} {
		raw, err := json.Marshal(map[string]any{"source": source, "destination": destination, "authentication": authentication})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.Handle(ctx, operation, raw); !errors.Is(err, vaultwire.ErrProtocol) {
			t.Fatal("malformed confirmation reached the active workspace", err)
		}
	}
	locked := &vaultFoundationHandler{shared: &vaultSharedSession{}}
	if _, err := locked.Handle(ctx, operation, payload); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("locked workspace accepted recovery kit refresh", err)
	}
	raw, err := h.Handle(ctx, operation, payload)
	if err != nil || string(raw) != `"unavailable"` || !controller.Unlocked() {
		t.Fatal("unmanaged refresh affected the active workspace", err)
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unmanaged workspace created a new file", err)
	}
	controller.session = probe
	if _, err := h.Handle(ctx, operation, payload); !errors.Is(err, vaultwire.ErrRetired) {
		t.Fatal("workspace without the refresh API was not retired", err)
	}
}
