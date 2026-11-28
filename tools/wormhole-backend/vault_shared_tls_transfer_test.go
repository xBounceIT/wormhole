package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestSharedTLSUpdateKeepsEndpointAndRetriesStartupPublication(t *testing.T) {
	ctx := context.Background()
	f, initial, original, slot := selectedDeviceFixture(t)
	protection := startupTestProtection()
	f.o.Settings.TLS = sharedpg.TLSVerified
	current := original.Trust
	sharedTLSFixture(t, &f.o, current, f.org, 1)
	current, err := acceptSharedTLSBundle(f.o, f.root, current)
	if err != nil {
		t.Fatal(err)
	}
	setup, err := sharedpg.SealTransportSetup(f.root, f.o.Binding, f.o.Settings, current, f.o.OSFloor, f.o.UserFloor, f.o.Request.API)
	if err != nil || persistSharedTransitionBytes(sharedTransportSetupPath(f.o.TrustPath), setup) != nil {
		t.Fatal("could not publish managed transport fixture", err)
	}
	anchor, err := writeSharedStartupAnchor(ctx, f.o, initial, original.DisplayName, original.Revision, protection)
	if err != nil {
		t.Fatal(err)
	}
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	device, err := unlockSharedSelectedDevice(ctx, f.o, slot, []byte("recovery-test-password"), nil, sharedDeviceOrdinary, protection)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	path := filepath.Join(t.TempDir(), "update.WHTLS")
	if err := device.applyTLSUpdate(ctx, path, protection); !errors.Is(err, errSharedTrustMissing) {
		t.Fatal("missing file advanced trust", err)
	}
	if err := device.applyTLSUpdate(ctx, "relative.whtls", protection); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("relative path accepted", err)
	}
	candidate := sharedTLSFixture(t, &f.o, current, f.org, 2)
	signed, err := sharedpg.DecodeTLSTrustBundle(candidate.Encode())
	if err != nil {
		t.Fatal(err)
	}
	redirected := signed
	redirected.Hosts = []string{"other.example.test"}
	redirected, err = sharedpg.SignTLSTrustBundle(redirected, f.org)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sharedpg.EncodeTLSTrustBundle(redirected)
	if err != nil {
		t.Fatal(err)
	}
	write := func(data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(wire)
	if err := device.applyTLSUpdate(ctx, path, protection); !errors.Is(err, sharedpg.ErrConfiguration) {
		t.Fatal("update was allowed to exclude the pinned endpoint", err)
	}
	before, err := readSharedTrustFile(f.o.TrustPath, f.root, f.o.Binding, current.Revision)
	if err != nil || before.TLSSequence != current.TLSSequence {
		t.Fatal("endpoint mismatch changed protected trust", err)
	}
	write(candidate.Encode())
	broken := protection
	broken.protect = func(string, []byte) ([]byte, error) { return nil, os.ErrPermission }
	if err := device.applyTLSUpdate(ctx, path, broken); !errors.Is(err, errSharedTrustStorage) {
		t.Fatal("failed startup publication was acknowledged", err)
	}
	advanced, err := readSharedTrustFile(f.o.TrustPath, f.root, f.o.Binding, current.Revision)
	if err != nil || advanced.TLSSequence != 2 {
		t.Fatal("verified TLS observation was lost after startup publication failed", err)
	}
	if err := device.applyTLSUpdate(ctx, path, protection); err != nil {
		t.Fatal("retry could not publish protected startup state", err)
	}
	after, err := readSharedStartupAnchor(f.o.TrustPath, protection)
	if err != nil || after.Revision != anchor.Revision+1 || after.Trust.Revision != advanced.Revision ||
		!bytes.Equal(after.Trust.TLSDigest, candidate.Pin().Digest) || device.options.MinimumRevision != advanced.Revision {
		t.Fatal("retry did not protect the same authenticated TLS floor", err)
	}
	if err := device.applyTLSUpdate(ctx, path, protection); err != nil {
		t.Fatal("current trust artifact is not idempotent", err)
	}
	equal, err := readSharedStartupAnchor(f.o.TrustPath, protection)
	if err != nil || equal.Revision != after.Revision {
		t.Fatal("an equal update unexpectedly rewrote startup state", err)
	}
}

func TestVaultTLSExportDoesNotPublishFromUnmanagedOrLockedOwner(t *testing.T) {
	ctx := context.Background()
	controller, probe, _, _, _, _, _, _ := credentialControllerFixture(t)
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: controller}}
	path := filepath.Join(t.TempDir(), "export.whtls")
	payload, err := json.Marshal(map[string]string{"path": path})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		nil, []byte(`{"path":"/relative.json"}`), []byte(`{"path":null}`), []byte(`{"path":"relative.whtls"}`),
	} {
		if _, err := h.Handle(ctx, "shared-tls-export", bad); !errors.Is(err, vaultwire.ErrProtocol) {
			t.Fatal("bad export request reached the owner", err)
		}
	}
	locked := &vaultFoundationHandler{shared: &vaultSharedSession{}}
	if _, err := locked.Handle(ctx, "shared-tls-export", payload); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("locked workspace exported an artifact", err)
	}
	if raw, err := h.Handle(ctx, "shared-tls-export", payload); err != nil || string(raw) != `{"exported":false}` {
		t.Fatal("unmanaged export unexpectedly published", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unmanaged export created a file", err)
	}
	controller.session = probe.catalogProbe
	if _, err := h.Handle(ctx, "shared-tls-export", payload); !errors.Is(err, vaultwire.ErrRetired) {
		t.Fatal("unsupported native owner accepted an export", err)
	}
}

func TestVaultTLSUpdatePathIsScopedToOrdinaryAdmission(t *testing.T) {
	h, _, request, probe := vaultSharedFixture(t)
	var payload map[string]any
	if err := json.Unmarshal(request, &payload); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rotation.whtls")
	for _, test := range []struct {
		operation string
		path      string
	}{
		{"shared-unlock", "relative.whtls"},
		{"shared-unlock", filepath.Join(filepath.Dir(path), "rotation.json")},
		{"shared-recover-enrollment", path},
		{"shared-recover-password", path},
	} {
		payload["tlsUpdatePath"] = test.path
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.Handle(context.Background(), test.operation, raw); !errors.Is(err, vaultwire.ErrProtocol) || *probe != nil {
			t.Fatal("the request reached the selected device with an invalid or recovery path", err)
		}
	}
}
