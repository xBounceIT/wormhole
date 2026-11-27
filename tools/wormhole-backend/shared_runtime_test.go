package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestSharedRuntimeSnapshotPublicationAndPolicySource(t *testing.T) {
	for _, mode := range []string{"workspace", "user", "sticky-os", "sticky-os-and-user"} {
		t.Run(mode, func(t *testing.T) {
			c, p, o, root, account, org, _, wire := credentialControllerFixture(t, vault.Default)
			c.runtimeProfile, c.runtimeOSFloor = vault.Default, vault.Default
			initial := c.trustRevision
			state := *account.State
			state.Sequence++
			state, e := vault.SignUserKeyState(state, org)
			if e != nil {
				t.Fatal(e)
			}
			raw, e := vault.EncodeUserKeyState(state)
			if e != nil {
				t.Fatal(e)
			}
			wire["account"] = []any{strconv.FormatUint(state.Sequence, 10), hex.EncodeToString(raw)}
			if mode == "user" || mode == "sticky-os-and-user" {
				c.runtimeProfile = vault.Standard
				c.runtimeUserFloor = vault.Standard
			}
			if mode == "sticky-os" || mode == "sticky-os-and-user" {
				c.runtimeProfile = vault.Standard
				c.runtimeOSFloor = vault.Standard
			}
			p.begin = func(context.Context, uuid.UUID, string) (*sharedpg.UseIntent, error) {
				t.Fatal("runtime state issued ticket")
				return nil, nil
			}
			p.fetch = func(context.Context, sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
				t.Fatal("runtime state fetched ciphertext")
				return nil, nil
			}
			if e := c.privateKeys.With(func(b []byte) error { vault.Wipe(b); return nil }); e != nil {
				t.Fatal(e)
			}
			result, e := c.RuntimeSnapshot(context.Background())
			if e != nil || result.WorkspaceID != o.Binding.WorkspaceID {
				t.Fatal(result, e)
			}
			wantEffective, wantSource := vault.Default, "workspace"
			if mode != "workspace" {
				wantEffective = vault.Standard
				wantSource = map[string]string{"user": "user", "sticky-os": "os", "sticky-os-and-user": "user"}[mode]
			}
			if result.Security.Sequence == 0 || result.Security.Workspace != vault.Default || result.Security.Effective != wantEffective || result.Security.Source != wantSource {
				t.Fatal(result)
			}
			if result.Security.RetainedUntilLock != (mode == "sticky-os") || result.Security.OS != vault.Default {
				t.Fatal("current machine policy and retained session floor", result)
			}
			stored, e := readSharedTrustFile(o.TrustPath, root, o.Binding, initial+1)
			if e != nil || stored.Revision != c.trustRevision || stored.Account.Sequence != state.Sequence {
				t.Fatal("policy escaped durable state", e)
			}
			again, e := c.RuntimeSnapshot(context.Background())
			if e != nil || again != result || c.trustRevision != initial+1 {
				t.Fatal("unstable runtime snapshot", e)
			}
		})
	}
}

func TestSharedRuntimeSnapshotErrorsRetire(t *testing.T) {
	for _, mode := range []string{"query", "nil", "revoked", "rotated", "policy", "forged", "anchor", "storage", "cancel", "stronger-floor", "unknown-user-floor", "closed"} {
		t.Run(mode, func(t *testing.T) {
			c, p, o, root, account, org, _, wire := credentialControllerFixture(t)
			initial := c.trustRevision
			failure := errors.New("runtime fixture failure")
			ctx := context.Background()
			switch mode {
			case "query":
				p.runtime = func(context.Context) (*sharedpg.UnverifiedRuntimeState, error) { return nil, failure }
			case "nil":
				p.runtime = func(context.Context) (*sharedpg.UnverifiedRuntimeState, error) { return nil, nil }
			case "revoked", "rotated":
				state := *account.State
				state.Sequence++
				if mode == "revoked" {
					state.Active = false
				} else {
					state.Encryption.ID = uuid.New()
				}
				state, e := vault.SignUserKeyState(state, org)
				if e != nil {
					t.Fatal(e)
				}
				raw, e := vault.EncodeUserKeyState(state)
				if e != nil {
					t.Fatal(e)
				}
				wire["account"] = []any{strconv.FormatUint(state.Sequence, 10), hex.EncodeToString(raw)}
			case "policy", "forged":
				raw, _ := hex.DecodeString(wire["profile"].(string))
				policy, e := vault.DecodeSignedPolicy(raw)
				if e != nil {
					t.Fatal(e)
				}
				if mode == "policy" {
					policy.Policy.Sequence++
					policy.Policy.Profile = vault.Standard
					policy, e = vault.SignPolicy(policy.Policy, policy.SignerKeyID, policy.SignerKeyVersion, org)
					if e != nil {
						t.Fatal(e)
					}
				} else {
					policy.Signature[0] ^= 1
				}
				raw, e = vault.EncodeSignedPolicy(policy)
				if e != nil {
					t.Fatal(e)
				}
				wire["profile"] = hex.EncodeToString(raw)
			case "anchor":
				c.catalogAnchor = func(context.Context, string, []byte, sharedpg.TrustBinding, sharedpg.TrustState) error {
					return failure
				}
			case "storage":
				if e := os.WriteFile(o.TrustPath, []byte("damaged protected trust"), 0600); e != nil {
					t.Fatal(e)
				}
			case "cancel":
				old := p.runtime
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				p.runtime = func(ctx context.Context) (*sharedpg.UnverifiedRuntimeState, error) {
					r, e := old(ctx)
					cancel()
					return r, e
				}
			case "stronger-floor":
				c.runtimeProfile = vault.Default
				c.runtimeOSFloor = vault.Standard
			case "unknown-user-floor":
				c.runtimeUserFloor = ""
			case "closed":
				if e := c.Close(ctx); e != nil {
					t.Fatal(e)
				}
			}
			result, e := c.RuntimeSnapshot(ctx)
			if e == nil || !reflect.DeepEqual(result, sharedRuntimeSnapshot{}) || c.Unlocked() || c.privateKeys != nil {
				t.Fatal("failed runtime retained policy/keys", e)
			}
			if mode == "policy" || mode == "revoked" || mode == "rotated" {
				stored, e := readSharedTrustFile(o.TrustPath, root, o.Binding, initial+1)
				if e != nil {
					t.Fatal("lost observations", e)
				}
				if mode == "policy" && stored.PolicySequence < 2 {
					t.Fatal("higher floor lost")
				}
				if mode == "revoked" && stored.Account.Active {
					t.Fatal("revocation lost")
				}
				if mode == "rotated" && stored.Account.Encryption == account.State.Encryption {
					t.Fatal("rotation lost")
				}
			}
		})
	}
	c, p, _, _, _, _, _, _ := credentialControllerFixture(t)
	if _, e := c.RuntimeSnapshot(nil); e != sharedpg.ErrConfiguration {
		t.Fatal(e)
	}
	c.session = p.catalogProbe
	if _, e := c.RuntimeSnapshot(context.Background()); e != sharedpg.ErrConfiguration {
		t.Fatal(e)
	}
}

func TestSharedRuntimeCloseCancelsRead(t *testing.T) {
	c, p, _, _, _, _, _, _ := credentialControllerFixture(t)
	entered, done := make(chan struct{}), make(chan error, 1)
	p.runtime = func(ctx context.Context) (*sharedpg.UnverifiedRuntimeState, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	go func() { _, e := c.RuntimeSnapshot(context.Background()); done <- e }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("runtime read did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e := c.Close(ctx); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		if e != context.Canceled {
			t.Fatal(e)
		}
	case <-ctx.Done():
		t.Fatal("runtime read retained gate")
	}
}

func TestVaultSharedRuntimeSeparatesSlotAndWorkspaceIdentities(t *testing.T) {
	c, _, o, _, _, _, _, _ := credentialControllerFixture(t)
	slotVault := uuid.NewString()
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c, vaultID: slotVault, fileID: uuid.NewString()}}
	raw, e := h.Handle(context.Background(), "shared-runtime", nil)
	var result vaultSharedRuntime
	if e != nil || json.Unmarshal(raw, &result) != nil || result.VaultID != slotVault || result.WorkspaceID != o.Binding.WorkspaceID.String() || result.VaultID == result.WorkspaceID || result.TLS != c.runtimeTLS {
		t.Fatal("runtime identity", result, e)
	}
	for _, forbidden := range []string{"rootKey", "privateKey", "signature", "capability", "signedProfile", "nonce"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatal("private state in runtime projection", forbidden)
		}
	}
	security, e := h.Handle(context.Background(), "security", nil)
	var projection vaultSecurityProjection
	if e != nil || json.Unmarshal(security, &projection) != nil || projection != result.Security {
		t.Fatal("shared security", e)
	}
	for _, op := range []string{"shared-runtime", "security"} {
		if _, e := h.Handle(context.Background(), op, []byte(`{}`)); e != vaultwire.ErrProtocol {
			t.Fatal(e)
		}
	}
	h.shared.vaultID = "invalid"
	if _, e := h.Handle(context.Background(), "shared-runtime", nil); e != vaultwire.ErrProtocol {
		t.Fatal(e)
	}
	h.shared = nil
	if _, e := h.Handle(context.Background(), "shared-runtime", nil); e != vaultwire.ErrProtocol {
		t.Fatal(e)
	}
}

func TestVaultSharedProfileRejectsInvalidProtectedRequests(t *testing.T) {
	const op = "shared-tighten-profile"
	h := &vaultFoundationHandler{shared: &vaultSharedSession{}}
	if !h.ExitOnCancel(op) {
		t.Fatal("cancelling a pending change must retire the service")
	}
	for _, input := range [][]byte{nil, []byte(`{"sequence":"1"}`), []byte(`{"sequence":"1","authentication":{}}`), bytes.Repeat([]byte{'x'}, 16385)} {
		if _, err := h.Handle(context.Background(), op, input); err != vaultwire.ErrProtocol {
			t.Fatal("invalid protected request", err)
		}
		if !bytes.Equal(input, make([]byte, len(input))) {
			t.Fatal("invalid protected request retained input")
		}
	}
}

func TestVaultSharedUpdatePreferences(t *testing.T) {
	ctx := context.Background()
	controller, _, _, _, _, _, _, _ := credentialControllerFixture(t)
	h := &vaultFoundationHandler{databasePath: filepath.Join(t.TempDir(), "device.db"),
		shared: &vaultSharedSession{controller: controller, vaultID: uuid.NewString(), fileID: uuid.NewString()}}
	if raw, err := h.Handle(ctx, "update-preferences", []byte(`{"autoCheckForUpdates":false,"lastUpdateCheck":"2026-11-25T23:00:00Z"}`)); err != nil || string(raw) != "true" {
		t.Fatal(string(raw), err)
	}
	raw, err := h.Handle(ctx, "preferences", nil)
	var got appSettingsSnapshot
	if err != nil || json.Unmarshal(raw, &got) != nil || got.AutoCheckForUpdates || got.LastUpdateCheck == nil ||
		*got.LastUpdateCheck != "2026-11-25T23:00:00Z" {
		t.Fatal(string(raw), err)
	}
	h.shared.controller = nil
	if _, err := h.Handle(ctx, "preferences", nil); err != vaultwire.ErrProtocol {
		t.Fatalf("shared preferences after retirement: %v", err)
	}
	if _, err := h.Handle(ctx, "update-preferences", []byte(`{"autoCheckForUpdates":true}`)); err != vaultwire.ErrProtocol {
		t.Fatalf("shared preference write after retirement: %v", err)
	}
	if _, err := os.Stat(h.databasePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preferences opened a workspace database: %v", err)
	}
}

func TestSharedRuntimePublishesAdmittedTransportAndRejectsUnknownModes(t *testing.T) {
	for _, mode := range []sharedpg.TLSMode{sharedpg.TLSOff, sharedpg.TLSEncrypted, sharedpg.TLSVerified, "", "prefer", "VERIFIED"} {
		t.Run(string(mode), func(t *testing.T) {
			c, _, _, _, _, _, _, _ := credentialControllerFixture(t, vault.Default)
			// Native transport opening is separately proved by real TLS enrollment;
			// this projection must neither infer nor default an unknown mode.
			c.runtimeTLS = mode
			h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c, vaultID: uuid.NewString(), fileID: uuid.NewString()}}
			raw, err := h.Handle(context.Background(), "shared-runtime", nil)
			if mode != sharedpg.TLSOff && mode != sharedpg.TLSEncrypted && mode != sharedpg.TLSVerified {
				if err == nil || len(raw) != 0 || !h.closed || c.Unlocked() {
					t.Fatal("unknown transport remained active", err)
				}
				return
			}
			var result vaultSharedRuntime
			if err != nil || json.Unmarshal(raw, &result) != nil || result.TLS != mode {
				t.Fatal("transport projection", result, err)
			}
		})
	}
}

func TestVaultSharedRuntimeFailureRetiresService(t *testing.T) {
	for _, operation := range []string{"shared-runtime", "security"} {
		t.Run(operation, func(t *testing.T) {
			c, p, _, _, _, _, _, _ := credentialControllerFixture(t)
			p.runtime = func(context.Context) (*sharedpg.UnverifiedRuntimeState, error) { return nil, errors.New("read failed") }
			h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c, vaultID: uuid.NewString()}}
			result, e := h.Handle(context.Background(), operation, nil)
			if !errors.Is(e, vaultwire.ErrRetired) || len(result) != 0 || !h.closed || c.Unlocked() {
				t.Fatal(e)
			}
		})
	}
}

type runtimeAdmissionProbe struct {
	sharedAdmissionSession
	state *sharedpg.UnverifiedRuntimeState
}

func (p *runtimeAdmissionProbe) RuntimeState(context.Context) (*sharedpg.UnverifiedRuntimeState, error) {
	return p.state, nil
}

func TestVaultSharedRuntimeAfterSelectedDeviceAdmission(t *testing.T) {
	h, _, payload, _ := vaultSharedFixture(t)
	if _, e := h.Handle(context.Background(), "shared-unlock", payload); e != nil {
		t.Fatal(e)
	}
	verifySharedRuntimeAfterAdmission(t, h)
}

func verifySharedRuntimeAfterAdmission(t *testing.T, h *vaultFoundationHandler) vaultSharedRuntime {
	t.Helper()
	c := h.shared.controller
	c.catalogAnchor = func(ctx context.Context, path string, root []byte, binding sharedpg.TrustBinding, trust sharedpg.TrustState) error {
		_, e := refreshSharedCatalogAnchor(ctx, path, root, binding, trust, h.startupProtection())
		return e
	}
	var current sharedpg.TrustState
	if e := c.root.With(func(root []byte) error {
		var e error
		current, e = readSharedTrustFile(c.trustPath, root, c.trustBinding, c.trustRevision)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	state, e := vault.EncodeUserKeyState(*current.Account)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(map[string]any{"formatVersion": 1, "profile": hex.EncodeToString(current.SignedProfile), "account": []any{strconv.FormatUint(current.Account.Sequence, 10), hex.EncodeToString(state)}})
	input, e := sharedpg.DecodeRuntimeState(raw, sharedpg.AdmissionRequest{WorkspaceID: current.WorkspaceID, UserID: current.UserID})
	if e != nil {
		t.Fatal(e)
	}
	c.session = &runtimeAdmissionProbe{sharedAdmissionSession: c.session, state: input}
	raw, e = h.Handle(context.Background(), "shared-runtime", nil)
	var result vaultSharedRuntime
	if e != nil || json.Unmarshal(raw, &result) != nil || result.WorkspaceID != current.WorkspaceID.String() || result.VaultID != h.shared.vaultID {
		t.Fatal("admitted runtime identity", e)
	}
	anchor, e := readSharedStartupAnchor(c.trustPath, h.startupProtection())
	if e != nil || result.VaultID != anchor.VaultID || !reflect.DeepEqual(current, anchor.Trust) {
		t.Fatal("runtime escaped its durable startup anchor", e)
	}
	return result
}
