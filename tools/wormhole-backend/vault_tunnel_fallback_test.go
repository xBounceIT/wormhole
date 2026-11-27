package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type nativeFallbackTestData struct {
	h                              *vaultFoundationHandler
	request                        map[string]any
	binding                        vault.TunnelFallbackBinding
	public, private, configuration []byte
}

func nativeFallbackFixture(t *testing.T) nativeFallbackTestData {
	t.Helper()
	h := vaultCredentialFixture(t)
	ctx := context.Background()
	configuration := []byte(`{"Host":"ssl.test","Username":"ssl-user","Password":"secondary-secret"}`)
	target, err := h.owner.PutTunnel(ctx, vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "SSL", Kind: 2}, configuration, 0)
	if err != nil {
		t.Fatal(err)
	}
	settings, _ := json.Marshal(map[string]any{"Host": "ipsec.test", "PreSharedKey": "primary-secret", "UserAuth": 0, "FallbackTunnelId": target.ID})
	primary, err := h.owner.PutTunnel(ctx, vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "IPsec", Kind: 9}, settings, 0)
	if err != nil {
		t.Fatal(err)
	}
	protocol, mode, enabled, host := 4, 1, true, "protected.test"
	node, err := h.owner.PutNode(ctx, vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "HTTPS", Kind: 1, Protocol: &protocol, Host: &host, CredentialMode: &mode, TunnelEnabled: &enabled, TunnelConfigID: &primary.ID}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	q := localvault.TunnelPlanRequest{NodeID: node.ID, SessionID: uuid.NewString(), RequestID: uuid.NewString(), Epoch: 1}
	original, err := h.owner.PlanConnectionTunnel(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	// A caller can provide metadata but cannot authorize its own target. Build
	// this claim without opening the primary settings; the RPC must re-resolve it.
	secondary := original
	secondary.RequestID, secondary.TunnelConfigID, secondary.Kind = uuid.NewString(), target.ID, 2
	secondary.RowVersion, secondary.ConfigurationVersion = target.RowVersion, target.ConfigurationVersion
	binding := vault.TunnelFallbackBinding{Primary: original, Fallback: secondary}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return nativeFallbackTestData{h: h, request: map[string]any{"nodeId": q.NodeID, "credentialOverride": "", "sessionId": q.SessionID, "requestId": q.RequestID, "epoch": "1"}, binding: binding, public: key.PublicKey().Bytes(), private: key.Bytes(), configuration: configuration}
}

func (f nativeFallbackTestData) body(seal bool) map[string]any {
	q := make(map[string]any)
	for k, v := range f.request {
		q[k] = v
	}
	if seal {
		q["binding"], q["publicKey"] = f.binding, f.public
	} else {
		q["primary"], q["fallbackRequestId"] = f.binding.Primary, f.binding.Fallback.RequestID
	}
	return q
}

func TestNativeFallbackPublishesOnlyBoundMetadataOrCiphertext(t *testing.T) {
	f := nativeFallbackFixture(t)
	ctx := context.Background()
	before, err := readVaultSlotFile(f.h.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, seal := range []bool{false, true} {
		operation := "tunnel-fallback-plan"
		if seal {
			operation = "tunnel-fallback-bundle"
		}
		raw, err := f.h.Handle(ctx, operation, vaultInput(t, f.body(seal)))
		if err != nil || bytes.Contains(raw, []byte("primary-secret")) || bytes.Contains(raw, []byte("secondary-secret")) || bytes.Contains(raw, f.configuration) {
			t.Fatal("native fallback leaked or refused", err)
		}
		if seal {
			var packet localvault.TunnelFallbackBundle
			if json.Unmarshal(raw, &packet) != nil || packet.Binding != f.binding {
				t.Fatal("wrong packet context")
			}
			plain, err := vault.OpenTunnelFallback(f.private, packet.Binding, packet.Bundle)
			if err != nil || !bytes.Equal(plain, f.configuration) {
				t.Fatal("wrong target handoff", err)
			}
			vault.Wipe(plain)
		} else {
			var binding vault.TunnelFallbackBinding
			if json.Unmarshal(raw, &binding) != nil || binding != f.binding || bytes.Contains(raw, []byte("ciphertext")) {
				t.Fatal("wrong public plan")
			}
		}
	}
	after, err := readVaultSlotFile(f.h.databasePath)
	if err != nil || after.Sequence <= before.Sequence || after.FileID != before.FileID || len(after.Slots) != len(before.Slots) {
		t.Fatal("checkpoint publication changed factors or missed floors", err)
	}
	for _, binding := range []vault.TunnelBundleBinding{f.binding.Primary, f.binding.Fallback} {
		found := false
		for _, mark := range after.Tunnels {
			if mark.TunnelID == binding.TunnelConfigID && mark.Revision == binding.RowVersion {
				found = true
			}
		}
		if !found {
			t.Fatal("source high-water missing")
		}
	}
}

func TestNativeFallbackStrictDecoderRejectsMalformedOrCallerSelectedSources(t *testing.T) {
	f := nativeFallbackFixture(t)
	for _, seal := range []bool{false, true} {
		operation := "tunnel-fallback-plan"
		if seal {
			operation = "tunnel-fallback-bundle"
		}
		good := f.body(seal)
		if _, err := decodeNativeTunnelFallback(operation, vaultInput(t, good)); err != nil {
			t.Fatal(err)
		}
		for field := range good {
			bad := f.body(seal)
			delete(bad, field)
			if _, err := decodeNativeTunnelFallback(operation, vaultInput(t, bad)); err != vaultwire.ErrProtocol {
				t.Fatal("missing field accepted", field, err)
			}
		}
		for _, epoch := range []any{"01", "0", "bad", "9007199254740992", 1, nil} {
			bad := f.body(seal)
			bad["epoch"] = epoch
			if _, err := decodeNativeTunnelFallback(operation, vaultInput(t, bad)); err != vaultwire.ErrProtocol {
				t.Fatal("bad epoch accepted", epoch, err)
			}
		}
		for _, raw := range [][]byte{nil, []byte(`{}`), []byte(`{"nodeId":null}`), bytes.Repeat([]byte{'x'}, 16385), []byte(`{"epoch":"1","epoch":"2"}`)} {
			if _, err := decodeNativeTunnelFallback(operation, raw); err != vaultwire.ErrProtocol {
				t.Fatal("malformed body accepted", err)
			}
		}
		for _, field := range []string{"tunnelId", "fallbackTunnelId", "settings"} {
			bad := f.body(seal)
			bad[field] = f.binding.Fallback.TunnelConfigID
			if _, err := decodeNativeTunnelFallback(operation, vaultInput(t, bad)); err != vaultwire.ErrProtocol {
				t.Fatal("unbound caller selection accepted", field, err)
			}
		}
		if seal {
			for _, key := range []any{nil, "AA==", []any{1, 2, 3}} {
				bad := f.body(true)
				bad["publicKey"] = key
				if _, err := decodeNativeTunnelFallback(operation, vaultInput(t, bad)); err != vaultwire.ErrProtocol {
					t.Fatal("bad recipient format accepted", err)
				}
			}
			for _, binding := range []any{nil, map[string]any{}, map[string]any{"primary": nil, "fallback": f.binding.Fallback}, map[string]any{"primary": f.binding.Primary, "fallback": nil}, map[string]any{"primary": f.binding.Primary, "fallback": f.binding.Fallback, "extra": true}} {
				bad := f.body(true)
				bad["binding"] = binding
				if _, err := decodeNativeTunnelFallback(operation, vaultInput(t, bad)); err != vaultwire.ErrProtocol {
					t.Fatal("bad paired binding accepted", err)
				}
			}
		} else {
			for _, attempt := range []any{"", "bad", f.binding.Primary.RequestID, nil} {
				bad := f.body(false)
				bad["fallbackRequestId"] = attempt
				if _, err := decodeNativeTunnelFallback(operation, vaultInput(t, bad)); err != vaultwire.ErrProtocol {
					t.Fatal("reused or bad attempt accepted", err)
				}
			}
			bad := f.body(false)
			bad["primary"] = nil
			if _, err := decodeNativeTunnelFallback(operation, vaultInput(t, bad)); err != vaultwire.ErrProtocol {
				t.Fatal("missing primary accepted", err)
			}
		}
	}
	if _, err := decodeNativeTunnelFallback("other", nil); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	if _, err := f.h.Handle(context.Background(), "tunnel-fallback-plan", vaultInput(t, f.body(false))); err != nil {
		t.Fatal("bad frame retired valid owner", err)
	}
}

func TestNativeIPsecFallbackSelectorValidatesAndNormalizesOnlyConfiguredReference(t *testing.T) {
	id := uuid.NewString()
	for _, value := range []string{id, strings.ToUpper(id), " " + id + " "} {
		raw, _ := json.Marshal(map[string]any{"Host": "ipsec.test", "PreSharedKey": "synthetic", "UserAuth": 0, "FallbackTunnelId": value})
		got, err := selectNativeIPsecFallback(raw)
		if err != nil || got != id {
			t.Fatal("configured reference", err)
		}
	}
	if id, err := selectNativeIPsecFallback([]byte(`{"Host":"ipsec.test","PreSharedKey":"synthetic","UserAuth":0}`)); err != nil || id != "" {
		t.Fatal("absent reference", err)
	}
	for _, raw := range []string{`{}`, `{`, `{"Host":"ipsec.test","PreSharedKey":"synthetic","FallbackTunnelId":null}`, `{"Host":"ipsec.test","PreSharedKey":"synthetic","FallbackTunnelId":"bad"}`, `{"Host":"ipsec.test","PreSharedKey":"synthetic","FallbackTunnelId":"00000000-0000-0000-0000-000000000000"}`} {
		if _, err := selectNativeIPsecFallback([]byte(raw)); err == nil {
			t.Fatal("invalid settings admitted")
		}
	}
}

func TestNativeFallbackCannotPublishWithoutDurableCheckpoint(t *testing.T) {
	for _, phase := range []string{"before", "after", "cancel-after-seal"} {
		t.Run(phase, func(t *testing.T) {
			f := nativeFallbackFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			observed := false
			if phase == "before" {
				if err := os.Remove(vaultSlotPath(f.h.databasePath)); err != nil {
					t.Fatal(err)
				}
			} else {
				previous := privateFileDirectorySync
				t.Cleanup(func() { privateFileDirectorySync = previous })
				privateFileDirectorySync = func(path string) error {
					document, err := readVaultSlotFile(f.h.databasePath)
					if err != nil {
						return err
					}
					// An unchanged initial checkpoint needs no write. New source-node
					// observations are written after the action produces its packet.
					if len(document.Nodes) != 0 {
						observed = true
						if phase == "cancel-after-seal" {
							cancel()
						} else {
							return os.Remove(vaultSlotPath(f.h.databasePath))
						}
					}
					return previous(path)
				}
			}
			raw, err := f.h.Handle(ctx, "tunnel-fallback-bundle", vaultInput(t, f.body(true)))
			if phase != "before" && !observed {
				t.Fatal("test missed action publication boundary")
			}
			if phase == "cancel-after-seal" {
				if err != context.Canceled || raw != nil || f.h.closed {
					t.Fatal("late cancellation escaped or retired usable owner", err)
				}
			} else if err == nil || raw != nil || !f.h.closed {
				t.Fatal("uncheckpointed response escaped", err)
			}
		})
	}
	f := nativeFallbackFixture(t)
	if _, err := (&vaultFoundationHandler{}).Handle(context.Background(), "tunnel-fallback-plan", vaultInput(t, f.body(false))); err != vaultwire.ErrProtocol {
		t.Fatal("locked fallback", err)
	}
	if _, err := f.h.tunnelFallback(nil, "tunnel-fallback-plan", nil); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
}

func TestNativeFallbackDenialsPreserveSourceObservations(t *testing.T) {
	for _, mode := range []string{"plan-mismatch", "bundle-mismatch", "zero-recipient", "deleted-target"} {
		t.Run(mode, func(t *testing.T) {
			f := nativeFallbackFixture(t)
			ctx := context.Background()
			operation := "tunnel-fallback-bundle"
			body := f.body(true)
			switch mode {
			case "plan-mismatch":
				operation = "tunnel-fallback-plan"
				body = f.body(false)
				primary := f.binding.Primary
				primary.Host = "changed.example"
				body["primary"] = primary
			case "bundle-mismatch":
				binding := f.binding
				binding.Fallback.TunnelConfigID = uuid.NewString()
				body["binding"] = binding
			case "zero-recipient":
				body["publicKey"] = make([]byte, 32)
			case "deleted-target":
				if err := f.h.owner.DeleteTunnel(ctx, f.binding.Fallback.TunnelConfigID, f.binding.Fallback.RowVersion); err != nil {
					t.Fatal(err)
				}
			}
			raw, err := f.h.Handle(ctx, operation, vaultInput(t, body))
			if err == nil || raw != nil || f.h.closed != (mode != "deleted-target") {
				t.Fatal("source denial escaped or wrong retirement", err)
			}
			document, err := readVaultSlotFile(f.h.databasePath)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, mark := range document.Nodes {
				if mark.NodeID == f.binding.Primary.NodeID && mark.Revision > 0 {
					found = true
				}
			}
			if !found {
				t.Fatal("authenticated source observation lost on denial")
			}
		})
	}
}

func TestNativeFallbackRetainsAuthenticatedPolicyFloorBeforeUnsupportedProfileDenial(t *testing.T) {
	for _, operation := range []string{"tunnel-fallback-plan", "tunnel-plan", "security"} {
		t.Run(operation, func(t *testing.T) {
			f := nativeFallbackFixture(t)
			ctx := context.Background()
			policy, err := f.h.owner.ReadLocalPolicy(ctx)
			if err != nil {
				t.Fatal(err)
			}
			policy.Policy.Sequence++
			policy.Policy.Profile, policy.Policy.KDF = vault.Standard, vault.KDFV2
			if _, err := f.h.owner.PutLocalPolicy(ctx, policy.Policy, vault.Hardened, policy.Policy.Sequence-1); err != nil {
				t.Fatal(err)
			}
			payload := vaultInput(t, f.body(false))
			if operation == "tunnel-plan" {
				payload = vaultInput(t, f.request)
			}
			if operation == "security" {
				payload = nil
			}
			if raw, err := f.h.Handle(ctx, operation, payload); err == nil || raw != nil || !f.h.closed {
				t.Fatal("unsupported profile admitted", err)
			}
			document, err := readVaultSlotFile(f.h.databasePath)
			if err != nil || document.ProfileSequence != policy.Policy.Sequence {
				t.Fatal("authenticated stronger policy observation lost on denial", err)
			}
		})
	}
}

func TestNativeFallbackCancellationCannotMaskKnownPolicyFailure(t *testing.T) {
	for _, policyFailure := range []bool{false, true} {
		f := nativeFallbackFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		cause := error(context.Canceled)
		if policyFailure {
			cause = vault.ErrPolicy
		}
		raw, err := f.h.rejectLocalPolicy(ctx, cause)
		if raw != nil || err == nil || f.h.closed != policyFailure {
			t.Fatal("cancellation masked policy failure or retired a valid cancelled owner", err)
		}
		if policyFailure && !errors.Is(err, vault.ErrPolicy) {
			t.Fatal("policy failure identity lost", err)
		}
	}
}

func TestNativeFallbackPolicyDenialRetainsCheckpointFailure(t *testing.T) {
	f := nativeFallbackFixture(t)
	if err := os.Remove(vaultSlotPath(f.h.databasePath)); err != nil {
		t.Fatal(err)
	}
	raw, err := f.h.rejectLocalPolicy(context.Background(), vault.ErrPolicy)
	if raw != nil || !f.h.closed || !errors.Is(err, vaultwire.ErrRetired) || !errors.Is(err, vault.ErrPolicy) || !errors.Is(err, errVaultSlotMissing) {
		t.Fatal("checkpoint failure discarded policy denial or left owner active", err)
	}
}

func TestNativeFallbackStrictFramesAlsoApplyToSharedSources(t *testing.T) {
	h, _, _, _ := sharedSSOFixture(t, 9)
	for _, operation := range []string{"tunnel-fallback-plan", "tunnel-fallback-bundle"} {
		if raw, err := h.Handle(context.Background(), operation, json.RawMessage(`{}`)); raw != nil || err != vaultwire.ErrProtocol || h.closed {
			t.Fatal("shared fallback API accepted malformed input or retired shared session", err)
		}
	}
}
