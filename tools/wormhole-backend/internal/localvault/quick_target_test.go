package localvault

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type quickStoreProbe struct {
	*vaultstore.SQLite
	secretReads, nodeWrites int
	failRead                bool
	collision               bool
}

func (s *quickStoreProbe) ReadSecret(ctx context.Context, ref vaultstore.SecretRef) (vaultstore.Secret, error) {
	s.secretReads++
	return s.SQLite.ReadSecret(ctx, ref)
}
func (s *quickStoreProbe) WriteNode(context.Context, vaultstore.Node, []vaultstore.Secret, uint64) error {
	s.nodeWrites++
	return vaultstore.ErrStorage
}
func (s *quickStoreProbe) ReadNode(ctx context.Context, id string) (vaultstore.Node, error) {
	if s.failRead {
		return vaultstore.Node{}, vaultstore.ErrStorage
	}
	if s.collision {
		return vaultstore.Node{}, nil
	}
	return s.SQLite.ReadNode(ctx, id)
}
func quickRequest(t *testing.T, ref QuickTargetRef) (TunnelBundleRequest, []byte) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private := key.Bytes()
	t.Cleanup(func() { vault.Wipe(private) })
	return TunnelBundleRequest{NodeID: ref.ID, SessionID: ref.SessionID, RequestID: uuid.NewString(), Epoch: ref.Epoch, PublicKey: key.PublicKey().Bytes()}, private
}
func TestQuickTargetsUseScopedNativeProtocolsWithoutPersisting(t *testing.T) {
	for _, protocol := range []string{"rdp", "vnc", "ssh", "sftp", "http", "https"} {
		t.Run(protocol, func(t *testing.T) {
			o, _, _, _ := owner(t)
			ctx := context.Background()
			input := QuickTargetRequest{SessionID: uuid.NewString(), Epoch: 1, Target: QuickConnectionTarget{Protocol: protocol, Host: "quick.example"}}
			if protocol != "http" && protocol != "https" {
				d := draft()
				d.Protocol = protocol
				if protocol == "sftp" {
					d.Protocol = "ssh"
				}
				d.Username = "quick-user"
				credential, err := o.PutCredential(ctx, d, []SecretChange{{Field: "password", Value: []byte("quick-native-only")}}, 0)
				if err != nil {
					t.Fatal(err)
				}
				input.Target.CredentialID = credential.ID
			}
			store := &quickStoreProbe{SQLite: o.store.(*vaultstore.SQLite)}
			o.store = store
			ref, err := o.RegisterQuickTarget(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			if store.secretReads != 0 || store.nodeWrites != 0 || ref.ID == input.SessionID || ref.SessionID != input.SessionID || ref.Epoch != 1 {
				t.Fatal("registration borrowed/persisted", err)
			}
			if _, err = o.ReadNode(ctx, ref.ID, 0); !errors.Is(err, vaultstore.ErrMissing) {
				t.Fatal("temporary target became a node", err)
			}
			if _, err = o.ResolveConnection(ctx, ref.ID, ""); err == nil {
				t.Fatal("unscoped resolution")
			}
			q, key := quickRequest(t, ref)
			switch protocol {
			case "rdp":
				result, err := o.SealRDPConnection(ctx, q)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := vault.OpenBundle(key, result.Binding, result.Bundle)
				if err != nil {
					t.Fatal(err)
				}
				defer vault.Wipe(raw)
				payload, err := vault.DecodeRDPBundle(raw)
				if err != nil || string(payload.Password) != "quick-native-only" || result.Binding.Host != "quick.example" || result.Binding.Port != 3389 {
					t.Fatal("wrong RDP target", err)
				}
			case "vnc":
				result, err := o.SealVNCConnection(ctx, q)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := vault.OpenBundle(key, result.Binding, result.Bundle)
				if err != nil {
					t.Fatal(err)
				}
				defer vault.Wipe(raw)
				payload, err := vault.DecodeVNCBundle(raw)
				if err != nil || string(payload.Password) != "quick-native-only" || !payload.PasswordProvided || result.Binding.Port != 5900 {
					t.Fatal("wrong VNC target", err)
				}
			case "ssh", "sftp":
				plan, err := o.PlanSSHHost(ctx, q.Plan(), nil)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = o.TrustSSHHost(ctx, q.Plan(), nil, plan, hostFingerprint(1)); err == nil {
					t.Fatal("generic trust persisted a quick target")
				}
				trusted, err := o.TrustQuickSSHHost(ctx, q.Plan(), nil, plan, hostFingerprint(1))
				if err != nil || trusted.Fingerprint != hostFingerprint(1) || trusted.Revision == plan.Revision {
					t.Fatal("ephemeral trust", err)
				}
				if _, err = o.TrustQuickSSHHost(ctx, q.Plan(), nil, plan, hostFingerprint(2)); err == nil {
					t.Fatal("stale trust")
				}
				ssh := SSHBundleRequest{NodeID: q.NodeID, SessionID: q.SessionID, RequestID: q.RequestID, Epoch: q.Epoch, PublicKey: q.PublicKey, SFTPOnly: protocol == "sftp"}
				result, err := o.SealSSHConnection(ctx, ssh)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := vault.OpenBundle(key, result.Binding, result.Bundle)
				if err != nil {
					t.Fatal(err)
				}
				defer vault.Wipe(raw)
				payload, err := vault.DecodeSSHBundle(raw)
				if err != nil || string(payload.Password) != "quick-native-only" || payload.Fingerprint != hostFingerprint(1) || payload.SFTPOnly != (protocol == "sftp") || result.Binding.Port != 22 {
					t.Fatal("wrong SSH target", err)
				}
			default:
				result, err := o.PlanWebConnection(ctx, q.Plan())
				expected := uint16(80)
				if protocol == "https" {
					expected = 443
				}
				if err != nil || result.Binding.Host != "quick.example" || result.Binding.Port != expected || result.Route != nil {
					t.Fatal("wrong web target", err)
				}
			}
			if store.nodeWrites != 0 {
				t.Fatal("node persisted")
			}
			if err = o.ReleaseQuickTarget(ctx, ref); err != nil {
				t.Fatal(err)
			}
			if _, err = o.ResolveConnectionRoute(ctx, q.Plan()); err == nil {
				t.Fatal("released target usable")
			}
			if err = o.ReleaseQuickTarget(ctx, ref); err != nil {
				t.Fatal("non-idempotent close", err)
			}
		})
	}
}
func TestQuickTargetManualRDPHasNoSavedFallbackAndRechecksRoute(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	settings := vault.DefaultRDPSettings()
	input := QuickTargetRequest{SessionID: uuid.NewString(), Epoch: 3, Target: QuickConnectionTarget{Protocol: "rdp", Host: "direct.example", RDP: &settings}}
	ref, err := o.RegisterQuickTarget(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	settings.Domain = "tampered"
	input.Target.Host = "changed.example"
	q, key := quickRequest(t, ref)
	binding, err := o.PlanRDPConnection(ctx, q.Plan())
	if err != nil || binding.Host != "direct.example" {
		t.Fatal("input alias", err)
	}
	inner, err := vault.SealManualRDPCredentials(q.PublicKey, binding, nil, "", vault.RDPManualCredentials{Username: "manual", Domain: "ONE-USE", Password: []byte{}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := o.SealManualRDPConnection(ctx, q, binding, nil, "", inner)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := vault.OpenBundle(key, binding, result.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(raw)
	base, opaque, err := vault.DecodeRDPManualAuthorization(raw)
	if err != nil || base.PasswordProvided || base.Username != "" || base.Settings.Domain != "" {
		t.Fatal("fallback", err)
	}
	plain, err := vault.OpenManualRDPCredentials(key, binding, nil, "", opaque)
	if err != nil {
		t.Fatal(err)
	}
	vault.Wipe(plain)
	tunnel, err := o.PutTunnel(ctx, tunnelDraft(), []byte("quick-route-settings"), 0)
	if err != nil {
		t.Fatal(err)
	}
	input.Target = QuickConnectionTarget{Protocol: "rdp", Host: "routed.example", TunnelID: tunnel.ID}
	ref, err = o.RegisterQuickTarget(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	q, key = quickRequest(t, ref)
	route, err := o.ResolveConnectionRoute(ctx, q.Plan())
	if err != nil || route == nil {
		t.Fatal(err)
	}
	if _, err = o.PlanRDPConnection(ctx, q.Plan()); err == nil {
		t.Fatal("direct fallback")
	}
	endpoint := "127.0.0.1:2345"
	inner, err = vault.SealManualRDPCredentials(q.PublicKey, route.BundleBinding, route, endpoint, vault.RDPManualCredentials{Username: "routed"})
	if err != nil {
		t.Fatal(err)
	}
	result, err = o.SealManualRDPConnection(ctx, q, route.BundleBinding, route, endpoint, inner)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = vault.OpenRoutedBundle(key, *route, endpoint, result.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	vault.Wipe(raw)
	if _, err = o.PutTunnel(ctx, tunnel.TunnelMetadata, []byte("rotated-settings"), tunnel.RowVersion); err != nil {
		t.Fatal(err)
	}
	if _, err = o.SealManualRDPConnection(ctx, q, route.BundleBinding, route, endpoint, inner); err == nil {
		t.Fatal("stale route revision")
	}
}
func TestQuickTargetScopeExpiryCapacityAndMalformedInputs(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	good := QuickTargetRequest{SessionID: uuid.NewString(), Epoch: 1, Target: QuickConnectionTarget{Protocol: "vnc", Host: "target.example"}}
	for _, mutate := range []func(*QuickTargetRequest){
		func(q *QuickTargetRequest) { q.SessionID = "bad" }, func(q *QuickTargetRequest) { q.Epoch = 0 }, func(q *QuickTargetRequest) { q.Epoch = 9007199254740992 }, func(q *QuickTargetRequest) { q.Target.Protocol = "serial" },
		func(q *QuickTargetRequest) { q.Target.Host = "" }, func(q *QuickTargetRequest) { q.Target.Host = "bad host" }, func(q *QuickTargetRequest) { q.Target.Host = "user@host" }, func(q *QuickTargetRequest) { q.Target.Host = string([]byte{255}) }, func(q *QuickTargetRequest) { q.Target.Host = strings.Repeat("h", 1025) },
		func(q *QuickTargetRequest) { q.Target.Port = -1 }, func(q *QuickTargetRequest) { q.Target.Port = 65536 }, func(q *QuickTargetRequest) { q.Target.CredentialID = "bad" }, func(q *QuickTargetRequest) { q.Target.TunnelID = "bad" },
		func(q *QuickTargetRequest) { q.Target.SSHAutoSudo = true }, func(q *QuickTargetRequest) { q.Target.HTTPPath = "/path" }, func(q *QuickTargetRequest) { q.Target.IgnoreCertificateErrors = true }, func(q *QuickTargetRequest) { q.Target.RDP = &vault.RDPSettings{} },
		func(q *QuickTargetRequest) { q.Target.Protocol = "http"; q.Target.CredentialID = uuid.NewString() }, func(q *QuickTargetRequest) { q.Target.CredentialID = uuid.NewString() },
		func(q *QuickTargetRequest) {
			q.Target.Protocol = "rdp"
			s := vault.DefaultRDPSettings()
			s.Domain = "ordinary"
			q.Target.RDP = &s
		},
		func(q *QuickTargetRequest) {
			q.Target.Protocol = "rdp"
			s := vault.DefaultRDPSettings()
			s.ScreenSize = "invalid"
			q.Target.RDP = &s
		},
	} {
		q := good
		mutate(&q)
		if _, err := o.RegisterQuickTarget(ctx, q); err == nil {
			t.Fatal("invalid target admitted", q.Target.Protocol)
		}
	}
	if len(o.quickTargets) != 0 {
		t.Fatal("partial registration")
	}
	if _, err := o.RegisterQuickTarget(nil, good); err == nil {
		t.Fatal("nil context")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.RegisterQuickTarget(cancelled, good); err == nil {
		t.Fatal("cancelled registration")
	}
	ref, err := o.RegisterQuickTarget(ctx, good)
	if err != nil {
		t.Fatal(err)
	}
	q, _ := quickRequest(t, ref)
	for _, mutate := range []func(*TunnelPlanRequest){func(q *TunnelPlanRequest) { q.SessionID = uuid.NewString() }, func(q *TunnelPlanRequest) { q.Epoch++ }, func(q *TunnelPlanRequest) { q.CredentialOverride = uuid.NewString() }} {
		wrong := q.Plan()
		mutate(&wrong)
		if _, err := o.ResolveConnectionRoute(ctx, wrong); err == nil {
			t.Fatal("cross-scope target")
		}
	}
	bad := ref
	bad.SessionID = uuid.NewString()
	if err = o.ReleaseQuickTarget(ctx, bad); err == nil {
		t.Fatal("cross-session release")
	}
	if err = o.ReleaseQuickTarget(nil, ref); err == nil {
		t.Fatal("nil release")
	}
	bad = ref
	bad.ID = "bad"
	if err = o.ReleaseQuickTarget(ctx, bad); err == nil {
		t.Fatal("bad release")
	}
	if err = o.ReleaseQuickTarget(cancelled, ref); err == nil {
		t.Fatal("cancelled release")
	}
	if _, err = o.ResolveConnectionRoute(nil, q.Plan()); err == nil {
		t.Fatal("nil plan")
	}
	if _, err = o.ResolveConnectionRoute(cancelled, q.Plan()); err == nil {
		t.Fatal("cancelled plan")
	}
	o.quickTargets[ref.ID].expires = time.Now().Add(-time.Second)
	if _, err = o.ResolveConnectionRoute(ctx, q.Plan()); err == nil {
		t.Fatal("expired target")
	}
	for i := 0; i < maxQuickTargets; i++ {
		if _, err = o.RegisterQuickTarget(ctx, good); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = o.RegisterQuickTarget(ctx, good); err == nil {
		t.Fatal("unbounded targets")
	}
	for _, stage := range o.quickTargets {
		stage.expires = time.Now().Add(-time.Second)
	}
	if _, err = o.RegisterQuickTarget(ctx, good); err != nil || len(o.quickTargets) != 1 {
		t.Fatal("expiry did not release capacity", err)
	}
	if err = o.Close(); err != nil {
		t.Fatal(err)
	}
	if len(o.quickTargets) != 0 {
		t.Fatal("owner close retained targets")
	}
	if _, err = o.RegisterQuickTarget(ctx, good); err == nil {
		t.Fatal("closed registration")
	}
	if err = o.ReleaseQuickTarget(ctx, ref); err == nil {
		t.Fatal("closed release")
	}
}
func TestQuickTargetRejectsStoreFailuresAndStaleSavedAccounts(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	store := &quickStoreProbe{SQLite: o.store.(*vaultstore.SQLite)}
	o.store = store
	input := QuickTargetRequest{SessionID: uuid.NewString(), Epoch: 1, Target: QuickConnectionTarget{Protocol: "rdp", Host: "quick.example"}}
	for _, mode := range []string{"read", "collision"} {
		store.failRead = mode == "read"
		store.collision = mode == "collision"
		if _, err := o.RegisterQuickTarget(ctx, input); err == nil {
			t.Fatal("store failure accepted", mode)
		}
	}
	store.failRead, store.collision = false, false
	d := draft()
	d.Protocol = "rdp"
	credential, err := o.PutCredential(ctx, d, []SecretChange{{Field: "password", Value: []byte("saved-only")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	input.Target.CredentialID = credential.ID
	ref, err := o.RegisterQuickTarget(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	q, key := quickRequest(t, ref)
	before := store.secretReads
	metadata := credential.CredentialMetadata
	metadata.Username = "current-account"
	if _, err = o.PutCredential(ctx, metadata, nil, credential.RowVersion); err != nil {
		t.Fatal(err)
	}
	result, err := o.SealRDPConnection(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := vault.OpenBundle(key, result.Binding, result.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(raw)
	p, err := vault.DecodeRDPBundle(raw)
	if err != nil || p.Username != "current-account" || !bytes.Equal(p.Password, []byte("saved-only")) || store.secretReads != before+1 {
		t.Fatal("stale account used", err)
	}
}

func TestQuickSSHTrustCannotCrossSourcesOrAcceptInvalidEvidence(t *testing.T) {
	ctx := context.Background()
	o, node, request, _ := sshBundleFixture(t)
	q := TunnelPlanRequest{NodeID: node.ID, SessionID: request.SessionID, RequestID: request.RequestID, Epoch: request.Epoch}
	plan, err := o.PlanSSHHost(ctx, q, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = o.TrustQuickSSHHost(ctx, q, nil, plan, hostFingerprint(8)); err == nil {
		t.Fatal("saved source mutated")
	}
	input := QuickTargetRequest{SessionID: uuid.NewString(), Epoch: 1, Target: QuickConnectionTarget{Protocol: "ssh", Host: "quick.example"}}
	ref, err := o.RegisterQuickTarget(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := quickRequest(t, ref)
	q = r.Plan()
	plan, err = o.PlanSSHHost(ctx, q, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = o.TrustQuickSSHHost(ctx, q, nil, plan, "invalid"); err == nil {
		t.Fatal("invalid fingerprint")
	}
	if _, err = o.TrustQuickSSHHost(nil, q, nil, plan, hostFingerprint(2)); err == nil {
		t.Fatal("nil context")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = o.TrustQuickSSHHost(cancelled, q, nil, plan, hostFingerprint(2)); err == nil {
		t.Fatal("cancelled trust")
	}
	trusted, err := o.TrustQuickSSHHost(ctx, q, nil, plan, hostFingerprint(2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = o.TrustQuickSSHHost(ctx, q, nil, trusted, hostFingerprint(2)); err == nil {
		t.Fatal("no-op trust")
	}
	o.quickTargets[ref.ID].revision = ^uint64(0)
	plan, err = o.PlanSSHHost(ctx, q, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = o.TrustQuickSSHHost(ctx, q, nil, plan, hostFingerprint(3)); err == nil {
		t.Fatal("revision overflow")
	}
}
