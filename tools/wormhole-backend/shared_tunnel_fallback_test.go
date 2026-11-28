package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type sharedFallbackProbe struct {
	*credentialReleaseProbe
	beginFallback func(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string) (*sharedpg.FallbackUseIntent, error)
	fetchFallback func(context.Context, sharedpg.FallbackUseIntent) (*sharedpg.UnverifiedFallbackRelease, error)
}

func (p *sharedFallbackProbe) BeginFallbackUse(ctx context.Context, n, a, b uuid.UUID, s string) (*sharedpg.FallbackUseIntent, error) {
	return p.beginFallback(ctx, n, a, b, s)
}
func (p *sharedFallbackProbe) FetchFallbackSecret(ctx context.Context, i sharedpg.FallbackUseIntent) (*sharedpg.UnverifiedFallbackRelease, error) {
	return p.fetchFallback(ctx, i)
}

type sharedFallbackFixtureData struct {
	h                            *vaultFoundationHandler
	c                            *sharedAdmissionController
	p                            *sharedFallbackProbe
	q                            localvault.TunnelPlanRequest
	pair                         vault.TunnelFallbackBinding
	private, public, root, plain []byte
	wire                         map[string]any
	path                         string
	binding                      sharedpg.TrustBinding
	initial                      uint64
	primaryUses, secondaryUses   int
}

func sharedFallbackFixture(t *testing.T) *sharedFallbackFixtureData {
	return sharedFallbackFixtureWithSettings(t, []byte(`{"Host":"ssl.test","Username":"secondary","Password":"secondary-secret"}`))
}

func sharedFallbackFixtureWithSettings(t *testing.T, settings []byte) *sharedFallbackFixtureData {
	t.Helper()
	h, p, request, source := sharedSSOFixture(t, 9)
	c := h.shared.controller
	d := &sharedFallbackFixtureData{h: h, c: c, plain: bytes.Clone(settings), path: c.trustPath, binding: c.trustBinding, initial: c.trustRevision}
	if err := c.root.With(func(raw []byte) error { d.root = bytes.Clone(raw); return nil }); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vault.Wipe(d.root); vault.Wipe(d.private) })
	var signing ed25519.PrivateKey
	if err := c.privateKeys.With(func(raw []byte) error { signing = ed25519.NewKeyFromSeed(raw[32:]); return nil }); err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(signing)
	encoded, _ := json.Marshal(source)
	var secondary map[string]any
	_ = json.Unmarshal(encoded, &secondary)
	m := source["metadata"].(map[string]any)
	node := m["chain"].([]any)[0].([]any)
	certificateRaw, _ := hex.DecodeString(node[23].(string))
	certificate, err := vault.DecodeUserEnrollmentCertificate(certificateRaw)
	if err != nil {
		t.Fatal(err)
	}
	stateRaw, _ := hex.DecodeString(source["account"].([]any)[1].(string))
	state, err := vault.DecodeUserKeyState(stateRaw)
	if err != nil {
		t.Fatal(err)
	}
	material := &sharedpg.UnverifiedAccountKeys{Binding: vault.UserKeyBinding{WorkspaceID: c.trustBinding.WorkspaceID, UserID: c.trustBinding.UserID, Signing: vault.KeyRef{ID: certificate.Rekey.SigningKeyID, Version: certificate.Rekey.KeyVersion}, Encryption: vault.KeyRef{ID: certificate.Rekey.EncryptionKeyID, Version: certificate.Rekey.KeyVersion}, Revision: 1}, State: &state, EnrollmentCertificate: &certificate}
	targetID := uuid.NewString()
	editSharedConnectionFixture(t, c.trustBinding.WorkspaceID, material.Binding.Signing, secondary, func(n *vaultstore.NodeMetadata, _ *sharedcatalog.CredentialRecord) { n.TunnelConfigID = &targetID }, signing)
	installSharedTunnelReleaseFixture(t, secondary, material, d.plain, signing)
	metadata := secondary["metadata"].(map[string]any)
	target := metadata["tunnel"].([]any)
	var record sharedcatalog.TunnelRecord
	_ = json.Unmarshal([]byte(target[4].(string)), &record)
	record.Metadata.Kind = 2
	seal, err := sharedcatalog.SignSelection(c.trustBinding.WorkspaceID, uuid.MustParse(target[5].(string)), record, 1, material.Binding.Signing, signing)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(record)
	target[4], target[11] = string(body), hex.EncodeToString(seal.Signature)
	accounts := secondary["accounts"].([]any)
	targetAccount := accounts[len(accounts)-1].(map[string]any)
	var boundary any
	for _, raw := range metadata["boundaries"].([]any) {
		if raw.([]any)[1] == target[5] {
			boundary = raw
		}
	}
	d.wire = map[string]any{"formatVersion": 1, "source": source, "target": target, "boundary": boundary, "values": targetAccount["values"], "copies": targetAccount["copies"], "roots": source["roots"]}
	for _, entry := range source["accounts"].([]any) {
		a := entry.(map[string]any)
		if a["account"] != "tunnel" {
			continue
		}
		row := a["values"].([]any)[0].([]any)
		plain, _ := json.Marshal(map[string]any{"Host": "ipsec.test", "PreSharedKey": "primary-secret", "UserAuth": 0, "FallbackTunnelId": targetID})
		version, _ := strconv.ParseUint(row[5].(string), 10, 64)
		binding := vault.SharedValueBinding{WorkspaceID: c.trustBinding.WorkspaceID, OwnerKind: "tunnel", OwnerID: uuid.MustParse(row[1].(string)), Field: "settings", Version: version, DEK: vault.KeyRef{ID: uuid.MustParse(row[6].(string)), Version: 1}}
		value, err := vault.SealSharedValue(bytes.Repeat([]byte{24}, 32), binding, plain)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := vault.EncodeSharedEnvelope(value)
		row[8] = hex.EncodeToString(raw)
	}
	q := request["request"].(map[string]any)
	d.q = localvault.TunnelPlanRequest{NodeID: q["nodeId"].(string), SessionID: q["sessionId"].(string), RequestID: q["requestId"].(string), Epoch: 3}
	primary := request["binding"].(vault.TunnelBundleBinding)
	fallback := primary
	fallback.TunnelConfigID, fallback.Kind, fallback.RequestID = targetID, 2, uuid.NewString()
	d.pair = vault.TunnelFallbackBinding{Primary: primary, Fallback: fallback}
	d.private = request["fixturePrivate"].([]byte)
	key, _ := ecdh.X25519().NewPrivateKey(d.private)
	d.public = key.PublicKey().Bytes()
	d.p = &sharedFallbackProbe{credentialReleaseProbe: p}
	oldBegin := p.begin
	p.begin = func(ctx context.Context, n uuid.UUID, s string) (*sharedpg.UseIntent, error) {
		d.primaryUses++
		return oldBegin(ctx, n, s)
	}
	d.p.beginFallback = func(_ context.Context, n, a, b uuid.UUID, s string) (*sharedpg.FallbackUseIntent, error) {
		d.secondaryUses++
		if n.String() != d.q.NodeID || a.String() != primary.TunnelConfigID || b.String() != targetID || s != "ui" {
			return nil, sharedpg.ErrQuery
		}
		return &sharedpg.FallbackUseIntent{UseIntent: sharedpg.UseIntent{Ticket: uuid.New(), Node: n, Epoch: 1, ChangeSeq: 9, ExpiresAt: 1800000000}, PrimaryTunnel: a, FallbackTunnel: b}, nil
	}
	d.p.fetchFallback = func(_ context.Context, i sharedpg.FallbackUseIntent) (*sharedpg.UnverifiedFallbackRelease, error) {
		raw, _ := json.Marshal(d.wire)
		return sharedpg.DecodeFallbackRelease(raw, sharedpg.AdmissionRequest{WorkspaceID: d.binding.WorkspaceID, UserID: d.binding.UserID, DeviceID: d.binding.DeviceID}, i)
	}
	c.session = d.p
	return d
}

func (d *sharedFallbackFixtureData) body(seal bool) map[string]any {
	m := map[string]any{"nodeId": d.q.NodeID, "credentialOverride": "", "sessionId": d.q.SessionID, "requestId": d.q.RequestID, "epoch": "3"}
	if seal {
		m["binding"], m["publicKey"] = d.pair, d.public
	} else {
		m["primary"], m["fallbackRequestId"] = d.pair.Primary, d.pair.Fallback.RequestID
	}
	return m
}

func TestSharedFallbackNativePlanAndBundleCommitBothSources(t *testing.T) {
	d := sharedFallbackFixture(t)
	ctx := context.Background()
	raw, err := d.h.Handle(ctx, "tunnel-fallback-plan", vaultInput(t, d.body(false)))
	var plan vault.TunnelFallbackBinding
	if err != nil || json.Unmarshal(raw, &plan) != nil || plan != d.pair || d.primaryUses != 1 || d.secondaryUses != 1 {
		t.Fatal("shared fallback plan", err)
	}
	stored, err := readSharedTrustFile(d.path, d.root, d.binding, d.initial)
	if err != nil || stored.Catalog["tunnel/"+d.pair.Primary.TunnelConfigID].Revision == 0 || stored.Catalog["tunnel/"+d.pair.Fallback.TunnelConfigID].Revision == 0 {
		t.Fatal("both source facts not durable", err)
	}
	// The destination password is not part of either tunnel configuration loan.
	corruptSharedCiphertext(t, d.wire["source"].(map[string]any), "primary")
	raw, err = d.h.Handle(ctx, "tunnel-fallback-bundle", vaultInput(t, d.body(true)))
	var packet localvault.TunnelFallbackBundle
	if err != nil || json.Unmarshal(raw, &packet) != nil || packet.Binding != d.pair || d.primaryUses != 1 || d.secondaryUses != 2 {
		t.Fatal("shared fallback bundle", err)
	}
	plain, err := vault.OpenTunnelFallback(d.private, d.pair, packet.Bundle)
	if err != nil || !bytes.Equal(plain, d.plain) || bytes.Contains(raw, d.plain) || bytes.Contains(raw, []byte("primary-secret")) {
		t.Fatal("fallback ciphertext relay", err)
	}
	vault.Wipe(plain)
	if _, err := vault.OpenTunnelBundle(d.private, d.pair.Fallback, packet.Bundle); err == nil {
		t.Fatal("ordinary purpose substitution")
	}
}

func TestSharedFallbackAnchorFailureCannotPublishCiphertext(t *testing.T) {
	d := sharedFallbackFixture(t)
	want := errors.New("synthetic target anchor failure")
	old := d.c.catalogAnchor
	d.c.catalogAnchor = func(ctx context.Context, path string, key []byte, b sharedpg.TrustBinding, s sharedpg.TrustState) error {
		if s.Catalog["tunnel/"+d.pair.Fallback.TunnelConfigID].Revision > 0 {
			return want
		}
		return old(ctx, path, key, b, s)
	}
	raw, err := d.h.Handle(context.Background(), "tunnel-fallback-bundle", vaultInput(t, d.body(true)))
	if raw != nil || !errors.Is(err, want) || d.c.Unlocked() || !d.h.closed {
		t.Fatal("anchor failure escaped", err)
	}
	stored, err := readSharedTrustFile(d.path, d.root, d.binding, d.initial)
	if err != nil || stored.Catalog["tunnel/"+d.pair.Fallback.TunnelConfigID].Revision == 0 {
		t.Fatal("authenticated target observations lost", err)
	}
}

func TestSharedFallbackFailuresRetainFactsAndPublishNothing(t *testing.T) {
	for _, mode := range []string{"begin", "nil-intent", "intent", "fetch", "nil-graph", "source-proof", "target-proof", "target-cipher", "reference", "pair-primary", "pair-target", "cancel-fetch", "cancel-anchor", "short-key"} {
		t.Run(mode, func(t *testing.T) {
			d := sharedFallbackFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			body := d.body(true)
			wantFloor := false
			switch mode {
			case "begin":
				d.p.beginFallback = func(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string) (*sharedpg.FallbackUseIntent, error) {
					return nil, sharedpg.ErrQuery
				}
			case "nil-intent":
				d.p.beginFallback = func(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string) (*sharedpg.FallbackUseIntent, error) {
					return nil, nil
				}
			case "intent":
				old := d.p.beginFallback
				d.p.beginFallback = func(ctx context.Context, n, a, b uuid.UUID, s string) (*sharedpg.FallbackUseIntent, error) {
					i, err := old(ctx, n, a, b, s)
					i.FallbackTunnel = uuid.New()
					return i, err
				}
			case "fetch":
				d.p.fetchFallback = func(context.Context, sharedpg.FallbackUseIntent) (*sharedpg.UnverifiedFallbackRelease, error) {
					return nil, sharedpg.ErrQuery
				}
			case "nil-graph":
				d.p.fetchFallback = func(context.Context, sharedpg.FallbackUseIntent) (*sharedpg.UnverifiedFallbackRelease, error) {
					return nil, nil
				}
			case "source-proof":
				d.wire["source"].(map[string]any)["metadata"].(map[string]any)["chain"].([]any)[0].([]any)[11] = hex.EncodeToString(make([]byte, 64))
				wantFloor = true
			case "target-proof":
				d.wire["target"].([]any)[11] = hex.EncodeToString(make([]byte, 64))
			case "target-cipher":
				row := d.wire["values"].([]any)[0].([]any)
				raw, _ := hex.DecodeString(row[8].(string))
				e, err := vault.DecodeSharedEnvelope(raw)
				if err != nil {
					t.Fatal(err)
				}
				e.Ciphertext[0] ^= 1
				raw, _ = vault.EncodeSharedEnvelope(e)
				row[8] = hex.EncodeToString(raw)
				wantFloor = true
			case "reference":
				source := d.wire["source"].(map[string]any)
				for _, entry := range source["accounts"].([]any) {
					a := entry.(map[string]any)
					if a["account"] != "tunnel" {
						continue
					}
					row := a["values"].([]any)[0].([]any)
					b := vault.SharedValueBinding{WorkspaceID: d.binding.WorkspaceID, OwnerKind: "tunnel", OwnerID: uuid.MustParse(row[1].(string)), Field: "settings", Version: 1, DEK: vault.KeyRef{ID: uuid.MustParse(row[6].(string)), Version: 1}}
					plain, _ := json.Marshal(map[string]any{"Host": "ipsec.test", "PreSharedKey": "primary-secret", "UserAuth": 0, "FallbackTunnelId": uuid.NewString()})
					e, err := vault.SealSharedValue(bytes.Repeat([]byte{24}, 32), b, plain)
					if err != nil {
						t.Fatal(err)
					}
					raw, _ := vault.EncodeSharedEnvelope(e)
					row[8] = hex.EncodeToString(raw)
				}
				wantFloor = true
			case "pair-primary":
				pair := d.pair
				pair.Primary.Host = "different.example"
				body["binding"] = pair
				wantFloor = true
			case "pair-target":
				pair := d.pair
				pair.Fallback.RowVersion++
				body["binding"] = pair
				wantFloor = true
			case "cancel-fetch":
				old := d.p.fetchFallback
				d.p.fetchFallback = func(ctx context.Context, i sharedpg.FallbackUseIntent) (*sharedpg.UnverifiedFallbackRelease, error) {
					g, err := old(ctx, i)
					cancel()
					return g, err
				}
			case "cancel-anchor":
				old := d.c.catalogAnchor
				d.c.catalogAnchor = func(ctx context.Context, path string, key []byte, b sharedpg.TrustBinding, s sharedpg.TrustState) error {
					err := old(ctx, path, key, b, s)
					if s.Catalog["tunnel/"+d.pair.Fallback.TunnelConfigID].Revision > 0 {
						cancel()
					}
					return err
				}
				wantFloor = true
			case "short-key":
				if err := d.c.privateKeys.Close(); err != nil {
					t.Fatal(err)
				}
				var err error
				d.c.privateKeys, err = securemem.New(32, false)
				if err != nil {
					t.Fatal(err)
				}
				wantFloor = true
			}
			raw, err := d.h.Handle(ctx, "tunnel-fallback-bundle", vaultInput(t, body))
			if err == nil || raw != nil || d.c.Unlocked() || !d.h.closed {
				t.Fatal("shared denial published or left usable owner", err)
			}
			stored, readErr := readSharedTrustFile(d.path, d.root, d.binding, d.initial)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if (stored.Catalog["tunnel/"+d.pair.Fallback.TunnelConfigID].Revision > 0) != wantFloor {
				t.Fatal("independent authenticated target observation mismatch", mode, err)
			}
		})
	}
}

func TestSharedFallbackPlanningKeepsTargetCiphertextClosed(t *testing.T) {
	d := sharedFallbackFixture(t)
	row := d.wire["values"].([]any)[0].([]any)
	raw, _ := hex.DecodeString(row[8].(string))
	envelope, err := vault.DecodeSharedEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Ciphertext[0] ^= 1
	raw, _ = vault.EncodeSharedEnvelope(envelope)
	row[8] = hex.EncodeToString(raw)
	if _, err := d.h.Handle(context.Background(), "tunnel-fallback-plan", vaultInput(t, d.body(false))); err != nil {
		t.Fatal("plan opened target", err)
	}
	raw, err = d.h.Handle(context.Background(), "tunnel-fallback-bundle", vaultInput(t, d.body(true)))
	if err == nil || raw != nil {
		t.Fatal("corrupt target admitted")
	}
}

func TestSharedFallbackNativeInputAndUnsupportedSessionBoundaries(t *testing.T) {
	d := sharedFallbackFixture(t)
	ctx := context.Background()
	bad := d.q
	bad.NodeID = "bad"
	if _, err := d.c.PlanConnectionFallback(ctx, bad, d.pair.Primary, d.pair.Fallback.RequestID, d.h.shared.fileID, "ui"); err == nil {
		t.Fatal("bad request")
	}
	if _, err := d.c.PlanConnectionFallback(nil, d.q, d.pair.Primary, d.pair.Fallback.RequestID, d.h.shared.fileID, "ui"); err == nil {
		t.Fatal("nil context")
	}
	if _, err := d.c.PlanConnectionFallback(ctx, d.q, d.pair.Primary, d.q.RequestID, d.h.shared.fileID, "ui"); err == nil {
		t.Fatal("same attempt")
	}
	bad = d.q
	bad.CredentialOverride = uuid.NewString()
	if _, err := d.c.PlanConnectionFallback(ctx, bad, d.pair.Primary, d.pair.Fallback.RequestID, d.h.shared.fileID, "ui"); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	if _, err := d.c.SealConnectionFallback(ctx, bad, d.pair, d.public, d.h.shared.fileID, "ui"); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	if _, err := d.c.SealConnectionFallback(ctx, d.q, d.pair, nil, d.h.shared.fileID, "ui"); err == nil {
		t.Fatal("missing recipient")
	}
	pair := d.pair
	pair.Fallback.TunnelConfigID = "bad"
	if _, err := d.c.SealConnectionFallback(ctx, d.q, pair, d.public, d.h.shared.fileID, "ui"); err == nil {
		t.Fatal("invalid target")
	}
	if err := d.c.withFallbackRelease(nil, uuid.New(), uuid.New(), uuid.New(), "ui", nil); err != sharedpg.ErrConfiguration {
		t.Fatal(err)
	}
	d.c.session = d.p.credentialReleaseProbe
	if _, err := d.c.SealConnectionFallback(ctx, d.q, d.pair, d.public, d.h.shared.fileID, "ui"); err != sharedpg.ErrConfiguration {
		t.Fatal("unsupported session", err)
	}
}
