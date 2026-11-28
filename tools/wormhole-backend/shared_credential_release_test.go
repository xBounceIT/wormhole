package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type credentialReleaseProbe struct {
	*catalogProbe
	begin   func(context.Context, uuid.UUID, string) (*sharedpg.UseIntent, error)
	fetch   func(context.Context, sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error)
	plan    func(context.Context, uuid.UUID) (*sharedpg.UnverifiedConnectionPlan, error)
	runtime func(context.Context) (*sharedpg.UnverifiedRuntimeState, error)
}

func (p *credentialReleaseProbe) RuntimeState(ctx context.Context) (*sharedpg.UnverifiedRuntimeState, error) {
	return p.runtime(ctx)
}

func (p *credentialReleaseProbe) ConnectionPlan(ctx context.Context, node uuid.UUID) (*sharedpg.UnverifiedConnectionPlan, error) {
	return p.plan(ctx, node)
}

func (p *credentialReleaseProbe) BeginUse(ctx context.Context, n uuid.UUID, source string) (*sharedpg.UseIntent, error) {
	return p.begin(ctx, n, source)
}
func (p *credentialReleaseProbe) FetchSecret(ctx context.Context, i sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
	return p.fetch(ctx, i)
}

func credentialControllerFixture(t *testing.T, profiles ...vault.Profile) (*sharedAdmissionController, *credentialReleaseProbe, sharedAdmissionOptions, []byte, *sharedpg.UnverifiedAccountKeys, ed25519.PrivateKey, uuid.UUID, map[string]any) {
	t.Helper()
	c, p, o, root, account, org := catalogControllerFixture(t, profiles...)
	return installCredentialControllerFixture(t, c, p, o, root, account, org)
}

func installCredentialControllerFixture(t *testing.T, c *sharedAdmissionController, p *catalogProbe, o sharedAdmissionOptions, root []byte, account *sharedpg.UnverifiedAccountKeys, org ed25519.PrivateKey) (*sharedAdmissionController, *credentialReleaseProbe, sharedAdmissionOptions, []byte, *sharedpg.UnverifiedAccountKeys, ed25519.PrivateKey, uuid.UUID, map[string]any) {
	t.Helper()
	var key ed25519.PrivateKey
	if err := c.privateKeys.With(func(raw []byte) error { key = ed25519.NewKeyFromSeed(raw[32:]); return nil }); err != nil {
		t.Fatal(err)
	}
	enrolled := account.EnrollmentCertificate != nil
	var enrollmentHex string
	var encryptionPublic []byte
	if enrolled {
		raw, err := vault.EncodeUserEnrollmentCertificate(*account.EnrollmentCertificate)
		if err != nil {
			t.Fatal(err)
		}
		enrollmentHex = hex.EncodeToString(raw)
		encryptionPublic = account.EnrollmentCertificate.Rekey.Public.Encryption
	} else {
		encryptionPublic = account.EncryptionCertificate.PublicKey
	}
	defer vault.Wipe(key)
	boundary, node, credential := uuid.New(), uuid.New(), uuid.New()
	host, protocol, mode := "server.example", 0, 2
	id := credential.String()
	n := vaultstore.NodeMetadata{ID: node.String(), Name: "Node", Kind: 1, Protocol: &protocol, Host: &host, CredentialMode: &mode, CredentialID: &id}
	nseal, e := sharedcatalog.SignNode(o.Binding.WorkspaceID, boundary, n, 1, account.Binding.Signing, key)
	if e != nil {
		t.Fatal(e)
	}
	profile := sharedcatalog.CredentialRecord{Metadata: vaultstore.CredentialMetadata{ID: id, Name: "Account", Protocol: "ssh", Kind: "password", Provider: "local", Username: "account"}, Fields: []vaultstore.CredentialField{{Field: "password", Version: 9, Present: true}}}
	cseal, e := sharedcatalog.SignCredential(o.Binding.WorkspaceID, boundary, profile, 1, account.Binding.Signing, key)
	if e != nil {
		t.Fatal(e)
	}
	state, e := vault.EncodeUserKeyState(*account.State)
	if e != nil {
		t.Fatal(e)
	}
	str := func(v uint64) string { return strconv.FormatUint(v, 10) }
	row := func(id string, body any, seal vault.RecordSeal) []any {
		b, _ := json.Marshal(body)
		cert := account.SigningCertificate
		r := []any{o.Binding.WorkspaceID.String(), id, "1", "9", string(b), boundary.String(), "1", "2", seal.SignerKeyID, str(uint64(seal.SignerKeyVersion)), nil, hex.EncodeToString(seal.Signature), o.Binding.UserID.String(), account.Binding.Signing.ID.String(), str(uint64(account.Binding.Signing.Version)), str(account.State.Sequence), hex.EncodeToString(state), nil, nil, nil, nil, nil, nil}
		if enrolled {
			return append(r, enrollmentHex)
		}
		r[17], r[18], r[19], r[20], r[21], r[22] = "1", hex.EncodeToString(cert.PublicKey), cert.Signer.ID.String(), str(uint64(cert.Signer.Version)), str(cert.Revision), hex.EncodeToString(cert.Signature)
		return r
	}
	plan, e := resolver.Resolve([]vaultstore.NodeMetadata{n}, "")
	if e != nil {
		t.Fatal(e)
	}
	plan, e = resolver.ApplyCredential(plan, profile.Metadata)
	if e != nil {
		t.Fatal(e)
	}
	viewPrivate, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{3}, 32))
	secretPrivate, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{4}, 32))
	m := vault.BoundaryManifest{FormatVersion: 1, WorkspaceID: o.Binding.WorkspaceID, BoundaryID: boundary, Revision: 1, OrgEscrow: true, Active: true, View: vault.BoundaryKey{Key: vault.KeyRef{ID: uuid.New(), Version: 1}, Public: viewPrivate.PublicKey().Bytes()}, Secret: vault.BoundaryKey{Key: vault.KeyRef{ID: uuid.New(), Version: 1}, Public: secretPrivate.PublicKey().Bytes()}, Signer: account.State.Signer}
	m, e = vault.SignBoundaryManifest(m, org)
	if e != nil {
		t.Fatal(e)
	}
	manifest, e := vault.EncodeBoundaryManifest(m)
	if e != nil {
		t.Fatal(e)
	}
	metadata := map[string]any{"formatVersion": 1, "workspaceId": o.Binding.WorkspaceID.String(), "userId": o.Binding.UserID.String(), "nodeId": node.String(), "epoch": "1", "changeSeq": "9", "plan": plan, "chain": []any{row(node.String(), n, nseal)}, "override": nil, "slot": nil, "slotValue": nil, "credential": row(id, profile, cseal), "gateway": nil, "boundaries": []any{[]any{o.Binding.WorkspaceID.String(), boundary.String(), "1", "9", "1", hex.EncodeToString(manifest), m.Signer.ID.String(), str(uint64(m.Signer.Version)), hex.EncodeToString(m.Signature)}}}
	copyWire := func(b vault.KeyCopyBinding, plain, recipient []byte, member bool) []any {
		seed := org.Seed()
		if member {
			vault.Wipe(seed)
			seed = key.Seed()
		}
		defer vault.Wipe(seed)
		copy, e := vault.SealKeyCopy(plain, b, recipient, seed)
		if e != nil {
			t.Fatal(e)
		}
		r := []any{o.Binding.WorkspaceID.String(), "1", "9", b.Key.ID.String(), str(uint64(b.Key.Version)), b.Holder.ID.String(), str(uint64(b.Holder.Version)), "2", hex.EncodeToString(copy.Envelope.Enc), hex.EncodeToString(copy.Envelope.Ciphertext), b.Issuer.ID.String(), str(uint64(b.Issuer.Version)), hex.EncodeToString(copy.Signature), "org-sign", nil, nil, nil, nil, nil, nil, nil, nil, nil}
		if member {
			cert := account.SigningCertificate
			r[13], r[14], r[15], r[16] = "user-sign", o.Binding.UserID.String(), str(account.State.Sequence), hex.EncodeToString(state)
			if !enrolled {
				r[17], r[18], r[19], r[20], r[21], r[22] = "1", hex.EncodeToString(cert.PublicKey), cert.Signer.ID.String(), str(uint64(cert.Signer.Version)), str(cert.Revision), hex.EncodeToString(cert.Signature)
			}
		}
		if enrolled {
			var value any
			if member {
				value = enrollmentHex
			}
			r = append(r, value)
		}
		return r
	}
	dek := vault.KeyRef{ID: uuid.New(), Version: 1}
	binding := vault.SharedValueBinding{WorkspaceID: o.Binding.WorkspaceID, OwnerKind: "credential", OwnerID: credential, Field: "password", Version: 9, DEK: dek}
	value, e := vault.SealSharedValue(bytes.Repeat([]byte{23}, 32), binding, []byte("native-connection-secret"))
	if e != nil {
		t.Fatal(e)
	}
	envelope, e := vault.EncodeSharedEnvelope(value)
	if e != nil {
		t.Fatal(e)
	}
	rootCopy := copyWire(vault.KeyCopyBinding{WorkspaceID: o.Binding.WorkspaceID, Key: m.Secret.Key, Holder: account.Binding.Encryption, Issuer: m.Signer}, secretPrivate.Bytes(), encryptionPublic, false)
	dekCopy := copyWire(vault.KeyCopyBinding{WorkspaceID: o.Binding.WorkspaceID, Key: dek, Holder: m.Secret.Key, Issuer: account.Binding.Signing}, bytes.Repeat([]byte{23}, 32), m.Secret.Public, true)
	wire := map[string]any{"formatVersion": 2, "profile": hex.EncodeToString(p.response.SignedProfile), "metadata": metadata, "account": []any{str(account.State.Sequence), hex.EncodeToString(state)}, "roots": []any{rootCopy}, "accounts": []any{map[string]any{"account": "primary", "values": []any{[]any{o.Binding.WorkspaceID.String(), id, "1", "9", "password", "9", dek.ID.String(), "1", hex.EncodeToString(envelope)}}, "copies": []any{dekCopy}}}}
	if enrolled {
		metadata["formatVersion"] = 3
		metadata["tunnel"] = nil
		wire["formatVersion"] = 5
		wire["enrollment"] = enrollmentHex
		wire["nodeFields"] = nil
	}

	probe := &credentialReleaseProbe{catalogProbe: p}
	probe.begin = func(_ context.Context, n uuid.UUID, source string) (*sharedpg.UseIntent, error) {
		if n != node || (source != "ui" && source != "mcp") {
			t.Error("audit binding")
		}
		return &sharedpg.UseIntent{Ticket: uuid.New(), Node: n, Epoch: 1, ChangeSeq: 9, ExpiresAt: 1800000000}, nil
	}
	probe.fetch = func(_ context.Context, i sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
		raw, _ := json.Marshal(wire)
		return sharedpg.DecodeCredentialRelease(raw, o.Request, i.Node, i.Epoch, i.ChangeSeq)
	}
	probe.plan = func(_ context.Context, node uuid.UUID) (*sharedpg.UnverifiedConnectionPlan, error) {
		raw, _ := json.Marshal(map[string]any{"formatVersion": 1, "profile": wire["profile"], "account": wire["account"], "metadata": wire["metadata"]})
		return sharedpg.DecodeConnectionPlan(raw, o.Request, node, 1, 9)
	}
	probe.runtime = func(context.Context) (*sharedpg.UnverifiedRuntimeState, error) {
		raw, _ := json.Marshal(map[string]any{"formatVersion": 1, "profile": wire["profile"], "account": wire["account"]})
		return sharedpg.DecodeRuntimeState(raw, o.Request)
	}
	c.session = probe
	// Release graphs carry account state themselves; a separate read would
	// break snapshot coherence and add an unnecessary account request.
	probe.accountState = func(context.Context) (*vault.UserKeyState, error) {
		t.Error("separate release account read")
		return nil, errors.New("unexpected account read")
	}
	return c, probe, o, root, account, org, node, wire
}

func TestSharedCredentialReleaseCommitsBeforeOpening(t *testing.T) {
	c, p, o, root, _, _, node, _ := credentialControllerFixture(t)
	initial := c.trustRevision
	var events []string
	oldBegin, oldFetch, oldAnchor := p.begin, p.fetch, c.catalogAnchor
	p.begin = func(ctx context.Context, n uuid.UUID, source string) (*sharedpg.UseIntent, error) {
		events = append(events, "begin")
		return oldBegin(ctx, n, source)
	}
	p.fetch = func(ctx context.Context, i sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
		events = append(events, "fetch")
		return oldFetch(ctx, i)
	}
	// Wrong private material becomes usable only from the successful anchor
	// callback. Opening before that callback would fail HPKE authentication.
	if e := c.privateKeys.With(func(keys []byte) error { copy(keys[:32], bytes.Repeat([]byte{17}, 32)); return nil }); e != nil {
		t.Fatal(e)
	}
	c.catalogAnchor = func(ctx context.Context, path string, key []byte, binding sharedpg.TrustBinding, trust sharedpg.TrustState) error {
		if e := oldAnchor(ctx, path, key, binding, trust); e != nil {
			return e
		}
		if trust.Revision != initial+1 || trust.Catalog["node/"+node.String()].Revision != 1 {
			t.Fatal("incomplete committed observations")
		}
		events = append(events, "anchor")
		return c.privateKeys.With(func(keys []byte) error { copy(keys[:32], bytes.Repeat([]byte{33}, 32)); return nil })
	}
	recipientBytes := bytes.Repeat([]byte{31}, 32)
	defer vault.Wipe(recipientBytes)
	recipient, _ := ecdh.X25519().NewPrivateKey(recipientBytes)
	var opaque vault.SealedBundle
	var binding vault.BundleBinding
	var borrowed []byte
	e := c.WithConnectionCredentials(context.Background(), node, "ui", func(plan resolver.Plan, values sharedpg.CredentialReleaseValues) error {
		events = append(events, "use")
		stored, e := readSharedTrustFile(o.TrustPath, root, o.Binding, initial+1)
		if e != nil || stored.Revision != c.trustRevision {
			t.Fatal("not durably published", e)
		}
		if values.Primary == nil || values.Gateway != nil || string(values.Primary.Fields["password"]) != "native-connection-secret" {
			t.Fatal("incorrect native credential")
		}
		borrowed = values.Primary.Fields["password"]
		binding = vault.BundleBinding{WorkspaceID: o.Binding.WorkspaceID.String(), SessionID: uuid.NewString(), RequestID: uuid.NewString(), NodeID: node.String(), Protocol: "ssh", Host: plan.Host, Port: uint16(plan.Port), Epoch: 1}
		frame, e := vault.EncodeSSHBundle(vault.SSHBundlePayload{Username: plan.Username, Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), Password: borrowed})
		if e != nil {
			return e
		}
		defer vault.Wipe(frame)
		opaque, e = vault.SealBundle(recipient.PublicKey().Bytes(), binding, frame)
		return e
	})
	if e != nil || !reflect.DeepEqual(events, []string{"begin", "fetch", "anchor", "use"}) || !c.Unlocked() {
		t.Fatal("release order", events, e)
	}
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("plaintext retained after protocol sealing")
	}
	plain, e := vault.OpenBundle(recipientBytes, binding, opaque)
	if e != nil {
		t.Fatal(e)
	}
	defer vault.Wipe(plain)
	decoded, e := vault.DecodeSSHBundle(plain)
	if e != nil || string(decoded.Password) != "native-connection-secret" {
		t.Fatal("HPKE recipient", e)
	}
	before := c.trustRevision
	if e := c.WithConnectionCredentials(context.Background(), node, "mcp", func(resolver.Plan, sharedpg.CredentialReleaseValues) error { return nil }); e != nil || c.trustRevision != before {
		t.Fatal("repeat with fresh ticket", e)
	}
}

func TestSharedCredentialReleaseErrors(t *testing.T) {
	for _, mode := range []string{"begin", "nil-intent", "wrong-intent", "fetch", "nil-graph", "forged", "revoked", "rotated", "policy", "anchor", "anchor-uncertain", "storage", "cipher", "callback", "cancel-fetch", "cancel-anchor", "short-key", "panic-read", "panic-use", "cleanup"} {
		t.Run(mode, func(t *testing.T) {
			c, p, o, root, account, org, node, wire := credentialControllerFixture(t)
			initial := c.trustRevision
			fixtureError := errors.New("release fixture failure")
			want := error(fixtureError)
			var borrowed []byte
			called := false
			metadata := wire["metadata"].(map[string]any)
			switch mode {
			case "begin":
				p.begin = func(context.Context, uuid.UUID, string) (*sharedpg.UseIntent, error) { return nil, fixtureError }
			case "nil-intent":
				p.begin = func(context.Context, uuid.UUID, string) (*sharedpg.UseIntent, error) { return nil, nil }
				want = sharedpg.ErrAdmissionResponse
			case "wrong-intent":
				old := p.begin
				p.begin = func(ctx context.Context, n uuid.UUID, s string) (*sharedpg.UseIntent, error) {
					i, e := old(ctx, n, s)
					i.Node = uuid.New()
					return i, e
				}
				want = sharedpg.ErrAdmissionResponse
			case "fetch":
				p.fetch = func(context.Context, sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
					return nil, fixtureError
				}
			case "nil-graph":
				p.fetch = func(context.Context, sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
					return nil, nil
				}
				want = sharedpg.ErrAdmissionResponse
			case "forged", "cleanup":
				row := metadata["chain"].([]any)[0].([]any)
				row[11] = hex.EncodeToString(make([]byte, 64))
				want = vault.ErrAuthentication
			case "revoked", "rotated":
				state := *account.State
				state.Sequence++
				if mode == "revoked" {
					state.Active = false
					want = vault.ErrPolicy
				} else {
					state.Encryption.Version++
					for _, root := range wire["roots"].([]any) {
						root.([]any)[6] = strconv.FormatUint(uint64(state.Encryption.Version), 10)
					}
					want = vault.ErrAuthentication
				}
				state, e := vault.SignUserKeyState(state, org)
				if e != nil {
					t.Fatal(e)
				}
				raw, _ := vault.EncodeUserKeyState(state)
				wire["account"] = []any{strconv.FormatUint(state.Sequence, 10), hex.EncodeToString(raw)}
			case "anchor":
				c.catalogAnchor = func(context.Context, string, []byte, sharedpg.TrustBinding, sharedpg.TrustState) error {
					return fixtureError
				}
			case "policy":
				policy, e := vault.DecodeSignedPolicy(p.response.SignedProfile)
				if e != nil {
					t.Fatal(e)
				}
				policy.Policy.Sequence++
				policy, e = vault.SignPolicy(policy.Policy, policy.SignerKeyID, policy.SignerKeyVersion, org)
				if e != nil {
					t.Fatal(e)
				}
				raw, _ := vault.EncodeSignedPolicy(policy)
				wire["profile"] = hex.EncodeToString(raw)
				want = sharedpg.ErrProfileChanged
			case "anchor-uncertain":
				c.catalogAnchor = func(context.Context, string, []byte, sharedpg.TrustBinding, sharedpg.TrustState) error {
					return errSharedTrustCommitUncertain
				}
				want = errSharedTrustCommitUncertain
			case "storage":
				old := privateFileDirectorySync
				t.Cleanup(func() { privateFileDirectorySync = old })
				privateFileDirectorySync = func(string) error { return fixtureError }
				want = errSharedTrustCommitUncertain
			case "cipher":
				a := wire["accounts"].([]any)[0].(map[string]any)
				row := a["values"].([]any)[0].([]any)
				raw, _ := hex.DecodeString(row[8].(string))
				envelope, e := vault.DecodeSharedEnvelope(raw)
				if e != nil {
					t.Fatal(e)
				}
				envelope.Ciphertext[0] ^= 1
				raw, _ = vault.EncodeSharedEnvelope(envelope)
				row[8] = hex.EncodeToString(raw)
				want = vault.ErrAuthentication
			case "cancel-fetch":
				p.fetch = func(ctx context.Context, _ sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
					c.cancel()
					<-ctx.Done()
					return nil, ctx.Err()
				}
				want = context.Canceled
			case "cancel-anchor":
				old := c.catalogAnchor
				fetch := p.fetch
				var operationCtx context.Context
				p.fetch = func(ctx context.Context, intent sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
					operationCtx = ctx
					return fetch(ctx, intent)
				}
				c.catalogAnchor = func(ctx context.Context, path string, key []byte, b sharedpg.TrustBinding, s sharedpg.TrustState) error {
					e := old(ctx, path, key, b, s)
					c.cancel()
					<-operationCtx.Done()
					return e
				}
				want = context.Canceled
			case "short-key":
				if e := c.privateKeys.Close(); e != nil {
					t.Fatal(e)
				}
				var e error
				c.privateKeys, e = securemem.New(32, false)
				if e != nil {
					t.Fatal(e)
				}
				want = sharedpg.ErrTrustState
			case "panic-read":
				p.begin = func(context.Context, uuid.UUID, string) (*sharedpg.UseIntent, error) { panic(fixtureError) }
			}
			if mode == "cleanup" {
				p.closeFailure.Store(true)
				t.Cleanup(func() { p.closeFailure.Store(false); _ = c.Close(context.Background()) })
				want = errSharedAdmissionCleanup
			}
			use := func(_ resolver.Plan, values sharedpg.CredentialReleaseValues) error {
				called = true
				borrowed = values.Primary.Fields["password"]
				if mode == "panic-use" {
					panic(fixtureError)
				}
				return fixtureError
			}
			if mode == "panic-read" || mode == "panic-use" {
				func() {
					defer func() {
						if recover() != fixtureError {
							t.Fatal("panic changed")
						}
					}()
					_ = c.WithConnectionCredentials(context.Background(), node, "ui", use)
				}()
			} else if e := c.WithConnectionCredentials(context.Background(), node, "ui", use); e != want {
				t.Fatal("release failure", mode, e, want)
			}
			if called != (mode == "callback" || mode == "panic-use") {
				t.Fatal("plaintext callback reached before complete commit/open", mode)
			}
			if c.Unlocked() {
				t.Fatal("failed owner remained unlocked")
			}
			if mode != "cleanup" && (c.privateKeys != nil || c.root != nil) {
				t.Fatal("failed owner retained keys")
			}
			if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("failed callback retained plaintext")
			}
			if mode == "revoked" || mode == "rotated" {
				stored, e := readSharedTrustFile(o.TrustPath, root, o.Binding, initial+1)
				if e != nil || stored.Account.Sequence != account.State.Sequence+1 {
					t.Fatal("authenticated observation lost", e)
				}
			}
			if mode == "policy" {
				stored, e := readSharedTrustFile(o.TrustPath, root, o.Binding, initial+1)
				if e != nil || stored.PolicySequence != 2 || len(stored.Catalog) != 0 {
					t.Fatal("new policy floor lost or continued release", e)
				}
			}
		})
	}
}

func TestSharedCredentialReleaseReadPanicPersistsWithoutUse(t *testing.T) {
	c, _, o, root, account, org, _, _ := credentialControllerFixture(t)
	initial := c.trustRevision
	state := *account.State
	state.Sequence++
	state.Active = false
	state, e := vault.SignUserKeyState(state, org)
	if e != nil {
		t.Fatal(e)
	}
	failure := errors.New("read panic")
	func() {
		defer func() {
			if recover() != failure {
				t.Fatal("panic lost")
			}
		}()
		_ = c.withCatalogOperation(context.Background(), func(_ context.Context, current sharedpg.TrustState, pending *sharedpg.TrustState) error {
			next, e := current.AdvanceAccount(state, current.WrappingRevision)
			if e != nil {
				t.Fatal(e)
			}
			*pending = next
			panic(failure)
		}, func(context.Context, sharedpg.TrustState) error {
			t.Fatal("use ran while unwinding read panic")
			return nil
		}, false)
	}()
	stored, e := readSharedTrustFile(o.TrustPath, root, o.Binding, initial+1)
	if e != nil || stored.Account.Active || stored.Account.Sequence != state.Sequence || c.Unlocked() || c.privateKeys != nil {
		t.Fatal("panic lost revocation or retained owner", e)
	}
}

func TestSharedCredentialReleaseValidationAndClose(t *testing.T) {
	c, p, _, _, _, _, node, _ := credentialControllerFixture(t)
	use := func(resolver.Plan, sharedpg.CredentialReleaseValues) error { return nil }
	for _, call := range []func() error{func() error { return c.WithConnectionCredentials(nil, node, "ui", use) }, func() error { return c.WithConnectionCredentials(context.Background(), uuid.Nil, "ui", use) }, func() error { return c.WithConnectionCredentials(context.Background(), node, "UI", use) }, func() error { return c.WithConnectionCredentials(context.Background(), node, "ui", nil) }, func() error { return c.withCatalogOperation(nil, nil, nil, false) }} {
		if e := call(); e != sharedpg.ErrConfiguration {
			t.Fatal(e)
		}
	}
	old := c.session
	c.session = p.sharedAdmissionProbe
	if e := c.WithConnectionCredentials(context.Background(), node, "ui", use); e != sharedpg.ErrConfiguration {
		t.Fatal(e)
	}
	c.session = old
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if e := c.WithConnectionCredentials(cancelled, node, "ui", use); e != context.Canceled {
		t.Fatal(e)
	}
	entered := make(chan struct{})
	p.fetch = func(ctx context.Context, _ sharedpg.UseIntent) (*sharedpg.UnverifiedCredentialRelease, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	finished := make(chan error, 1)
	go func() { finished <- c.WithConnectionCredentials(context.Background(), node, "ui", use) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("fetch not entered")
	}
	ctx, cancelClose := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelClose()
	if e := c.Close(ctx); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-finished:
		if e != context.Canceled {
			t.Fatal(e)
		}
	case <-ctx.Done():
		t.Fatal("release gate retained")
	}
	if e := c.WithConnectionCredentials(context.Background(), node, "ui", use); e != sharedpg.ErrSessionClosed && e != context.Canceled {
		t.Fatal("closed owner release", e)
	}
}
