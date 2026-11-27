package sharedpg

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func openReleaseFixture(t *testing.T, kind string, member, previous bool) (connectionFixture, *UnverifiedCredentialRelease, TrustState, *VerifiedCredentialRelease) {
	t.Helper()
	f, w := releaseGraphFixture(t, kind, member, previous)
	raw, _ := json.Marshal(w)
	g, e := DecodeCredentialRelease(raw, AdmissionRequest{WorkspaceID: f.s.WorkspaceID, UserID: f.s.UserID}, f.node(), 1, 7)
	if e != nil {
		t.Fatal(e)
	}
	vault.Wipe(raw)
	next, v, e := f.s.VerifyCredentialRelease(context.Background(), f.node(), g)
	if e != nil {
		t.Fatal(e)
	}
	return f, g, next, v
}

func assertReleaseWiped(t *testing.T, fields [][]byte) {
	t.Helper()
	for _, v := range fields {
		if !bytes.Equal(v, make([]byte, len(v))) {
			t.Fatal("plaintext retained")
		}
	}
}

func TestCredentialReleaseOpening(t *testing.T) {
	for _, kind := range []string{"saved", "gateway", "none"} {
		for _, member := range []bool{false, true} {
			for _, previous := range []bool{false, true} {
				_, g, next, v := openReleaseFixture(t, kind, member, previous)
				// Replacing the exported unverified value must not change preparation.
				*g = UnverifiedCredentialRelease{}
				var borrowed [][]byte
				e := v.WithValues(context.Background(), next, bytes.Repeat([]byte{17}, 32), func(plan resolver.Plan, values CredentialReleaseValues) error {
					if plan.NodeID != v.plan.NodeID {
						t.Fatal("plan changed")
					}
					for i, account := range []*BorrowedCredential{values.Primary, values.Gateway} {
						role := "primary"
						if i == 1 {
							role = "gateway"
						}
						if kind == "none" || i == 1 && kind != "gateway" {
							if account != nil {
								t.Fatal("extra account")
							}
							continue
						}
						if account == nil || string(account.Fields["password"]) != role+"-secret" {
							t.Fatal("wrong account")
						}
						borrowed = append(borrowed, account.Fields["password"])
						wire, _ := json.Marshal(account)
						if bytes.Contains(wire, []byte("-secret")) {
							t.Fatal("plaintext JSON exposure")
						}
						// Wiping must not depend on callback-controlled maps.
						delete(account.Fields, "password")
						account.Fields["password"] = []byte("unowned")
					}
					wire, _ := json.Marshal(values)
					if string(wire) != "{}" {
						t.Fatal("native result marshaled")
					}
					return nil
				})
				if e != nil {
					t.Fatal(kind, member, previous, e)
				}
				assertReleaseWiped(t, borrowed)
				if e := v.WithValues(context.Background(), next, bytes.Repeat([]byte{17}, 32), func(resolver.Plan, CredentialReleaseValues) error { t.Fatal("second use"); return nil }); e != ErrUseTicket {
					t.Fatal("prepared release replay", e)
				}
			}
		}
	}
}

func TestCredentialReleaseOpenErrors(t *testing.T) {
	fixtureError := errors.New("callback failed")
	for _, mode := range []string{"wrong-private", "wrong-seed", "dek", "value", "callback", "panic", "cancel-before", "cancel-during", "cancel-after"} {
		t.Run(mode, func(t *testing.T) {
			f, g, next, v := openReleaseFixture(t, "gateway", true, false)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			private := bytes.Repeat([]byte{17}, 32)
			switch mode {
			case "wrong-private":
				private = bytes.Repeat([]byte{19}, 32)
			case "wrong-seed":
				copy := &v.graph.roots[0]
				copy.Copy, _ = vault.SealKeyCopy(bytes.Repeat([]byte{7}, 32), copy.Binding, func() []byte { k, _ := ecdh.X25519().NewPrivateKey(private); return k.PublicKey().Bytes() }(), f.key.Seed())
			case "dek":
				v.graph.accounts[1].copies[0].Copy.Envelope.Ciphertext[0] ^= 1
			case "value":
				v.graph.accounts[1].values[0].Envelope.Ciphertext[0] ^= 1
			case "cancel-before":
				cancel()
			case "cancel-during":
				ctx = &cancelResolutionContext{Context: ctx, after: 1}
			}
			_ = g
			called := false
			var fields [][]byte
			use := func(_ resolver.Plan, values CredentialReleaseValues) error {
				called = true
				fields = append(fields, values.Primary.Fields["password"], values.Gateway.Fields["password"])
				switch mode {
				case "callback":
					return fixtureError
				case "panic":
					panic(fixtureError)
				case "cancel-after":
					cancel()
				}
				return nil
			}
			if mode == "panic" {
				func() {
					defer func() {
						if recover() != fixtureError {
							t.Fatal("panic lost")
						}
					}()
					_ = v.WithValues(ctx, next, private, use)
				}()
			} else {
				e := v.WithValues(ctx, next, private, use)
				if e == nil {
					t.Fatal("failed opening succeeded")
				}
				if mode == "callback" && e != fixtureError {
					t.Fatal(e)
				}
				if (mode == "cancel-before" || mode == "cancel-during" || mode == "cancel-after") && e != context.Canceled {
					t.Fatal(e)
				}
			}
			if called != (mode == "callback" || mode == "panic" || mode == "cancel-after") {
				t.Fatal("callback reached before full opening", mode)
			}
			assertReleaseWiped(t, fields)
		})
	}
}

func TestCredentialReleaseOpenValidation(t *testing.T) {
	f, _, next, v := openReleaseFixture(t, "saved", true, false)
	use := func(resolver.Plan, CredentialReleaseValues) error { t.Fatal("invalid use"); return nil }
	for _, call := range []func() error{
		func() error { return v.WithValues(nil, next, bytes.Repeat([]byte{17}, 32), use) },
		func() error {
			return (*VerifiedCredentialRelease)(nil).WithValues(context.Background(), next, bytes.Repeat([]byte{17}, 32), use)
		},
		func() error {
			return (&VerifiedCredentialRelease{}).WithValues(context.Background(), next, bytes.Repeat([]byte{17}, 32), use)
		},
		func() error { return v.WithValues(context.Background(), next, nil, use) },
		func() error { return v.WithValues(context.Background(), next, bytes.Repeat([]byte{17}, 32), nil) },
	} {
		if e := call(); e != ErrConfiguration {
			t.Fatal(e)
		}
	}
	for _, state := range []TrustState{{}, f.s, func() TrustState { s := cloneTrustState(next); s.Revision++; return s }()} {
		if e := v.WithValues(context.Background(), state, bytes.Repeat([]byte{17}, 32), use); e != ErrTrustState {
			t.Fatal("uncommitted/different trust", e)
		}
	}
}

func TestCredentialReleaseOneConcurrentOpening(t *testing.T) {
	_, _, next, v := openReleaseFixture(t, "saved", true, false)
	var wg sync.WaitGroup
	var opened atomic.Int32
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- v.WithValues(context.Background(), next, bytes.Repeat([]byte{17}, 32), func(resolver.Plan, CredentialReleaseValues) error { opened.Add(1); return nil })
		}()
	}
	wg.Wait()
	close(results)
	success, spent := 0, 0
	for e := range results {
		if e == nil {
			success++
		} else if e == ErrUseTicket {
			spent++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || spent != 1 || opened.Load() != 1 {
		t.Fatal("double opening")
	}
}

func TestCredentialReleaseMultipleFieldsAndProtocol(t *testing.T) {
	f, g, _, _ := openReleaseFixture(t, "saved", false, false)
	profile := g.metadata.records.Credential
	profile.Credential.Record.Metadata.Kind = "sshKey"
	profile.Credential.Record.Fields = []vaultstore.CredentialField{{Field: "passphrase", Version: 9, Present: true}, {Field: "privateKey", Version: 9, Present: true}}
	var e error
	profile.Credential.Seal, e = sharedcatalog.SignCredential(f.s.WorkspaceID, profile.Credential.Boundary, profile.Credential.Record, 1, profile.Author.Key, f.key)
	if e != nil {
		t.Fatal(e)
	}
	root := g.accounts[0].copies[0].Binding.Holder
	var manifest vault.BoundaryManifest
	for _, m := range g.metadata.manifests {
		if m.BoundaryID == g.accounts[0].boundary {
			manifest = m
		}
	}
	g.accounts[0].values = nil
	g.accounts[0].copies = nil
	for _, field := range []string{"passphrase", "privateKey"} {
		b := vault.SharedValueBinding{WorkspaceID: f.s.WorkspaceID, OwnerKind: "credential", OwnerID: uuid.MustParse(profile.Credential.Record.Metadata.ID), Field: field, Version: 9, DEK: vault.KeyRef{ID: uuid.New(), Version: 1}}
		cipher, e := vault.SealSharedValue(bytes.Repeat([]byte{23}, 32), b, []byte(field+"-secret"))
		if e != nil {
			t.Fatal(e)
		}
		binding := vault.KeyCopyBinding{WorkspaceID: f.s.WorkspaceID, Key: b.DEK, Holder: root, Issuer: manifest.Signer}
		copy, e := vault.SealKeyCopy(bytes.Repeat([]byte{23}, 32), binding, manifest.Secret.Public, f.org.Seed())
		if e != nil {
			t.Fatal(e)
		}
		g.accounts[0].values = append(g.accounts[0].values, UnverifiedSharedValue{Binding: b, Envelope: cipher})
		g.accounts[0].copies = append(g.accounts[0].copies, UnverifiedKeyCopy{Binding: binding, Copy: copy})
	}
	next, v, e := f.s.VerifyCredentialRelease(context.Background(), f.node(), g)
	if e != nil {
		t.Fatal(e)
	}
	recipientBytes := bytes.Repeat([]byte{31}, 32)
	defer vault.Wipe(recipientBytes)
	recipient, _ := ecdh.X25519().NewPrivateKey(recipientBytes)
	binding := vault.BundleBinding{WorkspaceID: f.s.WorkspaceID.String(), SessionID: uuid.NewString(), RequestID: uuid.NewString(), NodeID: f.node().String(), Protocol: "ssh", Host: v.plan.Host, Port: uint16(v.plan.Port), Epoch: 1}
	var opaque vault.SealedBundle
	var borrowed [][]byte
	e = v.WithValues(context.Background(), next, bytes.Repeat([]byte{17}, 32), func(plan resolver.Plan, values CredentialReleaseValues) error {
		p := values.Primary
		if len(p.Fields) != 2 || string(p.Fields["privateKey"]) != "privateKey-secret" {
			t.Fatal("root cache/multiple fields")
		}
		borrowed = append(borrowed, p.Fields["passphrase"], p.Fields["privateKey"])
		frame, e := vault.EncodeSSHBundle(vault.SSHBundlePayload{Username: plan.Username, Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), PrivateKey: p.Fields["privateKey"], Passphrase: p.Fields["passphrase"]})
		if e != nil {
			return e
		}
		defer vault.Wipe(frame)
		opaque, e = vault.SealBundle(recipient.PublicKey().Bytes(), binding, frame)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	assertReleaseWiped(t, borrowed)
	plain, e := vault.OpenBundle(recipientBytes, binding, opaque)
	if e != nil {
		t.Fatal(e)
	}
	defer vault.Wipe(plain)
	payload, e := vault.DecodeSSHBundle(plain)
	if e != nil || string(payload.PrivateKey) != "privateKey-secret" || string(payload.Passphrase) != "passphrase-secret" {
		t.Fatal("protocol handoff", e)
	}
}

func TestCredentialReleasePublicPlan(t *testing.T) {
	for _, v := range []*VerifiedCredentialRelease{nil, {}} {
		p, e := v.Plan()
		if e != ErrConfiguration || p != (resolver.Plan{}) {
			t.Fatal("unverified plan", e)
		}
	}
	_, _, _, v := openReleaseFixture(t, "saved", false, false)
	p, e := v.Plan()
	if e != nil || p != v.plan {
		t.Fatal("verified public plan", e)
	}
	p.Host = "modified"
	again, e := v.Plan()
	if e != nil || again.Host == p.Host {
		t.Fatal("mutable prepared plan", e)
	}
}

func TestCredentialReleaseRDPSettings(t *testing.T) {
	for _, value := range []*VerifiedCredentialRelease{nil, {}, {graph: &UnverifiedCredentialRelease{}}} {
		if _, err := value.RDPSettings(); err != ErrConfiguration {
			t.Fatal("unverified RDP settings", err)
		}
	}
	_, _, _, wrongProtocol := openReleaseFixture(t, "saved", false, false)
	if _, err := wrongProtocol.RDPSettings(); err != ErrConfiguration {
		t.Fatal("non-RDP settings", err)
	}
	_, _, _, verified := openReleaseFixture(t, "gateway", false, false)
	settings, err := verified.RDPSettings()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := verified.Plan()
	if err != nil || settings.GatewayHostname != plan.GatewayHost || settings.GatewayUsageMethod != plan.GatewayMethod || settings.Domain != plan.Domain || settings.GatewayCredentialID != plan.GatewayCredentialID || settings.GatewayUseSameCreds != plan.GatewaySameCredentials {
		t.Fatal("authenticated account policy was not projected", err)
	}
	if settings.ColorDepth != vault.DefaultRDPSettings().ColorDepth {
		t.Fatal("missing inherited default")
	}
	settings.Domain, settings.ScreenSize = "changed", "1024x768"
	again, err := verified.RDPSettings()
	if err != nil || again.Domain == "changed" || again.ScreenSize == "1024x768" {
		t.Fatal("mutable settings escaped", err)
	}
	verified.plan.GatewayMethod = 99
	if _, err := verified.RDPSettings(); err == nil {
		t.Fatal("invalid native policy was normalized silently")
	}
}

func TestCredentialReleaseGatewayOnlyNeverOpensPrimary(t *testing.T) {
	for _, member := range []bool{false, true} {
		_, _, next, v := openReleaseFixture(t, "gateway", member, false)
		for i := range v.graph.accounts {
			if v.graph.accounts[i].role == "primary" {
				v.graph.accounts[i].values[0].Envelope.Ciphertext[0] ^= 1
			}
		}
		var fields [][]byte
		err := v.WithGatewayValues(context.Background(), next, bytes.Repeat([]byte{17}, 32), func(_ resolver.Plan, values CredentialReleaseValues) error {
			if values.Primary != nil || values.Inline != nil || values.Tunnel != nil || values.Gateway == nil || string(values.Gateway.Fields["password"]) != "gateway-secret" {
				t.Fatal("wrong credential selection")
			}
			fields = append(fields, values.Gateway.Fields["password"])
			return nil
		})
		if err != nil {
			t.Fatal("unselected primary was decrypted", err)
		}
		assertReleaseWiped(t, fields)
		if err = v.WithValues(context.Background(), next, bytes.Repeat([]byte{17}, 32), func(resolver.Plan, CredentialReleaseValues) error { return nil }); err != ErrUseTicket {
			t.Fatal("gateway release replay", err)
		}
	}
	for _, kind := range []string{"saved", "none"} {
		_, _, next, v := openReleaseFixture(t, kind, false, false)
		if err := v.WithGatewayValues(context.Background(), next, bytes.Repeat([]byte{17}, 32), func(resolver.Plan, CredentialReleaseValues) error { t.Fatal("unselected gateway"); return nil }); err != ErrConfiguration {
			t.Fatal(err)
		}
	}
	if err := (*VerifiedCredentialRelease)(nil).WithGatewayValues(nil, TrustState{}, nil, nil); err != ErrConfiguration {
		t.Fatal(err)
	}
}
