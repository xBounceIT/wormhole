package sharedpg

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"math"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func fallbackSelector(t *testing.T, before func([]byte)) func([]byte) (string, error) {
	t.Helper()
	return func(raw []byte) (string, error) {
		if before != nil {
			before(raw)
		}
		var settings struct {
			Fallback string `json:"FallbackTunnelId"`
		}
		if err := json.Unmarshal(raw, &settings); err != nil {
			return "", err
		}
		return settings.Fallback, nil
	}
}

func TestFallbackOpeningConcurrentAttemptsShareTheSourceOneUseGate(t *testing.T) {
	d := fallbackReleaseFixture(t, true)
	next, v, err := d.f.s.VerifyFallbackRelease(context.Background(), d.f.node(), d.parsed)
	if err != nil {
		t.Fatal(err)
	}
	var opened, rejected atomic.Int32
	var tasks sync.WaitGroup
	for range 8 {
		tasks.Go(func() {
			err := v.WithConfiguration(context.Background(), next, d.private, fallbackSelector(t, nil), func(FallbackSources, []byte) error { opened.Add(1); return nil })
			if err == ErrUseTicket {
				rejected.Add(1)
			} else if err != nil {
				t.Error(err)
			}
		})
	}
	tasks.Wait()
	if opened.Load() != 1 || rejected.Load() != 7 {
		t.Fatal("concurrent target replay", opened.Load(), rejected.Load())
	}
}

func TestFallbackVerifierRetainsIndependentObservationsOnDenial(t *testing.T) {
	for _, mode := range []string{"boundary-inactive", "deleted", "revoked", "bad-source-revoked-target", "copy-proof-new-state", "inconsistent-state"} {
		t.Run(mode, func(t *testing.T) {
			d := fallbackReleaseFixture(t, true)
			g := d.parsed
			switch mode {
			case "boundary-inactive":
				g.manifest.Revision++
				g.manifest.Active = false
				var err error
				g.manifest, err = vault.SignBoundaryManifest(g.manifest, d.f.org)
				if err != nil {
					t.Fatal(err)
				}
			case "deleted":
				r := g.target.Selection.Record.(sharedcatalog.TunnelRecord)
				r.Deleted = true
				g.target.Selection.Record = r
				d.f.signSelection(t, &g.target, 2)
			default:
				state := *g.target.Author.State
				state.Sequence++
				state.Active = mode == "copy-proof-new-state" || mode == "inconsistent-state"
				signed, err := vault.SignUserKeyState(state, d.f.org)
				if err != nil {
					t.Fatal(err)
				}
				g.target.Author.State = &signed
				if mode == "inconsistent-state" {
					g.root.Author.State = &signed
					g.copy.Author.State = &signed
				}
				if mode == "bad-source-revoked-target" {
					s := &g.source.metadata.records.Chain[0].Node.Seal
					s.Signature = bytes.Clone(s.Signature)
					s.Signature[0] ^= 1
				}
				if mode == "copy-proof-new-state" {
					// Valid newer account fact survives a later corrupt copy seal.
					g.root.Author.State = &signed
					g.root.Copy.Signature = bytes.Clone(g.root.Copy.Signature)
					g.root.Copy.Signature[0] ^= 1
				}
			}
			next, v, err := d.f.s.VerifyFallbackRelease(context.Background(), d.f.node(), g)
			if err == nil || v != nil || d.f.s.ValidateAdvance(next) != nil {
				t.Fatal("denial lost observations or prepared keys", err)
			}
			switch mode {
			case "boundary-inactive":
				if next.Catalog["boundary/"+g.manifest.BoundaryID.String()].Revision != g.manifest.Revision {
					t.Fatal("inactive manifest lost")
				}
			case "deleted":
				if next.Catalog["tunnel/"+d.intent.FallbackTunnel.String()].Revision != 2 {
					t.Fatal("target tombstone lost")
				}
			default:
				if next.Account.Sequence != g.target.Author.State.Sequence || next.Account.Active != g.target.Author.State.Active {
					t.Fatal("new signed account observation lost")
				}
			}
		})
	}
}

func TestFallbackVerifierAuthenticatesTombstonesFromTheActualDecoder(t *testing.T) {
	d := fallbackReleaseFixture(t, true)
	r := d.parsed.target.Selection.Record.(sharedcatalog.TunnelRecord)
	r.Deleted = true
	d.parsed.target.Selection.Record = r
	d.f.signSelection(t, &d.parsed.target, 2)
	row := d.wire["target"].([]any)
	body, _ := json.Marshal(r)
	row[4], row[6], row[11] = string(body), "2", hex.EncodeToString(d.parsed.target.Selection.Seal.Signature)
	d.wire["values"], d.wire["copies"], d.wire["roots"] = []any{}, []any{}, []any{}
	raw, _ := json.Marshal(d.wire)
	graph, err := DecodeFallbackRelease(raw, AdmissionRequest{WorkspaceID: d.f.s.WorkspaceID, UserID: d.f.s.UserID}, d.intent)
	if err != nil {
		t.Fatal("decoder discarded signed tombstone before authentication", err)
	}
	next, v, err := d.f.s.VerifyFallbackRelease(context.Background(), d.f.node(), graph)
	if !errors.Is(err, vault.ErrPolicy) || v != nil || next.Catalog["tunnel/"+d.intent.FallbackTunnel.String()].Revision != 2 || d.f.s.ValidateAdvance(next) != nil {
		t.Fatal("decoded tombstone observation lost", err)
	}
}

func TestFallbackVerifierRetainsSignedProviderChangesBeforeDenial(t *testing.T) {
	for _, which := range []string{"primary", "target"} {
		d := fallbackReleaseFixture(t, true)
		r := &d.parsed.target
		row := d.wire["target"].([]any)
		if which == "primary" {
			r = d.parsed.source.metadata.records.Tunnel
			row = d.source["metadata"].(map[string]any)["tunnel"].([]any)
		}
		record := r.Selection.Record.(sharedcatalog.TunnelRecord)
		record.Metadata.Kind = 9
		if which == "primary" {
			record.Metadata.Kind = 2
		}
		r.Selection.Record = record
		d.f.signSelection(t, r, 2)
		body, _ := json.Marshal(record)
		row[4], row[6], row[11] = string(body), "2", hex.EncodeToString(r.Selection.Seal.Signature)
		raw, _ := json.Marshal(d.wire)
		graph, err := DecodeFallbackRelease(raw, AdmissionRequest{WorkspaceID: d.f.s.WorkspaceID, UserID: d.f.s.UserID}, d.intent)
		if err != nil {
			t.Fatal("provider change lost before authentication", err)
		}
		next, v, err := d.f.s.VerifyFallbackRelease(context.Background(), d.f.node(), graph)
		if !errors.Is(err, vault.ErrPolicy) || v != nil || next.Catalog["tunnel/"+record.Metadata.ID].Revision != 2 || d.f.s.ValidateAdvance(next) != nil {
			t.Fatal("signed provider observation lost", err)
		}
	}
}

func TestFallbackReferencePlanDoesNotOpenTargetAndConsumesOneUse(t *testing.T) {
	d := fallbackReleaseFixture(t, true)
	d.parsed.values[0].Envelope.Ciphertext = bytes.Clone(d.parsed.values[0].Envelope.Ciphertext)
	d.parsed.values[0].Envelope.Ciphertext[0] ^= 1
	next, v, err := d.f.s.VerifyFallbackRelease(context.Background(), d.f.node(), d.parsed)
	if err != nil {
		t.Fatal(err)
	}
	var primary []byte
	sources, err := v.ValidateReference(context.Background(), next, d.private, fallbackSelector(t, func(raw []byte) { primary = raw }))
	if err != nil || sources.Fallback.Metadata.ID != d.intent.FallbackTunnel.String() {
		t.Fatal("planning opened target ciphertext", err)
	}
	assertReleaseWiped(t, [][]byte{primary})
	if err := v.WithConfiguration(context.Background(), next, d.private, fallbackSelector(t, nil), func(FallbackSources, []byte) error { return nil }); err != ErrUseTicket {
		t.Fatal("plan graph reused", err)
	}
}

func TestFallbackOpeningDenialsAndCleanup(t *testing.T) {
	for _, mode := range []string{"uncommitted", "wrong-reference", "selector-error", "wrong-key", "target-root", "target-value", "cancel-primary", "cancel-target", "callback-error", "panic", "frozen"} {
		t.Run(mode, func(t *testing.T) {
			d := fallbackReleaseFixture(t, true)
			if mode == "target-root" {
				wrong, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{91}, 32))
				sealed, err := vault.SealKeyCopy(bytes.Repeat([]byte{31}, 32), d.parsed.root.Binding, wrong.PublicKey().Bytes(), d.finalKeys.SigningSeed)
				if err != nil {
					t.Fatal(err)
				}
				d.parsed.root.Copy = sealed
			}
			if mode == "target-value" {
				d.parsed.values[0].Envelope.Ciphertext = bytes.Clone(d.parsed.values[0].Envelope.Ciphertext)
				d.parsed.values[0].Envelope.Ciphertext[0] ^= 1
			}
			next, v, err := d.f.s.VerifyFallbackRelease(context.Background(), d.f.node(), d.parsed)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "frozen" {
				*d.parsed = UnverifiedFallbackRelease{}
			}
			if mode == "uncommitted" {
				next = d.f.s
			}
			private := d.private
			if mode == "wrong-key" {
				private = bytes.Repeat([]byte{92}, 32)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var primary, target []byte
			selectorCalled, targetCalled := false, false
			selector := fallbackSelector(t, func(raw []byte) {
				selectorCalled = true
				primary = raw
				if mode == "cancel-primary" {
					cancel()
				}
			})
			if mode == "wrong-reference" {
				selector = func(raw []byte) (string, error) { primary = raw; return uuid.NewString(), nil }
			}
			if mode == "selector-error" {
				selector = func(raw []byte) (string, error) { primary = raw; return "", vault.ErrPolicy }
			}
			call := func() {
				err = v.WithConfiguration(ctx, next, private, selector, func(_ FallbackSources, raw []byte) error {
					targetCalled = true
					target = raw
					if mode == "cancel-target" {
						cancel()
					}
					if mode == "callback-error" {
						return vault.ErrPolicy
					}
					if mode == "panic" {
						panic("synthetic callback panic")
					}
					return nil
				})
			}
			if mode == "panic" {
				func() {
					defer func() {
						if recover() == nil {
							t.Error("callback panic swallowed")
						}
					}()
					call()
				}()
			} else {
				call()
			}
			assertReleaseWiped(t, [][]byte{primary, target})
			if mode == "frozen" {
				if err != nil || !targetCalled {
					t.Fatal("caller changed verified graph", err)
				}
				return
			}
			if mode != "panic" && err == nil {
				t.Fatal("denial escaped")
			}
			if mode == "uncommitted" {
				if err != ErrTrustState || selectorCalled || targetCalled {
					t.Fatal("key used before commit", err)
				}
				return
			}
			if targetCalled != (mode == "cancel-target" || mode == "callback-error" || mode == "panic") {
				t.Fatal("wrong target opening boundary", err)
			}
			if _, err := v.ValidateReference(context.Background(), v.trust, d.private, fallbackSelector(t, nil)); err != ErrUseTicket {
				t.Fatal("failed attempt replay", err)
			}
		})
	}
}

func TestFallbackVerifierAndOpenerInputBoundaries(t *testing.T) {
	d := fallbackReleaseFixture(t, true)
	ctx := context.Background()
	for _, q := range []struct {
		ctx   context.Context
		node  uuid.UUID
		graph *UnverifiedFallbackRelease
	}{{nil, d.f.node(), d.parsed}, {ctx, uuid.Nil, d.parsed}, {ctx, d.f.node(), nil}, {ctx, d.f.node(), &UnverifiedFallbackRelease{}}} {
		if _, v, err := d.f.s.VerifyFallbackRelease(q.ctx, q.node, q.graph); err != ErrConfiguration || v != nil {
			t.Fatal(err)
		}
	}
	bad := d.f.s
	bad.Revision = math.MaxUint64
	if _, v, err := bad.VerifyFallbackRelease(ctx, d.f.node(), d.parsed); err != ErrTrustState || v != nil {
		t.Fatal("revision overflow", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, v, err := d.f.s.VerifyFallbackRelease(canceled, d.f.node(), d.parsed); !errors.Is(err, context.Canceled) || v != nil {
		t.Fatal(err)
	}
	_, v, err := d.f.s.VerifyFallbackRelease(ctx, d.f.node(), d.parsed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.ValidateReference(nil, v.trust, d.private, fallbackSelector(t, nil)); err != ErrConfiguration {
		t.Fatal(err)
	}
	if _, err := v.ValidateReference(ctx, v.trust, nil, fallbackSelector(t, nil)); err != ErrConfiguration {
		t.Fatal(err)
	}
	if _, err := v.ValidateReference(ctx, v.trust, d.private, nil); err != ErrConfiguration {
		t.Fatal(err)
	}
	if err := v.WithConfiguration(ctx, v.trust, d.private, fallbackSelector(t, nil), nil); err != ErrConfiguration {
		t.Fatal(err)
	}
	var missing *VerifiedFallbackRelease
	if _, err := missing.Sources(); err != ErrConfiguration {
		t.Fatal(err)
	}
}

func TestFallbackVerifierOpensOnlyTheReferencedTargetAfterCommit(t *testing.T) {
	for _, enrolled := range []bool{false, true} {
		d := fallbackReleaseFixture(t, enrolled)
		next, v, err := d.f.s.VerifyFallbackRelease(context.Background(), d.f.node(), d.parsed)
		if err != nil || v == nil || d.f.s.ValidateAdvance(next) != nil {
			t.Fatal("fallback verification", err)
		}
		sources, err := v.Sources()
		if err != nil || sources.Plan.TunnelID != d.intent.PrimaryTunnel.String() || sources.Primary.Metadata.ID != d.intent.PrimaryTunnel.String() || sources.Fallback.Metadata.ID != d.intent.FallbackTunnel.String() {
			t.Fatal("original plan retagged", err)
		}
		var primary, target []byte
		err = v.WithConfiguration(context.Background(), next, d.private, fallbackSelector(t, func(raw []byte) { primary = raw }), func(s FallbackSources, raw []byte) error {
			if !bytes.Equal(primary, make([]byte, len(primary))) || s != sources {
				t.Fatal("primary loan retained or source drift")
			}
			target = raw
			if string(raw) != `{"Host":"ssl.test","Password":"secondary-secret"}` {
				t.Fatal("wrong target")
			}
			return nil
		})
		if err != nil {
			t.Fatal("target opening", err)
		}
		assertReleaseWiped(t, [][]byte{primary, target})
		if err := v.WithConfiguration(context.Background(), next, d.private, fallbackSelector(t, nil), func(FallbackSources, []byte) error { t.Fatal("replay opened target"); return nil }); err != ErrUseTicket {
			t.Fatal("replay", err)
		}
	}
}

func TestFallbackVerifierRejectsBootstrapSourceAfterTargetPinsFinalAuthor(t *testing.T) {
	d := fallbackReleaseFixture(t, false)
	start := cloneTrustState(d.f.s)
	raw, _ := json.Marshal(d.source)
	var finalWire map[string]any
	_ = json.Unmarshal(raw, &finalWire)
	f, _, keys := enrollReleaseFixture(t, d.f, finalWire)
	author := f.records.Tunnel.Author
	d.parsed.target.Author = author
	f.signSelection(t, &d.parsed.target, d.parsed.target.Selection.Seal.Revision)
	public, _ := ecdh.X25519().NewPrivateKey(d.private)
	for _, entry := range []struct {
		copy          *UnverifiedKeyCopy
		plain, public []byte
	}{{&d.parsed.root, bytes.Repeat([]byte{31}, 32), public.PublicKey().Bytes()}, {&d.parsed.copy, bytes.Repeat([]byte{32}, 32), d.parsed.manifest.Secret.Public}} {
		entry.copy.Binding.Issuer = author.Key
		sealed, err := vault.SealKeyCopy(entry.plain, entry.copy.Binding, entry.public, keys.SigningSeed)
		if err != nil {
			t.Fatal(err)
		}
		entry.copy.Copy, entry.copy.Author = sealed, &author
	}
	// All signatures are valid and all author state sequences agree. The final
	// proof is learned only from the target after the bootstrap source was read.
	next, v, err := start.VerifyFallbackRelease(context.Background(), d.f.node(), d.parsed)
	if err == nil || v != nil {
		t.Fatal("bootstrap source survived newly authenticated final selection")
	}
	if !errors.Is(err, vault.ErrAuthentication) || next.Catalog[catalogEnrollmentName(*author.State)].Revision == 0 || start.ValidateAdvance(next) != nil {
		t.Fatal("final selection lost on denial", err)
	}
}
