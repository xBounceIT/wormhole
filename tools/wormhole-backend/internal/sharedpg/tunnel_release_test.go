package sharedpg

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// Add a tunnel in an independent boundary to a saved/inline/gateway graph.
// The fixture uses synthetic keys and a distinct root and DEK for that boundary.
func addTunnelReleaseFixture(t *testing.T, f *connectionFixture, w map[string]any) {
	t.Helper()
	id := uuid.NewString()
	enabled := true
	f.records.Chain[0].Node.Metadata.TunnelEnabled = &enabled
	f.records.Chain[0].Node.Metadata.TunnelConfigID = &id
	f.records.Tunnel = f.selection(t, sharedcatalog.TunnelRecord{Metadata: vaultstore.TunnelMetadata{ID: id, Name: "VPN", Kind: 1}, ConfigurationVersion: 1})
	metadata := w["metadata"].(map[string]any)
	first := metadata["boundaries"].([]any)[0].([]any)
	body, _ := hex.DecodeString(first[5].(string))
	manifest, err := vault.DecodeBoundaryManifest(body)
	if err != nil {
		t.Fatal(err)
	}
	manifest.BoundaryID = uuid.New()
	manifest.Secret.Key.ID = uuid.New()
	manifest.View.Key.ID = uuid.New()
	manifest, err = vault.SignBoundaryManifest(manifest, f.org)
	if err != nil {
		t.Fatal(err)
	}
	body, err = vault.EncodeBoundaryManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	boundaryRow := []any{manifest.WorkspaceID.String(), manifest.BoundaryID.String(), "1", "7", strconv.FormatUint(manifest.Revision, 10), hex.EncodeToString(body), manifest.Signer.ID.String(), strconv.Itoa(int(manifest.Signer.Version)), hex.EncodeToString(manifest.Signature)}
	boundaries := append(metadata["boundaries"].([]any), boundaryRow)
	sort.Slice(boundaries, func(i, j int) bool { return boundaries[i].([]any)[1].(string) < boundaries[j].([]any)[1].(string) })
	metadata["boundaries"] = boundaries
	f.records.Tunnel.Selection.Boundary = manifest.BoundaryID
	f.signSelection(t, f.records.Tunnel, 1)
	f.signChain(t)
	row := metadata["chain"].([]any)[0].([]any)
	raw, _ := json.Marshal(f.records.Chain[0].Node.Metadata)
	row[4], row[11] = string(raw), hex.EncodeToString(f.records.Chain[0].Node.Seal.Signature)
	tunnelRow := append([]any{}, row...)
	r := f.records.Tunnel.Selection
	raw, _ = json.Marshal(r.Record)
	tunnelRow[1], tunnelRow[4], tunnelRow[5], tunnelRow[6], tunnelRow[11] = id, string(raw), r.Boundary.String(), strconv.FormatUint(r.Seal.Revision, 10), hex.EncodeToString(r.Seal.Signature)
	_, plan, err := f.s.ResolveCatalogConnection(context.Background(), f.node(), f.records)
	if err != nil {
		t.Fatal(err)
	}
	metadata["formatVersion"], metadata["tunnel"], metadata["plan"] = 2, tunnelRow, plan
	w["formatVersion"] = 4
	if _, ok := w["nodeFields"]; !ok {
		w["nodeFields"] = nil
	}
	root := manifest.Secret
	private, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{17}, 32))
	// The author on selection and copy is deliberately the same current member.
	copyFor := func(key, holder vault.KeyRef, plain, public []byte) UnverifiedKeyCopy {
		b := vault.KeyCopyBinding{WorkspaceID: f.s.WorkspaceID, Key: key, Holder: holder, Issuer: f.records.Tunnel.Author.Key}
		seed := f.key.Seed()
		defer vault.Wipe(seed)
		c, e := vault.SealKeyCopy(plain, b, public, seed)
		if e != nil {
			t.Fatal(e)
		}
		return UnverifiedKeyCopy{Binding: b, Copy: c, Author: &f.records.Tunnel.Author}
	}
	dek := vault.KeyRef{ID: uuid.New(), Version: 1}
	binding := vault.SharedValueBinding{WorkspaceID: f.s.WorkspaceID, OwnerKind: "tunnel", OwnerID: uuid.MustParse(id), Field: "settings", Version: 1, DEK: dek}
	envelope, err := vault.SealSharedValue(bytes.Repeat([]byte{24}, 32), binding, []byte("tunnel-secret"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err = vault.EncodeSharedEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	value := []any{f.s.WorkspaceID.String(), id, "1", "7", "settings", "1", dek.ID.String(), "1", hex.EncodeToString(raw)}
	copy := copyFor(dek, root.Key, bytes.Repeat([]byte{24}, 32), root.Public)
	w["accounts"] = append(w["accounts"].([]any), map[string]any{"account": "tunnel", "values": []any{value}, "copies": []any{releaseCopyWire(t, copy, 1, 7)}})
	roots := w["roots"].([]any)
	present := false
	for _, entry := range roots {
		row := entry.([]any)
		if row[3] == root.Key.ID.String() && row[4] == strconv.Itoa(int(root.Key.Version)) {
			present = true
		}
	}
	if !present {
		roots = append(roots, releaseCopyWire(t, copyFor(root.Key, f.s.Account.Encryption, bytes.Repeat([]byte{4}, 32), private.PublicKey().Bytes()), 1, 7))
	}
	sort.Slice(roots, func(i, j int) bool {
		a, b := roots[i].([]any), roots[j].([]any)
		return a[3].(string)+"/"+a[4].(string) < b[3].(string)+"/"+b[4].(string)
	})
	w["roots"] = roots
}

func tunnelReleaseFixture(t *testing.T, kind string) (connectionFixture, map[string]any) {
	t.Helper()
	var f connectionFixture
	var w map[string]any
	if kind == "inline" || kind == "inline-gateway" {
		mode := "password"
		if kind == "inline-gateway" {
			mode = "rdp-gateway"
		}
		f, w = inlineReleaseFixture(t, mode)
	} else {
		f, w = releaseGraphFixture(t, kind, true, false)
	}
	addTunnelReleaseFixture(t, &f, w)
	return f, w
}

func TestTunnelMetadataSnapshotAndPlan(t *testing.T) {
	f, w, want := snapshotFixture(t, "tunnel")
	input, err := snapshotParseFixture(t, f, w)
	if err != nil {
		t.Fatal(err)
	}
	next, p, err := f.s.VerifyConnectionSnapshot(context.Background(), f.node(), input)
	if err != nil || p != want || f.s.ValidateAdvance(next) != nil || next.Catalog["tunnel/"+p.TunnelID].Revision != 1 {
		t.Fatal(p, err)
	}
	// The tunnel boundary is independent of the node and credential boundaries.
	if input.records.Tunnel.Selection.Boundary == input.records.Chain[0].Node.Boundary {
		t.Fatal("fixture boundary")
	}
	f2, w2 := tunnelReleaseFixture(t, "saved")
	planWire := map[string]any{"formatVersion": 1, "profile": w2["profile"], "account": w2["account"], "metadata": w2["metadata"]}
	q, err := decodePlanFixture(t, f2, planWire)
	if err != nil {
		t.Fatal(err)
	}
	state, plan, err := f2.s.VerifyConnectionPlan(context.Background(), f2.node(), q)
	if err != nil || plan.Tunnel == nil || plan.Tunnel.Metadata.ID != plan.Plan.TunnelID || plan.Tunnel.ConfigurationVersion != 1 || plan.Tunnel.RowVersion != 1 {
		t.Fatal(plan, err)
	}
	again, same, err := state.VerifyConnectionPlan(context.Background(), f2.node(), q)
	if err != nil || !reflect.DeepEqual(same, plan) || !reflect.DeepEqual(again, state) {
		t.Fatal("unstable plan", err)
	}
	// A signed name-only edit advances the plan revision without changing settings.
	r := q.metadata.records.Tunnel
	changed := r.Selection.Record.(sharedcatalog.TunnelRecord)
	changed.Metadata.Name = "New name"
	r.Selection.Record = changed
	f2.signSelection(t, r, 2)
	_, updated, err := state.VerifyConnectionPlan(context.Background(), f2.node(), q)
	if err != nil || updated.Revision == plan.Revision || updated.Tunnel.RowVersion != 2 || updated.Tunnel.ConfigurationVersion != 1 {
		t.Fatal("name edit", err)
	}
}

func TestTunnelMetadataRejectsAmbiguityAndUnselectedRecords(t *testing.T) {
	for _, mode := range []string{"missing", "null", "old-format", "new-without-route", "wrong-id", "wrong-kind", "unknown", "nested-unknown", "nested-null", "version-zero", "version-large", "boundary", "signature", "deleted", "extra-direct"} {
		t.Run(mode, func(t *testing.T) {
			f, w, _ := snapshotFixture(t, "tunnel")
			row := w["tunnel"].([]any)
			switch mode {
			case "missing":
				delete(w, "tunnel")
			case "null":
				w["tunnel"] = nil
			case "old-format":
				w["formatVersion"] = 1
			case "new-without-route", "extra-direct":
				p := w["plan"].(resolver.Plan)
				p.TunnelID = ""
				w["plan"] = p
			case "wrong-id":
				row[1] = uuid.NewString()
			case "wrong-kind":
				var r map[string]any
				json.Unmarshal([]byte(row[4].(string)), &r)
				r["metadata"].(map[string]any)["kind"] = 10
				raw, _ := json.Marshal(r)
				row[4] = string(raw)
			case "unknown", "nested-unknown", "nested-null", "version-zero", "version-large":
				var r map[string]any
				json.Unmarshal([]byte(row[4].(string)), &r)
				switch mode {
				case "unknown":
					r["fields"] = []any{}
				case "nested-unknown":
					r["metadata"].(map[string]any)["password"] = "bad"
				case "nested-null":
					r["metadata"] = nil
				case "version-zero":
					r["configurationVersion"] = 0
				case "version-large":
					r["configurationVersion"] = uint64(1) << 63
				}
				raw, _ := json.Marshal(r)
				row[4] = string(raw)
			case "boundary":
				row[5] = uuid.NewString()
			case "signature":
				row[11] = hex.EncodeToString(make([]byte, 64))
			case "deleted":
				r := f.records.Tunnel.Selection.Record.(sharedcatalog.TunnelRecord)
				r.Deleted = true
				f.records.Tunnel.Selection.Record = r
				f.signSelection(t, f.records.Tunnel, 2)
				raw, _ := json.Marshal(r)
				row[4], row[6], row[11] = string(raw), "2", hex.EncodeToString(f.records.Tunnel.Selection.Seal.Signature)
			}
			q, err := snapshotParseFixture(t, f, w)
			if err == nil {
				next, p, e := f.s.VerifyConnectionSnapshot(context.Background(), f.node(), q)
				err = e
				if p != (resolver.Plan{}) {
					t.Fatal("failed tunnel returned plan")
				}
				if mode == "deleted" && (err != vaultstore.ErrMissing || next.Catalog["tunnel/"+f.records.Tunnel.Selection.Record.(sharedcatalog.TunnelRecord).Metadata.ID].Revision != 2) {
					t.Fatal("tombstone floor", err)
				}
			}
			if err == nil {
				t.Fatal("malformed tunnel accepted")
			}
		})
	}
	// Omission is also refused by the resolver, without depending on the wire codec.
	f, _, _ := snapshotFixture(t, "tunnel")
	f.records.Tunnel = nil
	if _, p, err := f.s.ResolveCatalogConnection(context.Background(), f.node(), f.records); err != ErrAdmissionResponse || p != (resolver.Plan{}) {
		t.Fatal(err)
	}
	f = newConnectionFixture(t)
	f.records.Tunnel = f.selection(t, sharedcatalog.TunnelRecord{Metadata: vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "Extra", Kind: 1}, ConfigurationVersion: 1})
	if _, _, err := f.s.ResolveCatalogConnection(context.Background(), f.node(), f.records); err != ErrAdmissionResponse {
		t.Fatal("unselected tunnel", err)
	}
}

func TestTunnelReleaseSelectiveOpeningWipingAndReplay(t *testing.T) {
	for _, kind := range []string{"saved", "gateway", "inline", "inline-gateway", "none"} {
		for _, tunnelOnly := range []bool{false, true} {
			t.Run(kind+strconv.FormatBool(tunnelOnly), func(t *testing.T) {
				f, w := tunnelReleaseFixture(t, kind)
				g, err := releaseParseFixture(t, f, w)
				if err != nil {
					t.Fatal(err)
				}
				next, v, err := f.s.VerifyCredentialRelease(context.Background(), f.node(), g)
				if err != nil || f.s.ValidateAdvance(next) != nil {
					t.Fatal(err)
				}
				// Corrupt only the unselected ciphertext after verification. An attempted
				// decryption of that role would fail instead of reaching the callback.
				for i := range v.graph.accounts {
					a := &v.graph.accounts[i]
					if (a.role == "tunnel") != tunnelOnly && len(a.values) > 0 {
						a.values[0].Envelope.Ciphertext[0] ^= 1
					}
				}
				var borrowed [][]byte
				use := func(p resolver.Plan, values CredentialReleaseValues) error {
					if p.TunnelID == "" {
						t.Fatal("route lost")
					}
					if tunnelOnly {
						if values.Tunnel == nil || values.Primary != nil || values.Gateway != nil || values.Inline != nil || string(values.Tunnel.Fields["settings"]) != "tunnel-secret" {
							t.Fatal("role separation")
						}
						borrowed = append(borrowed, values.Tunnel.Fields["settings"])
						raw, _ := json.Marshal(values.Tunnel)
						if bytes.Contains(raw, []byte("tunnel-secret")) {
							t.Fatal("JSON leak")
						}
						delete(values.Tunnel.Fields, "settings")
					} else {
						if values.Tunnel != nil {
							t.Fatal("opened tunnel during credential release")
						}
						for _, c := range []*BorrowedCredential{values.Primary, values.Gateway} {
							if c != nil {
								borrowed = append(borrowed, c.Fields["password"])
							}
						}
						if values.Inline != nil {
							borrowed = append(borrowed, values.Inline.Fields["inlinePassword"])
						}
					}
					raw, _ := json.Marshal(values)
					if string(raw) != "{}" {
						t.Fatal("release JSON leak")
					}
					return nil
				}
				open := v.WithValues
				if tunnelOnly {
					open = v.WithTunnelValues
				}
				if err := open(context.Background(), next, bytes.Repeat([]byte{17}, 32), use); err != nil {
					t.Fatal(err)
				}
				assertReleaseWiped(t, borrowed)
				if err := v.WithValues(context.Background(), next, bytes.Repeat([]byte{17}, 32), use); err != ErrUseTicket {
					t.Fatal("cross-role replay", err)
				}
				if err := v.WithTunnelValues(context.Background(), next, bytes.Repeat([]byte{17}, 32), use); err != ErrUseTicket {
					t.Fatal("tunnel replay", err)
				}
			})
		}
	}
}

func TestTunnelReleaseOpeningFailuresAndSingleUse(t *testing.T) {
	failure := errors.New("callback failed")
	for _, mode := range []string{"callback", "panic", "cancel", "cancel-after", "wrong-private", "stale-trust", "short-private", "nil-context", "nil-callback"} {
		t.Run(mode, func(t *testing.T) {
			f, w := tunnelReleaseFixture(t, "gateway")
			g, err := releaseParseFixture(t, f, w)
			if err != nil {
				t.Fatal(err)
			}
			next, v, err := f.s.VerifyCredentialRelease(context.Background(), f.node(), g)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			private := bytes.Repeat([]byte{17}, 32)
			var plain []byte
			called := false
			use := func(_ resolver.Plan, values CredentialReleaseValues) error {
				called = true
				plain = values.Tunnel.Fields["settings"]
				switch mode {
				case "callback":
					return failure
				case "panic":
					panic(failure)
				case "cancel-after":
					cancel()
				}
				return nil
			}
			switch mode {
			case "cancel":
				cancel()
			case "wrong-private":
				private = bytes.Repeat([]byte{19}, 32)
			case "stale-trust":
				next = f.s
			case "short-private":
				private = private[:31]
			case "nil-context":
				ctx = nil
			case "nil-callback":
				use = nil
			}
			if mode == "panic" {
				func() {
					defer func() {
						if recover() != failure {
							t.Fatal("lost panic")
						}
					}()
					_ = v.WithTunnelValues(ctx, next, private, use)
				}()
			} else {
				if err := v.WithTunnelValues(ctx, next, private, use); err == nil {
					t.Fatal("invalid opening")
				}
			}
			if called != (mode == "callback" || mode == "panic" || mode == "cancel-after") {
				t.Fatal("callback reached")
			}
			assertReleaseWiped(t, [][]byte{plain})
		})
	}
	f, w := tunnelReleaseFixture(t, "saved")
	g, err := releaseParseFixture(t, f, w)
	if err != nil {
		t.Fatal(err)
	}
	next, v, err := f.s.VerifyCredentialRelease(context.Background(), f.node(), g)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var count atomic.Int32
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(tunnel bool) {
			defer wg.Done()
			open := v.WithValues
			if tunnel {
				open = v.WithTunnelValues
			}
			err := open(context.Background(), next, bytes.Repeat([]byte{17}, 32), func(resolver.Plan, CredentialReleaseValues) error { count.Add(1); return nil })
			if err != nil && err != ErrUseTicket {
				t.Error(err)
			}
		}(i%2 == 0)
	}
	wg.Wait()
	if count.Load() != 1 {
		t.Fatal("concurrent double opening")
	}
	var absent *VerifiedCredentialRelease
	if err := absent.WithTunnelValues(context.Background(), next, bytes.Repeat([]byte{17}, 32), func(resolver.Plan, CredentialReleaseValues) error { return nil }); err != ErrConfiguration {
		t.Fatal(err)
	}
	_, _, direct, prepared := openReleaseFixture(t, "saved", true, false)
	if err := prepared.WithTunnelValues(context.Background(), direct, bytes.Repeat([]byte{17}, 32), func(resolver.Plan, CredentialReleaseValues) error { return nil }); err != ErrConfiguration {
		t.Fatal("direct tunnel release", err)
	}
}

func TestTunnelTrustFloorsForksAndTombstones(t *testing.T) {
	f, _, _ := snapshotFixture(t, "tunnel")
	r := f.records.Tunnel
	next, err := f.s.AdvanceSelection(r.Selection, r.Author)
	if err != nil || f.s.ValidateAdvance(next) != nil {
		t.Fatal(err)
	}
	changed := r.Selection.Record.(sharedcatalog.TunnelRecord)
	changed.Metadata.Name = "Fork"
	fork := *r
	fork.Selection.Record = changed
	f.signSelection(t, &fork, 1)
	if _, err := next.AdvanceSelection(fork.Selection, fork.Author); err != ErrCatalogEquivocation {
		t.Fatal("same-revision fork", err)
	}
	f.signSelection(t, &fork, 2)
	newer, err := next.AdvanceSelection(fork.Selection, fork.Author)
	if err != nil || next.ValidateAdvance(newer) != nil {
		t.Fatal(err)
	}
	if _, err := newer.AdvanceSelection(r.Selection, r.Author); err != vault.ErrRollback {
		t.Fatal("rollback", err)
	}
	changed.Deleted = true
	fork.Selection.Record = changed
	f.signSelection(t, &fork, 3)
	tombstone, err := newer.AdvanceSelection(fork.Selection, fork.Author)
	if err != vaultstore.ErrMissing || tombstone.Catalog["tunnel/"+changed.Metadata.ID].Revision != 3 || newer.ValidateAdvance(tombstone) != nil {
		t.Fatal("tombstone floor", err)
	}
	raw, err := json.Marshal(tombstone)
	if err != nil {
		t.Fatal(err)
	}
	var restored TrustState
	if json.Unmarshal(raw, &restored) != nil || !restored.valid() {
		t.Fatal("floor lost across serialization")
	}
	if _, err := restored.AdvanceSelection(r.Selection, r.Author); err != vault.ErrRollback {
		t.Fatal("rollback after restart", err)
	}
	revoked := r.Author
	state := *revoked.State
	state.Sequence++
	state.Active = false
	state, err = vault.SignUserKeyState(state, f.org)
	if err != nil {
		t.Fatal(err)
	}
	revoked.State = &state
	observed, err := f.s.AdvanceSelection(r.Selection, revoked)
	if err != vault.ErrPolicy || observed.Account.Active || observed.Account.Sequence != state.Sequence {
		t.Fatal("lost revocation", err)
	}
}

func TestTunnelReleaseGraphRejectsSubstitutionAndPartialMaterial(t *testing.T) {
	for _, mode := range []string{"old-format", "missing-node-fields", "missing-account", "extra-account", "wrong-role", "wrong-owner", "wrong-field", "wrong-version", "missing-value", "missing-copy", "missing-root", "root-order", "dek-reuse", "extra-fields", "settings-null", "extra-node-fields", "metadata-old", "metadata-no-tunnel"} {
		t.Run(mode, func(t *testing.T) {
			f, w := tunnelReleaseFixture(t, "gateway")
			metadata := w["metadata"].(map[string]any)
			accounts := w["accounts"].([]any)
			tunnel := accounts[len(accounts)-1].(map[string]any)
			value := tunnel["values"].([]any)[0].([]any)
			switch mode {
			case "old-format":
				w["formatVersion"] = 3
			case "missing-node-fields":
				delete(w, "nodeFields")
			case "missing-account":
				w["accounts"] = accounts[:len(accounts)-1]
			case "extra-account":
				w["accounts"] = append(accounts, tunnel)
			case "wrong-role":
				tunnel["account"] = "primary"
			case "wrong-owner":
				value[1] = f.records.Credential.Credential.Record.Metadata.ID
			case "wrong-field":
				value[4] = "password"
			case "wrong-version":
				value[5] = "2"
			case "missing-value":
				tunnel["values"] = []any{}
			case "missing-copy":
				tunnel["copies"] = []any{}
			case "missing-root":
				roots := w["roots"].([]any)
				w["roots"] = roots[:len(roots)-1]
			case "root-order":
				roots := w["roots"].([]any)
				roots[0], roots[1] = roots[1], roots[0]
			case "dek-reuse":
				primary := accounts[0].(map[string]any)
				old := primary["values"].([]any)[0].([]any)
				value[6], value[7], value[8] = old[6], old[7], old[8]
				tunnel["copies"] = primary["copies"]
				// Keep the remaining graph coherent so DEK ownership, rather
				// than an unrelated holder/root mismatch, must reject it.
				oldBoundary := f.records.Tunnel.Selection.Boundary.String()
				profile := f.records.Tunnel
				profile.Selection.Boundary = f.records.Credential.Credential.Boundary
				f.signSelection(t, profile, 1)
				tunnelRow := metadata["tunnel"].([]any)
				tunnelRow[5], tunnelRow[11] = profile.Selection.Boundary.String(), hex.EncodeToString(profile.Selection.Seal.Signature)
				var dropped vault.KeyRef
				manifests := []any{}
				for _, entry := range metadata["boundaries"].([]any) {
					row := entry.([]any)
					if row[1] == oldBoundary {
						body, _ := hex.DecodeString(row[5].(string))
						m, err := vault.DecodeBoundaryManifest(body)
						if err != nil {
							t.Fatal(err)
						}
						dropped = m.Secret.Key
					} else {
						manifests = append(manifests, row)
					}
				}
				metadata["boundaries"] = manifests
				roots := []any{}
				for _, entry := range w["roots"].([]any) {
					row := entry.([]any)
					if row[3] != dropped.ID.String() || row[4] != strconv.Itoa(int(dropped.Version)) {
						roots = append(roots, row)
					}
				}
				w["roots"] = roots

			case "extra-fields":
				tunnel["settings"] = "bad"
			case "settings-null":
				tunnel["values"] = nil
			case "extra-node-fields":
				w["nodeFields"] = metadata["tunnel"]
			case "metadata-old":
				metadata["formatVersion"] = 1
				delete(metadata, "tunnel")
			case "metadata-no-tunnel":
				delete(metadata, "tunnel")
			}
			if g, err := releaseParseFixture(t, f, w); err == nil || g != nil {
				t.Fatal("partial or redirected tunnel graph accepted", mode, err)
			}
		})
	}
	f, w := releaseGraphFixture(t, "saved", true, false)
	w["formatVersion"], w["nodeFields"] = 4, nil
	if _, err := releaseParseFixture(t, f, w); err != ErrAdmissionResponse {
		t.Fatal("tunnel format without tunnel", err)
	}
}

func TestVerifiedTunnelMetadataIsDetachedAndCannotReleaseValues(t *testing.T) {
	f, w := tunnelReleaseFixture(t, "saved")
	g, err := releaseParseFixture(t, f, w)
	if err != nil {
		t.Fatal(err)
	}
	next, v, err := f.s.VerifyCredentialRelease(context.Background(), f.node(), g)
	if err != nil {
		t.Fatal(err)
	}
	original, err := v.Tunnel()
	if err != nil || original == nil || original.Metadata.ID != v.plan.TunnelID {
		t.Fatal(err)
	}
	original.Metadata.ID = uuid.NewString()
	original.ConfigurationVersion = 99
	current, err := v.Tunnel()
	if err != nil || current.Metadata.ID != v.plan.TunnelID || current.ConfigurationVersion != 1 {
		t.Fatal("mutable graph metadata")
	}
	// Reading public metadata does not consume its audited one-use opening.
	if err := v.WithTunnelValues(context.Background(), next, bytes.Repeat([]byte{17}, 32), func(_ resolver.Plan, values CredentialReleaseValues) error {
		if values.Tunnel.Tunnel != *current {
			t.Fatal("metadata drift")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, _, _, direct := openReleaseFixture(t, "saved", true, false)
	if meta, err := direct.Tunnel(); err != nil || meta != nil {
		t.Fatal("direct route metadata", err)
	}
	for _, bad := range []*VerifiedCredentialRelease{nil, {}, {graph: &UnverifiedCredentialRelease{}}} {
		if meta, err := bad.Tunnel(); err != ErrConfiguration || meta != nil {
			t.Fatal("invalid metadata accessor", err)
		}
	}
}
