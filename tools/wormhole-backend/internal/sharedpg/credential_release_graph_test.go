package sharedpg

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"sort"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func releaseCopyWire(t *testing.T, c UnverifiedKeyCopy, epoch, seq uint64) []any {
	t.Helper()
	n := func(v uint64) string { return strconv.FormatUint(v, 10) }
	b := c.Binding
	r := []any{b.WorkspaceID.String(), n(epoch), n(seq), b.Key.ID.String(), n(uint64(b.Key.Version)), b.Holder.ID.String(), n(uint64(b.Holder.Version)), "2", hex.EncodeToString(c.Copy.Envelope.Enc), hex.EncodeToString(c.Copy.Envelope.Ciphertext), b.Issuer.ID.String(), n(uint64(b.Issuer.Version)), hex.EncodeToString(c.Copy.Signature), "org-sign", nil, nil, nil, nil, nil, nil, nil, nil, nil}
	if a := c.Author; a != nil {
		r[13] = "user-sign"
		r[14] = a.State.UserID.String()
		r[15] = n(a.State.Sequence)
		raw, e := vault.EncodeUserKeyState(*a.State)
		if e != nil {
			t.Fatal(e)
		}
		r[16] = hex.EncodeToString(raw)
		if cert := a.Certificate; cert != nil {
			r[17] = "1"
			r[18] = hex.EncodeToString(cert.PublicKey)
			r[19] = cert.Signer.ID.String()
			r[20] = n(uint64(cert.Signer.Version))
			r[21] = n(cert.Revision)
			r[22] = hex.EncodeToString(cert.Signature)
		}
		if cert := a.EnrollmentCertificate; cert != nil {
			raw, e := vault.EncodeUserEnrollmentCertificate(*cert)
			if e != nil {
				t.Fatal(e)
			}
			r = append(r, hex.EncodeToString(raw))
		}
	}
	return r
}

func releaseGraphFixture(t *testing.T, kind string, member, previous bool) (connectionFixture, map[string]any) {
	t.Helper()
	f, metadata, _ := snapshotFixture(t, kind)
	userPrivate, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{17}, 32))
	state, e := vault.EncodeUserKeyState(*f.s.Account)
	if e != nil {
		t.Fatal(e)
	}
	graph := map[string]any{"formatVersion": 2, "profile": hex.EncodeToString(f.s.SignedProfile), "metadata": metadata, "account": []any{strconv.FormatUint(f.s.Account.Sequence, 10), hex.EncodeToString(state)}}
	manifests := make(map[uuid.UUID]vault.BoundaryManifest)
	for _, value := range metadata["boundaries"].([]any) {
		r := value.([]any)
		raw, _ := hex.DecodeString(r[5].(string))
		m, e := vault.DecodeBoundaryManifest(raw)
		if e != nil {
			t.Fatal(e)
		}
		if previous {
			old := m.Secret
			m.PreviousSecret = &old
			m.Secret.Key.Version++
			private, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{6}, 32))
			m.Secret.Public = private.PublicKey().Bytes()
			m.Revision++
			m, e = vault.SignBoundaryManifest(m, f.org)
			if e != nil {
				t.Fatal(e)
			}
			raw, _ = vault.EncodeBoundaryManifest(m)
			r[4], r[5], r[8] = strconv.FormatUint(m.Revision, 10), hex.EncodeToString(raw), hex.EncodeToString(m.Signature)
		}
		manifests[m.BoundaryID] = m
	}
	rootCopies := make(map[vault.KeyRef]UnverifiedKeyCopy)
	accounts := []any{}
	for i, profile := range []*UnverifiedCredentialRecord{f.records.Credential, f.records.Gateway} {
		if profile == nil {
			continue
		}
		role, prop := "primary", "credential"
		if i == 1 {
			role, prop = "gateway", "gateway"
		}
		profile.Credential.Record.Fields = []vaultstore.CredentialField{{Field: "password", Version: 9, Present: true}}
		profile.Credential.Record.Metadata.Name = profile.Credential.Record.Metadata.ID
		f.signProfile(t, profile, 1)
		raw, _ := json.Marshal(profile.Credential.Record)
		row := metadata[prop].([]any)
		row[4], row[11] = string(raw), hex.EncodeToString(profile.Credential.Seal.Signature)
		m := manifests[profile.Credential.Boundary]
		root := m.Secret
		if previous {
			root = *m.PreviousSecret
		}
		sealCopy := func(key, holder vault.KeyRef, plain, public []byte) UnverifiedKeyCopy {
			issuer, seed := m.Signer, f.org.Seed()
			var a *UnverifiedNodeAuthor
			if member {
				vault.Wipe(seed)
				issuer, seed, a = profile.Author.Key, f.key.Seed(), &profile.Author
			}
			defer vault.Wipe(seed)
			binding := vault.KeyCopyBinding{WorkspaceID: f.s.WorkspaceID, Key: key, Holder: holder, Issuer: issuer}
			copy, e := vault.SealKeyCopy(plain, binding, public, seed)
			if e != nil {
				t.Fatal(e)
			}
			return UnverifiedKeyCopy{Binding: binding, Copy: copy, Author: a}
		}
		dek := vault.KeyRef{ID: uuid.New(), Version: 3}
		value, e := vault.SealSharedValue(bytes.Repeat([]byte{23}, 32), vault.SharedValueBinding{WorkspaceID: f.s.WorkspaceID, OwnerKind: "credential", OwnerID: uuid.MustParse(profile.Credential.Record.Metadata.ID), Field: "password", Version: 9, DEK: dek}, []byte(role+"-secret"))
		if e != nil {
			t.Fatal(e)
		}
		raw, _ = vault.EncodeSharedEnvelope(value)
		values := []any{[]any{f.s.WorkspaceID.String(), profile.Credential.Record.Metadata.ID, "1", "7", "password", "9", dek.ID.String(), "3", hex.EncodeToString(raw)}}
		copy := sealCopy(dek, root.Key, bytes.Repeat([]byte{23}, 32), root.Public)
		accounts = append(accounts, map[string]any{"account": role, "values": values, "copies": []any{releaseCopyWire(t, copy, 1, 7)}})
		if _, exists := rootCopies[root.Key]; !exists {
			rootCopies[root.Key] = sealCopy(root.Key, f.s.Account.Encryption, bytes.Repeat([]byte{4}, 32), userPrivate.PublicKey().Bytes())
		}
	}
	refs := make([]vault.KeyRef, 0, len(rootCopies))
	for ref := range rootCopies {
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool { return releaseRootLabel(refs[i]) < releaseRootLabel(refs[j]) })
	roots := []any{}
	for _, ref := range refs {
		roots = append(roots, releaseCopyWire(t, rootCopies[ref], 1, 7))
	}
	graph["roots"], graph["accounts"] = roots, accounts
	return f, graph
}

func releaseParseFixture(t *testing.T, f connectionFixture, wire map[string]any) (*UnverifiedCredentialRelease, error) {
	t.Helper()
	raw, _ := json.Marshal(wire)
	return parseCredentialRelease(raw, AdmissionRequest{WorkspaceID: f.s.WorkspaceID, UserID: f.s.UserID}, f.node(), 1, 7)
}

func TestCredentialReleaseGraph(t *testing.T) {
	for _, kind := range []string{"saved", "slot", "override", "gateway", "none"} {
		for _, member := range []bool{false, true} {
			for _, previous := range []bool{false, true} {
				f, w := releaseGraphFixture(t, kind, member, previous)
				raw, _ := json.Marshal(w)
				graph, e := parseCredentialRelease(raw, AdmissionRequest{WorkspaceID: f.s.WorkspaceID, UserID: f.s.UserID}, f.node(), 1, 7)
				if e != nil {
					t.Fatal("parse", kind, member, previous, e)
				}
				vault.Wipe(raw)
				next, verified, e := f.s.VerifyCredentialRelease(context.Background(), f.node(), graph)
				if e != nil || verified == nil || f.s.ValidateAdvance(next) != nil || verified.plan != graph.metadata.plan || !reflect.DeepEqual(verified.trust, next) {
					t.Fatal("verify", kind, member, previous, e)
				}
				again, verified, e := next.VerifyCredentialRelease(context.Background(), f.node(), graph)
				if e != nil || verified == nil || !reflect.DeepEqual(again, next) {
					t.Fatal("repeat", e)
				}
				// Decoded material must outlive the borrowed network buffer, and
				// every field opens through the selected secret root and issuer.
				for _, account := range graph.accounts {
					var manifest vault.BoundaryManifest
					for _, m := range graph.metadata.manifests {
						if m.BoundaryID == account.boundary {
							manifest = m
						}
					}
					for i, value := range account.values {
						copy := account.copies[i]
						pub := f.s.PublicKey
						if copy.Author != nil {
							pub = copy.Author.Certificate.PublicKey
						}
						plain, e := vault.OpenSharedValue(bytes.Repeat([]byte{4}, 32), copy.Binding.Holder, value.Binding, copy.Copy, vault.KeyCopyTrust{Issuer: copy.Binding.Issuer, Public: pub}, value.Envelope, manifest, vault.BoundaryTrust{WorkspaceID: f.s.WorkspaceID, BoundaryID: account.boundary, Signer: manifest.Signer, Organisation: f.s.PublicKey, MinimumRevision: manifest.Revision})
						if e != nil || string(plain) != account.role+"-secret" {
							t.Fatal("open", e)
						}
						vault.Wipe(plain)
					}
				}
			}
		}
	}
}

func TestCredentialReleaseGraphMalformed(t *testing.T) {
	for _, mode := range []string{"format", "metadata", "account", "account-state", "accounts-null", "accounts-missing", "accounts-extra", "account-fields", "account-role", "values", "copies", "holder", "holder-version", "view-holder", "dek", "copy-header", "roots-missing", "roots-extra", "roots-holder", "roots-order", "roots-shape"} {
		t.Run(mode, func(t *testing.T) {
			f, w := releaseGraphFixture(t, "gateway", true, false)
			a := w["accounts"].([]any)[0].(map[string]any)
			copy := a["copies"].([]any)[0].([]any)
			roots := w["roots"].([]any)
			switch mode {
			case "format":
				w["formatVersion"] = 0
			case "metadata":
				w["metadata"] = nil
			case "account":
				w["account"] = []any{"4"}
			case "account-state":
				w["account"].([]any)[1] = "00"
			case "accounts-null":
				w["accounts"] = nil
			case "accounts-missing":
				w["accounts"] = []any{}
			case "accounts-extra":
				w["accounts"] = append(w["accounts"].([]any), a)
			case "account-fields":
				a["extra"] = "x"
			case "account-role":
				a["account"] = "gateway"
			case "values":
				a["values"] = []any{}
			case "copies":
				a["copies"] = []any{}
			case "holder":
				copy[5] = uuid.NewString()
			case "holder-version":
				copy[6] = "bad"
			case "view-holder":
				m, e := snapshotParseFixture(t, f, w["metadata"].(map[string]any))
				if e != nil {
					t.Fatal(e)
				}
				for _, manifest := range m.manifests {
					if manifest.BoundaryID == f.records.Credential.Credential.Boundary {
						copy[5], copy[6] = manifest.View.Key.ID.String(), strconv.Itoa(int(manifest.View.Key.Version))
					}
				}
			case "dek":
				copy[3] = uuid.NewString()
			case "copy-header":
				copy[0] = uuid.NewString()
			case "roots-missing":
				w["roots"] = roots[:1]
			case "roots-extra":
				w["roots"] = append(roots, roots[0])
			case "roots-holder":
				roots[0].([]any)[5] = uuid.NewString()
			case "roots-order":
				roots[0], roots[1] = roots[1], roots[0]
			case "roots-shape":
				w["roots"] = 1
			}
			if g, e := releaseParseFixture(t, f, w); g != nil || e == nil {
				t.Fatal("accepted", mode, e)
			}
		})
	}
	f, w := releaseGraphFixture(t, "saved", false, false)
	w["formatVersion"] = 7
	if _, e := releaseParseFixture(t, f, w); e != vault.ErrNewerFormat {
		t.Fatal(e)
	}
	for _, raw := range [][]byte{nil, {255}, []byte("{}"), []byte("null"), bytes.Repeat([]byte("x"), MaxCredentialReleaseBytes+1)} {
		if _, e := parseCredentialRelease(raw, AdmissionRequest{}, uuid.Nil, 0, 0); e == nil {
			t.Fatal("raw accepted")
		}
	}
	f, w = releaseGraphFixture(t, "saved", false, false)
	for _, mode := range []string{"inline", "tunnel"} {
		metadata := w["metadata"].(map[string]any)
		plan := metadata["plan"].(resolver.Plan)
		if mode == "inline" {
			plan.Credential.Kind = "inline"
		} else {
			plan.TunnelID = uuid.NewString()
		}
		metadata["plan"] = plan
		if _, e := releaseParseFixture(t, f, w); e != ErrAdmissionResponse {
			t.Fatal(mode, e)
		}
	}
}

func TestCredentialReleaseVerificationFailures(t *testing.T) {
	for _, mode := range []string{"account-signature", "revoked", "rotated", "metadata", "root-copy", "dek-copy", "newer-copy-state", "nil-copy-state", "context", "invalid-trust", "max-revision"} {
		t.Run(mode, func(t *testing.T) {
			f, w := releaseGraphFixture(t, "saved", true, false)
			g, e := releaseParseFixture(t, f, w)
			if e != nil {
				t.Fatal(e)
			}
			ctx := context.Background()
			switch mode {
			case "account-signature":
				g.account.Signature[0] ^= 1
			case "revoked", "rotated":
				g.account.Sequence++
				if mode == "revoked" {
					g.account.Active = false
				} else {
					g.account.Encryption.Version++
				}
				g.account, e = vault.SignUserKeyState(g.account, f.org)
				if e != nil {
					t.Fatal(e)
				}
			case "metadata":
				g.metadata.plan.Host = "redirect.example"
			case "root-copy":
				g.roots[0].Copy.Signature[0] ^= 1
			case "dek-copy":
				g.accounts[0].copies[0].Copy.Signature[0] ^= 1
			case "newer-copy-state":
				state := *g.accounts[0].copies[0].Author.State
				state.Sequence++
				state, e = vault.SignUserKeyState(state, f.org)
				if e != nil {
					t.Fatal(e)
				}
				g.accounts[0].copies[0].Author.State = &state
			case "nil-copy-state":
				g.accounts[0].copies[0].Author.State = nil
			case "context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "invalid-trust":
				f.s.Account = nil
			case "max-revision":
				f.s.Revision = math.MaxUint64
			}
			next, verified, e := f.s.VerifyCredentialRelease(ctx, f.node(), g)
			if e == nil || verified != nil {
				t.Fatal("invalid release accepted", e)
			}
			if mode == "revoked" || mode == "rotated" {
				if next.Account == nil || next.Account.Sequence != g.account.Sequence || f.s.ValidateAdvance(next) != nil {
					t.Fatal("lost current state", e)
				}
			}
			if mode == "newer-copy-state" && (e != ErrTreeSnapshotChanged || next.Account.Sequence != g.account.Sequence+1 || f.s.ValidateAdvance(next) != nil) {
				t.Fatal("mixed author states or lost partial observation", e)
			}
		})
	}
	f, w := releaseGraphFixture(t, "none", false, false)
	g, _ := releaseParseFixture(t, f, w)
	for _, call := range []func() error{
		func() error { _, _, e := f.s.VerifyCredentialRelease(nil, f.node(), g); return e },
		func() error { _, _, e := f.s.VerifyCredentialRelease(context.Background(), uuid.Nil, g); return e },
		func() error { _, _, e := f.s.VerifyCredentialRelease(context.Background(), f.node(), nil); return e },
	} {
		if e := call(); e != ErrConfiguration {
			t.Fatal(e)
		}
	}
}

func TestCredentialReleaseGraphCompletenessAndCancellation(t *testing.T) {
	// Distinct owners cannot share a DEK even when every row is otherwise well
	// shaped. A duplicated primary/gateway selection is the sole allowed reuse.
	f, w := releaseGraphFixture(t, "gateway", true, false)
	accounts := w["accounts"].([]any)
	primary, gateway := accounts[0].(map[string]any), accounts[1].(map[string]any)
	pvalue := primary["values"].([]any)[0].([]any)
	gvalue := gateway["values"].([]any)[0].([]any)
	gvalue[6], gvalue[7], gvalue[8] = pvalue[6], pvalue[7], pvalue[8]
	pcopy := primary["copies"].([]any)[0].([]any)
	gcopy := gateway["copies"].([]any)[0].([]any)
	gcopy[3], gcopy[4] = pcopy[3], pcopy[4]
	if _, e := releaseParseFixture(t, f, w); e != ErrAdmissionResponse {
		t.Fatal("DEK reused across owners", e)
	}
	metadata := w["metadata"].(map[string]any)
	oldGatewayBoundary := f.records.Gateway.Credential.Boundary
	f.records.Gateway = f.records.Credential
	f.records.Chain[0].Node.Metadata.RDPGatewayCredentialID = &f.records.Credential.Credential.Record.Metadata.ID
	f.signChain(t)
	leaf := metadata["chain"].([]any)[0].([]any)
	leafBody, _ := json.Marshal(f.records.Chain[0].Node.Metadata)
	leaf[4], leaf[11] = string(leafBody), hex.EncodeToString(f.records.Chain[0].Node.Seal.Signature)
	_, plan, e := f.s.ResolveCatalogConnection(context.Background(), f.node(), f.records)
	if e != nil {
		t.Fatal(e)
	}
	metadata["plan"] = plan
	metadata["gateway"] = metadata["credential"]
	manifests := []any{}
	for _, row := range metadata["boundaries"].([]any) {
		if row.([]any)[1] != oldGatewayBoundary.String() {
			manifests = append(manifests, row)
		}
	}
	metadata["boundaries"] = manifests
	gateway["values"], gateway["copies"] = primary["values"], primary["copies"]
	rootRows := w["roots"].([]any)
	for _, row := range rootRows {
		if row.([]any)[3] == pcopy[5] {
			w["roots"] = []any{row}
			break
		}
	}
	g, e := releaseParseFixture(t, f, w)
	if e != nil {
		t.Fatal("same field in both roles rejected structurally", e)
	}
	if _, v, e := f.s.VerifyCredentialRelease(context.Background(), f.node(), g); e != nil || v == nil {
		t.Fatal("same field in both roles rejected", e)
	}
	// Empty field manifests still require their role entry, with no copy/root.
	f, w = releaseGraphFixture(t, "saved", true, false)
	metadata = w["metadata"].(map[string]any)
	row := metadata["credential"].([]any)
	profile := f.records.Credential
	profile.Credential.Record.Fields[0].Present = false
	f.signProfile(t, profile, 1)
	body, _ := json.Marshal(profile.Credential.Record)
	row[4], row[11] = string(body), hex.EncodeToString(profile.Credential.Seal.Signature)
	account := w["accounts"].([]any)[0].(map[string]any)
	account["values"], account["copies"], w["roots"] = []any{}, []any{}, []any{}
	g, e = releaseParseFixture(t, f, w)
	if e != nil {
		t.Fatal(e)
	}
	if _, v, e := f.s.VerifyCredentialRelease(context.Background(), f.node(), g); e != nil || v == nil {
		t.Fatal("absent value", e)
	}
	// Cancellation at every orchestration boundary retains any observations
	// already authenticated, and never returns a usable prepared graph.
	f, w = releaseGraphFixture(t, "gateway", true, false)
	g, e = releaseParseFixture(t, f, w)
	if e != nil {
		t.Fatal(e)
	}
	checks := &cancelResolutionContext{Context: context.Background(), after: math.MaxInt}
	next, v, e := f.s.VerifyCredentialRelease(checks, f.node(), g)
	if e != nil || v == nil {
		t.Fatal(e)
	}
	for after := 0; after < checks.checks; after++ {
		observed, v, e := f.s.VerifyCredentialRelease(&cancelResolutionContext{Context: context.Background(), after: after}, f.node(), g)
		if e != context.Canceled || v != nil || observed.Revision == 0 || (!reflect.DeepEqual(observed, f.s) && f.s.ValidateAdvance(observed) != nil) {
			t.Fatal("cancellation", after, e)
		}
	}
	f.s.Revision = math.MaxUint64 - 1
	next, v, e = f.s.VerifyCredentialRelease(context.Background(), f.node(), g)
	if e != nil || v == nil || next.Revision != math.MaxUint64 {
		t.Fatal("one revision", e)
	}
	again, v, e := next.VerifyCredentialRelease(context.Background(), f.node(), g)
	if e != nil || v == nil || !reflect.DeepEqual(again, next) {
		t.Fatal("max idempotence", e)
	}
}
