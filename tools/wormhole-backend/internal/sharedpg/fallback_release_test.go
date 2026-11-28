package sharedpg

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"math"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type fallbackTestData struct {
	f                connectionFixture
	wire, source     map[string]any
	intent           FallbackUseIntent
	private, primary []byte
	finalKeys        *vault.UserKeys
	parsed           *UnverifiedFallbackRelease
}

func fallbackReleaseFixture(t *testing.T, enrolled bool) fallbackTestData {
	t.Helper()
	var d fallbackTestData
	if enrolled {
		d.f, d.source, d.finalKeys = enrolledReleaseFixture(t, true)
		d.private = d.finalKeys.EncryptionPrivate
	} else {
		d.f, d.source = tunnelReleaseFixture(t, "saved")
		d.private = bytes.Repeat([]byte{17}, 32)
		// Current SQL returns format5 even for a bootstrap account without a
		// final enrollment. Promote only the fixture's public wire layout.
		m := d.source["metadata"].(map[string]any)
		m["formatVersion"], d.source["formatVersion"], d.source["enrollment"] = 3, 5, nil
		for i, row := range m["chain"].([]any) {
			m["chain"].([]any)[i] = append(row.([]any), nil)
		}
		for _, key := range []string{"credential", "gateway", "tunnel", "override", "slot", "slotValue"} {
			if row, ok := m[key].([]any); ok {
				m[key] = append(row, nil)
			}
		}
		for i, row := range d.source["roots"].([]any) {
			d.source["roots"].([]any)[i] = append(row.([]any), nil)
		}
		for _, raw := range d.source["accounts"].([]any) {
			a := raw.(map[string]any)
			for i, row := range a["copies"].([]any) {
				a["copies"].([]any)[i] = append(row.([]any), nil)
			}
		}
	}
	f := &d.f
	g, err := releaseParseFixture(t, *f, d.source)
	if err != nil {
		t.Fatal(err)
	}
	m := g.metadata.manifests[0]
	m.BoundaryID, m.View.Key.ID, m.Secret.Key.ID, m.PreviousView, m.PreviousSecret = uuid.New(), uuid.New(), uuid.New(), nil, nil
	rootSeed, dekSeed := bytes.Repeat([]byte{31}, 32), bytes.Repeat([]byte{32}, 32)
	rootKey, _ := ecdh.X25519().NewPrivateKey(rootSeed)
	m.Secret.Public = rootKey.PublicKey().Bytes()
	m, err = vault.SignBoundaryManifest(m, f.org)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := vault.EncodeBoundaryManifest(m)
	id := uuid.New()
	r := f.selection(t, sharedcatalog.TunnelRecord{Metadata: vaultstore.TunnelMetadata{ID: id.String(), Name: "Secondary SSL", Kind: 2}, ConfigurationVersion: 1})
	r.Selection.Boundary = m.BoundaryID
	f.signSelection(t, r, 1)
	metadata := d.source["metadata"].(map[string]any)
	target := append([]any(nil), metadata["tunnel"].([]any)...)
	record, _ := json.Marshal(r.Selection.Record)
	target[1], target[4], target[5], target[6], target[11] = id.String(), string(record), m.BoundaryID.String(), "1", hex.EncodeToString(r.Selection.Seal.Signature)
	d.intent = FallbackUseIntent{UseIntent: UseIntent{Node: f.node(), Ticket: uuid.New(), Epoch: 1, ChangeSeq: 7, ExpiresAt: 1800000000}, PrimaryTunnel: uuid.MustParse(g.metadata.plan.TunnelID), FallbackTunnel: id}
	primary := f.records.Tunnel
	p := primary.Selection.Record.(sharedcatalog.TunnelRecord)
	p.Metadata.Kind = 9
	primary.Selection.Record = p
	f.signSelection(t, primary, 1)
	primaryRow := metadata["tunnel"].([]any)
	record, _ = json.Marshal(p)
	primaryRow[4], primaryRow[11] = string(record), hex.EncodeToString(primary.Selection.Seal.Signature)
	d.primary, _ = json.Marshal(map[string]any{"Host": "ipsec.test", "PreSharedKey": "synthetic", "UserAuth": 0, "FallbackTunnelId": id.String()})
	for _, raw := range d.source["accounts"].([]any) {
		a := raw.(map[string]any)
		if a["account"] != "tunnel" {
			continue
		}
		value := a["values"].([]any)[0].([]any)
		binding := g.accounts[len(g.accounts)-1].values[0].Binding
		envelope, e := vault.SealSharedValue(bytes.Repeat([]byte{24}, 32), binding, d.primary)
		if e != nil {
			t.Fatal(e)
		}
		rawEnvelope, _ := vault.EncodeSharedEnvelope(envelope)
		value[8] = hex.EncodeToString(rawEnvelope)
	}
	public, _ := ecdh.X25519().NewPrivateKey(d.private)
	holder := f.s.Account.Encryption
	if f.s.Enrollment != nil {
		holder = f.s.Enrollment.Encryption
	}
	copyFor := func(key, recipient vault.KeyRef, plain, public []byte) []any {
		binding := vault.KeyCopyBinding{WorkspaceID: f.s.WorkspaceID, Key: key, Holder: recipient, Issuer: r.Author.Key}
		seed := f.key.Seed()
		defer vault.Wipe(seed)
		sealed, e := vault.SealKeyCopy(plain, binding, public, seed)
		if e != nil {
			t.Fatal(e)
		}
		row := releaseCopyWire(t, UnverifiedKeyCopy{Binding: binding, Copy: sealed, Author: &r.Author}, 1, 7)
		if len(row) == 23 {
			row = append(row, nil)
		}
		return row
	}
	dek := vault.KeyRef{ID: uuid.New(), Version: 1}
	binding := vault.SharedValueBinding{WorkspaceID: f.s.WorkspaceID, OwnerKind: "tunnel", OwnerID: id, Field: "settings", Version: 1, DEK: dek}
	sealed, err := vault.SealSharedValue(dekSeed, binding, []byte(`{"Host":"ssl.test","Password":"secondary-secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := vault.EncodeSharedEnvelope(sealed)
	d.wire = map[string]any{"formatVersion": 1, "source": d.source, "target": target,
		"boundary": []any{f.s.WorkspaceID.String(), m.BoundaryID.String(), "1", "7", "1", hex.EncodeToString(body), m.Signer.ID.String(), "1", hex.EncodeToString(m.Signature)},
		"values":   []any{[]any{f.s.WorkspaceID.String(), id.String(), "1", "7", "settings", "1", dek.ID.String(), "1", hex.EncodeToString(encoded)}},
		"copies":   []any{copyFor(dek, m.Secret.Key, dekSeed, m.Secret.Public)}, "roots": []any{copyFor(m.Secret.Key, holder, rootSeed, public.PublicKey().Bytes())}}
	raw, _ := json.Marshal(d.wire)
	d.parsed, err = parseFallbackRelease(raw, AdmissionRequest{WorkspaceID: f.s.WorkspaceID, UserID: f.s.UserID}, d.intent)
	if err != nil {
		t.Fatal("fallback fixture", err)
	}
	return d
}

func TestFallbackReleaseDecoderBindsBothSourcesAndFinalRecipients(t *testing.T) {
	for _, enrolled := range []bool{false, true} {
		d := fallbackReleaseFixture(t, enrolled)
		g := d.parsed
		if g.target.Selection.Record.(sharedcatalog.TunnelRecord).Metadata.ID != d.intent.FallbackTunnel.String() || g.source.metadata.plan.TunnelID != d.intent.PrimaryTunnel.String() || (g.source.enrollment != nil) != enrolled || g.root.Binding.Holder == g.copy.Binding.Holder {
			t.Fatal("wrong source/recipient")
		}
		// These are genuine encrypted values, not a mocked decoded response.
		root, err := vault.OpenKeyCopy(d.private, g.root.Binding, g.root.Copy, g.root.Author.signingPublic())
		if err != nil {
			t.Fatal(err)
		}
		defer vault.Wipe(root)
		if len(root) != 32 {
			t.Fatal("wrong encrypted root")
		}
	}
}

func TestFallbackReleaseStrictDecoderRejectsSubstitutionAndPartialGraphs(t *testing.T) {
	d := fallbackReleaseFixture(t, true)
	request := AdmissionRequest{WorkspaceID: d.f.s.WorkspaceID, UserID: d.f.s.UserID}
	for _, mode := range []string{"version", "unknown", "source", "target", "boundary", "values", "copies", "roots", "primary-id", "target-id", "boundary-id", "value-owner", "value-version", "dek-reuse", "copy-holder", "root-recipient", "extra-value", "missing-copy", "missing-root"} {
		t.Run(mode, func(t *testing.T) {
			raw, _ := json.Marshal(d.wire)
			var bad map[string]any
			_ = json.Unmarshal(raw, &bad)
			switch mode {
			case "version":
				bad["formatVersion"] = 2
			case "unknown":
				bad["unbound"] = true
			case "source", "target", "boundary", "values", "copies", "roots":
				bad[mode] = nil
			case "primary-id":
				m := bad["source"].(map[string]any)["metadata"].(map[string]any)
				m["plan"].(map[string]any)["tunnelId"] = uuid.NewString()
			case "target-id":
				bad["target"].([]any)[1] = uuid.NewString()
			case "boundary-id":
				bad["boundary"].([]any)[1] = uuid.NewString()
			case "value-owner":
				bad["values"].([]any)[0].([]any)[1] = uuid.NewString()
			case "value-version":
				bad["values"].([]any)[0].([]any)[5] = "2"
			case "dek-reuse":
				bad["values"].([]any)[0].([]any)[6] = d.parsed.source.accounts[0].values[0].Binding.DEK.ID.String()
			case "copy-holder":
				bad["copies"].([]any)[0].([]any)[5] = uuid.NewString()
			case "root-recipient":
				bad["roots"].([]any)[0].([]any)[5] = d.f.s.Account.Encryption.ID.String()
			case "extra-value":
				bad["values"] = append(bad["values"].([]any), bad["values"].([]any)[0])
			case "missing-copy":
				bad["copies"] = []any{}
			case "missing-root":
				bad["roots"] = []any{}
			}
			raw, _ = json.Marshal(bad)
			if got, err := parseFallbackRelease(raw, request, d.intent); err == nil || got != nil {
				t.Fatal("invalid fallback graph accepted")
			}
		})
	}
	for _, raw := range [][]byte{nil, []byte(`{`), {0xff}, bytes.Repeat([]byte{'x'}, MaxCredentialReleaseBytes+1), []byte(`{"formatVersion":1,"formatVersion":1}`)} {
		if got, err := parseFallbackRelease(raw, request, d.intent); err == nil || got != nil {
			t.Fatal("malformed graph accepted")
		}
	}
}

func TestFallbackUseValidationAndReceiptBindings(t *testing.T) {
	s := NewSession()
	defer s.Close(context.Background())
	node, primary, target := uuid.New(), uuid.New(), uuid.New()
	for _, q := range []struct {
		ctx                   context.Context
		node, primary, target uuid.UUID
		source                string
	}{{nil, node, primary, target, "ui"}, {context.Background(), uuid.Nil, primary, target, "ui"}, {context.Background(), node, uuid.Nil, target, "ui"}, {context.Background(), node, primary, uuid.Nil, "ui"}, {context.Background(), node, primary, primary, "ui"}, {context.Background(), node, primary, target, "bad"}} {
		if _, err := s.BeginFallbackUse(q.ctx, q.node, q.primary, q.target, q.source); err != ErrConfiguration {
			t.Fatal(err)
		}
	}
	if _, err := s.BeginFallbackUse(context.Background(), node, primary, target, "ui"); err != ErrAuthentication {
		t.Fatal(err)
	}
	rows := useIntentRows()
	rows[0] = append(rows[0], []byte(primary.String()), []byte(target.String()))
	for i := 0; i < 10; i++ {
		bad := make([][]byte, len(rows[0]))
		copy(bad, rows[0])
		bad[i] = []byte("bad")
		if _, err := parseFallbackUseIntent([][][]byte{bad}, admissionRequest(), uuid.MustParse(treeFirstID), primary, target); err == nil {
			t.Fatal("unbound receipt", i)
		}
	}
	if _, err := parseFallbackUseIntent(nil, admissionRequest(), node, primary, target); err == nil {
		t.Fatal("empty receipt")
	}
	if _, err := parseFallbackUseIntent(rows, admissionRequest(), uuid.MustParse(treeFirstID), primary, target); err != nil {
		t.Fatal(err)
	}
	valid := FallbackUseIntent{UseIntent: UseIntent{Node: node, Ticket: uuid.New(), Epoch: 1, ExpiresAt: 1}, PrimaryTunnel: primary, FallbackTunnel: target}
	for _, mode := range []string{"node", "ticket", "primary", "target", "same", "epoch", "big-epoch", "sequence", "expiry", "context"} {
		q := valid
		ctx := context.Background()
		switch mode {
		case "node":
			q.Node = uuid.Nil
		case "ticket":
			q.Ticket = uuid.Nil
		case "primary":
			q.PrimaryTunnel = uuid.Nil
		case "target":
			q.FallbackTunnel = uuid.Nil
		case "same":
			q.FallbackTunnel = q.PrimaryTunnel
		case "epoch":
			q.Epoch = 0
		case "big-epoch":
			q.Epoch = math.MaxUint64
		case "sequence":
			q.ChangeSeq = math.MaxUint64
		case "expiry":
			q.ExpiresAt = 0
		case "context":
			ctx = nil
		}
		if _, err := s.FetchFallbackSecret(ctx, q); err != ErrConfiguration {
			t.Fatal(mode, err)
		}
	}
}

func TestFallbackSecretReceiptRejectsEveryUnboundHeader(t *testing.T) {
	d := fallbackReleaseFixture(t, true)
	r := AdmissionRequest{WorkspaceID: d.f.s.WorkspaceID, UserID: d.f.s.UserID, DeviceID: uuid.New()}
	raw, _ := json.Marshal(d.wire)
	row := [][]byte{[]byte(r.WorkspaceID.String()), []byte(r.UserID.String()), []byte(r.DeviceID.String()), []byte(d.intent.Node.String()), []byte(d.intent.Ticket.String()), []byte("1"), []byte("7"), []byte(d.intent.PrimaryTunnel.String()), []byte(d.intent.FallbackTunnel.String()), raw}
	if _, err := parseFallbackSecret([][][]byte{row}, r, d.intent); err != nil {
		t.Fatal(err)
	}
	for i := range row {
		bad := append([][]byte(nil), row...)
		bad[i] = []byte("bad")
		if got, err := parseFallbackSecret([][][]byte{bad}, r, d.intent); err == nil || got != nil {
			t.Fatal("unbound receipt", i)
		}
	}
	for _, rows := range [][][][]byte{nil, {row[:9]}, {row, row}} {
		if got, err := parseFallbackSecret(rows, r, d.intent); err == nil || got != nil {
			t.Fatal("receipt shape")
		}
	}
	s := NewSession()
	defer s.Close(context.Background())
	if _, err := s.FetchFallbackSecret(context.Background(), d.intent); err != ErrAuthentication {
		t.Fatal("unauthenticated secondary fetch", err)
	}
}
