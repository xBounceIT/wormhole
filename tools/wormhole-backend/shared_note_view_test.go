package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/workspaceimport"
)

type noteViewProbe struct {
	*credentialReleaseProbe
	supported, allowed bool
	response           *sharedpg.UnverifiedNoteView
	capabilityChecks   int
}

func (p *noteViewProbe) NoteViewSupported(context.Context) (bool, error) {
	p.capabilityChecks++
	return p.supported, nil
}

func (p *noteViewProbe) BeginNoteView(_ context.Context, _ uuid.UUID, revision uint64) (*sharedpg.NoteViewIntent, error) {
	if !p.allowed || revision != 1 {
		return nil, nil
	}
	return &sharedpg.NoteViewIntent{}, nil
}

func (p *noteViewProbe) FetchNote(context.Context, *sharedpg.NoteViewIntent) (*sharedpg.UnverifiedNoteView, error) {
	return p.response, nil
}

func TestSharedNoteDisplayRetainsLegacyWrapAndCommitsBeforeSealing(t *testing.T) {
	ctx := context.Background()
	c, connection, options, node, wire := sharedNoteDisplayFixture(t)
	payload := makeSharedNoteDisplayFixture(t, c, node, wire)
	graph, err := sharedpg.DecodeNoteView(vaultInput(t, payload), options.Request, node, 1, 1, 9)
	if err != nil {
		t.Fatal(err)
	}
	testSharedNoteDisplayProjection(t, payload, options.Request, node)
	probe := &noteViewProbe{credentialReleaseProbe: connection, response: graph}
	c.session = probe
	c.catalogAnchor = func(context.Context, string, []byte, sharedpg.TrustBinding, sharedpg.TrustState) error { return nil }
	handler := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c}}
	defer handler.Close()
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requestID := uuid.NewString()
	request := vaultInput(t, map[string]any{"nodeId": node.String(), "rowVersion": "1", "requestId": requestID, "publicKey": recipient.PublicKey().Bytes()})
	for _, supported := range []bool{false, true} {
		probe.supported = supported
		if raw, err := handler.Handle(ctx, "notes-display", request); err != errSharedNoteUnavailable || raw != nil || !c.Unlocked() {
			t.Fatal("unavailable notes retired an otherwise valid session", err)
		}
	}
	probe.allowed = true
	if raw, err := handler.Handle(ctx, "credential-display", request); err != vaultwire.ErrProtocol || raw != nil {
		t.Fatal("the shared note path enabled credential display", err)
	}
	noteObserved := false
	c.catalogAnchor = func(_ context.Context, path string, key []byte, binding sharedpg.TrustBinding, trust sharedpg.TrustState) error {
		got, err := readSharedTrustFile(path, key, binding, trust.Revision)
		if err == nil {
			noteObserved = got.Catalog["node/"+node.String()].Revision == 1
		}
		return err
	}
	raw, err := handler.Handle(ctx, "notes-display", request)
	var result localvault.NotesDisplay
	if err != nil || !noteObserved || bytes.Contains(raw, []byte("synthetic shared note")) ||
		json.Unmarshal(raw, &result) != nil || result.NodeID != node.String() || result.WorkspaceID != options.Binding.WorkspaceID.String() ||
		result.RowVersion != "1" || result.RequestID != requestID {
		t.Fatal("native display did not return the sealed note after committing trust", err)
	}
	info := []byte("wormhole/v1/notes-display")
	for _, v := range []string{result.WorkspaceID, result.NodeID, requestID, "1"} {
		info = binary.BigEndian.AppendUint32(info, uint32(len(v)))
		info = append(info, v...)
	}
	key, _ := hpke.NewDHKEMPrivateKey(recipient)
	open, err := hpke.NewRecipient(result.Bundle.Enc, key, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := open.Open(nil, result.Bundle.Ciphertext)
	defer vault.Wipe(plain)
	if err != nil || !bytes.Equal(plain, []byte("synthetic shared note")) {
		t.Fatal("isolated native recipient did not receive the imported note", err)
	}
	c.catalogAnchor = func(context.Context, string, []byte, sharedpg.TrustBinding, sharedpg.TrustState) error {
		return errSharedTrustConflict
	}
	if raw, err := handler.Handle(ctx, "notes-display", request); raw != nil || !errors.Is(err, vaultwire.ErrRetired) || c.Unlocked() {
		t.Fatal("failed trust publication did not retire the owner before display", err)
	}
}

func testSharedNoteDisplayProjection(t *testing.T, payload map[string]any, request sharedpg.AdmissionRequest, node uuid.UUID) {
	t.Helper()
	mutateColumn := func(key string, column int, value string) []any {
		row := slices.Clone(payload[key].([]any))
		row[column] = value
		return row
	}
	for _, tc := range []struct {
		field string
		value any
	}{
		{"formatVersion", 2},
		{"node", []any{}},
		{"node", mutateColumn("node", 6, "2")},
		{"attachment", "zz"},
		{"profile", "zz"},
		{"enrollment", "zz"},
		{"enrollment", "00"},
		{"boundary", nil},
		{"boundary", mutateColumn("boundary", 1, uuid.NewString())},
		{"root", mutateColumn("root", 3, "invalid")},
		{"root", mutateColumn("root", 6, "2")},
		{"dek", mutateColumn("dek", 4, "2")},
		{"value", mutateColumn("value", 4, "inlinePassword")},
	} {
		bad := maps.Clone(payload)
		bad[tc.field] = tc.value
		if view, err := sharedpg.DecodeNoteView(vaultInput(t, bad), request, node, 1, 1, 9); view != nil || err == nil {
			t.Fatalf("malformed note projection at %s was accepted", tc.field)
		}
	}
}

func sharedNoteDisplayFixture(t *testing.T) (*sharedAdmissionController, *credentialReleaseProbe, sharedAdmissionOptions, uuid.UUID, map[string]any) {
	t.Helper()
	c, admission, options, root, master, account, org := sharedEnrolledFixture(t)
	if err := c.Unlock(context.Background(), master, vault.KDFV1, false); err != nil {
		t.Fatal(err)
	}
	_, connection, _, _, _, _, node, wire := installCredentialControllerFixture(t, c, &catalogProbe{sharedAdmissionProbe: admission}, options, root, account, org)
	return c, connection, options, node, wire
}

func makeSharedNoteDisplayFixture(t *testing.T, c *sharedAdmissionController, node uuid.UUID, wire map[string]any) map[string]any {
	t.Helper()
	meta := wire["metadata"].(map[string]any)
	row := meta["chain"].([]any)[0].([]any)
	var n vaultstore.NodeMetadata
	if err := json.Unmarshal([]byte(row[4].(string)), &n); err != nil {
		t.Fatal(err)
	}
	attachment, err := json.Marshal(workspaceimport.NodeData{FormatVersion: 1, NodeID: n.ID, NoteVersion: 1, Pins: []resolver.EffectiveCredentialSnapshot{}})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(attachment)
	n.Imported = &vaultstore.NodeImportReference{Digest: hex.EncodeToString(digest[:])}
	metaRaw, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	workspace, boundary := uuid.MustParse(row[0].(string)), uuid.MustParse(row[5].(string))
	if err := c.privateKeys.With(func(keys []byte) error {
		key := ed25519.NewKeyFromSeed(keys[32:])
		defer vault.Wipe(key)
		signer := vault.KeyRef{ID: uuid.MustParse(row[8].(string)), Version: 1}
		seal, err := sharedcatalog.SignNode(workspace, boundary, n, 1, signer, key)
		if err == nil {
			row[4], row[11] = string(metaRaw), hex.EncodeToString(seal.Signature)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	account := wire["accounts"].([]any)[0].(map[string]any)
	dek := account["copies"].([]any)[0].([]any)
	binding := vault.SharedValueBinding{WorkspaceID: workspace, OwnerKind: "node", OwnerID: node, Field: "notes", Version: 1,
		DEK: vault.KeyRef{ID: uuid.MustParse(dek[3].(string)), Version: 1}}
	value, err := vault.SealSharedValue(bytes.Repeat([]byte{23}, 32), binding, []byte("synthetic shared note"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := vault.EncodeSharedEnvelope(value)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"formatVersion": 1, "node": row, "attachment": hex.EncodeToString(attachment), "profile": wire["profile"], "account": wire["account"], "enrollment": wire["enrollment"],
		"boundary": meta["boundaries"].([]any)[0], "root": wire["roots"].([]any)[0], "dek": dek,
		"value": []any{workspace.String(), node.String(), "1", "9", "notes", "1", binding.DEK.ID.String(), "1", hex.EncodeToString(encoded)},
	}
}
