package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func inlineReleaseFixture(t *testing.T, mode string) (connectionFixture, map[string]any) {
	t.Helper()
	kind := "saved"
	if mode == "rdp-gateway" {
		kind = "gateway"
	}
	f, w := releaseGraphFixture(t, kind, true, false)
	leaf := &f.records.Chain[0].Node
	enabled := true
	leaf.Metadata.UseInlinePassword = &enabled
	if mode == "rdp" || mode == "rdp-gateway" {
		protocol := 1
		leaf.Metadata.Protocol = &protocol
	}
	f.records.Credential = nil
	f.signChain(t)
	metadata := w["metadata"].(map[string]any)
	nodeRow := metadata["chain"].([]any)[0].([]any)
	raw, _ := json.Marshal(leaf.Metadata)
	nodeRow[4], nodeRow[11] = string(raw), hex.EncodeToString(leaf.Seal.Signature)
	metadata["credential"] = nil
	_, plan, err := f.s.ResolveCatalogConnection(context.Background(), f.node(), f.records)
	if err != nil {
		t.Fatal(err)
	}
	metadata["plan"] = plan
	record := sharedcatalog.NodeFieldsRecord{NodeID: f.node().String(), Fields: []vaultstore.CredentialField{{Field: "inlinePassword", Version: 9, Present: true}}}
	account := w["accounts"].([]any)[0].(map[string]any)
	account["account"] = "inline"
	row := account["values"].([]any)[0].([]any)
	password := []byte("inline-secret")
	if mode == "empty" {
		password = []byte{}
	}
	binding := vault.SharedValueBinding{WorkspaceID: f.s.WorkspaceID, OwnerKind: "node", OwnerID: f.node(), Field: "inlinePassword", Version: 9, DEK: vault.KeyRef{ID: uuid.MustParse(row[6].(string)), Version: 3}}
	value, err := vault.SealSharedValue(bytes.Repeat([]byte{23}, 32), binding, password)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = vault.EncodeSharedEnvelope(value)
	if err != nil {
		t.Fatal(err)
	}
	row[1], row[4], row[8] = f.node().String(), "inlinePassword", hex.EncodeToString(raw)
	if mode == "absent" || mode == "removed" || mode == "deleted" {
		if mode == "absent" {
			record.Fields = []vaultstore.CredentialField{}
		} else {
			record.Fields[0].Present = false
		}
		record.Deleted = mode == "deleted"
		account["values"], account["copies"] = []any{}, []any{}
		w["roots"] = []any{}
	}
	seal, err := sharedcatalog.SignSelection(f.s.WorkspaceID, leaf.Boundary, record, leaf.Seal.Revision, f.records.Chain[0].Author.Key, f.key)
	if err != nil {
		t.Fatal(err)
	}
	fieldRow := append([]any{}, nodeRow...)
	raw, _ = json.Marshal(record)
	fieldRow[4], fieldRow[11] = string(raw), hex.EncodeToString(seal.Signature)
	w["formatVersion"], w["nodeFields"] = 3, fieldRow
	return f, w
}

func TestNodeFieldsInlineReleaseOpensOnlyBoundFieldsAndWipes(t *testing.T) {
	for _, mode := range []string{"password", "empty", "absent", "removed", "rdp", "rdp-gateway"} {
		t.Run(mode, func(t *testing.T) {
			f, w := inlineReleaseFixture(t, mode)
			g, err := releaseParseFixture(t, f, w)
			if err != nil {
				t.Fatal(err)
			}
			next, v, err := f.s.VerifyCredentialRelease(context.Background(), f.node(), g)
			if err != nil || v == nil || f.s.ValidateAdvance(next) != nil {
				t.Fatal("inline verification", err)
			}
			if next.Catalog["node-fields/"+f.node().String()].Revision != g.inline.Selection.Seal.Revision {
				t.Fatal("manifest floor missing")
			}
			var original []byte
			var gateway []byte
			err = v.WithValues(context.Background(), next, bytes.Repeat([]byte{17}, 32), func(p resolver.Plan, values CredentialReleaseValues) error {
				if p.Credential.Kind != "inline" || values.Primary != nil || (mode != "rdp-gateway" && values.Gateway != nil) || values.Inline == nil || values.Inline.NodeID != f.node().String() {
					t.Fatal("inline became a saved account")
				}
				value, present := values.Inline.Fields["inlinePassword"]
				if present != (mode == "password" || mode == "empty" || mode == "rdp" || mode == "rdp-gateway") {
					t.Fatal("inline presence")
				}
				want := ""
				if mode == "password" || mode == "rdp" || mode == "rdp-gateway" {
					want = "inline-secret"
				}
				if string(value) != want {
					t.Fatal("inline content")
				}
				original = value
				if mode == "rdp-gateway" {
					if values.Gateway == nil || string(values.Gateway.Fields["password"]) != "gateway-secret" {
						t.Fatal("inline gateway account lost")
					}
					gateway = values.Gateway.Fields["password"]
				}
				raw, _ := json.Marshal(values)
				if string(raw) != "{}" {
					t.Fatal("private JSON")
				}
				raw, _ = json.Marshal(values.Inline)
				if bytes.Contains(raw, []byte("inline-secret")) {
					t.Fatal("node plaintext JSON")
				}
				delete(values.Inline.Fields, "inlinePassword")
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			assertReleaseWiped(t, [][]byte{original, gateway})
		})
	}
}

func TestNodeFieldsInlineReleaseRejectsUnboundOrAmbiguousMaterial(t *testing.T) {
	for _, mode := range []string{"missing", "null", "format2", "row", "owner", "boundary", "revision", "case", "extra", "missing-field", "null-fields", "unknown-field", "zero", "wrong-kind", "saved-profile", "saved-value", "value-owner", "field-version", "copy", "root", "tunnel", "signature", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f, w := inlineReleaseFixture(t, "password")
			row := w["nodeFields"].([]any)
			account := w["accounts"].([]any)[0].(map[string]any)
			value := account["values"].([]any)[0].([]any)
			var body map[string]any
			_ = json.Unmarshal([]byte(row[4].(string)), &body)
			switch mode {
			case "missing":
				delete(w, "nodeFields")
			case "null":
				w["nodeFields"] = nil
			case "format2":
				w["formatVersion"] = 2
			case "row":
				w["nodeFields"] = []any{}
			case "owner":
				row[1] = uuid.NewString()
			case "boundary":
				row[5] = uuid.NewString()
			case "revision":
				row[6] = "99"
			case "case":
				body["NodeId"] = body["nodeId"]
				delete(body, "nodeId")
			case "extra":
				body["password"] = "not allowed"
			case "missing-field":
				delete(body, "fields")
			case "null-fields":
				body["fields"] = nil
			case "unknown-field":
				body["fields"].([]any)[0].(map[string]any)["extra"] = true
			case "zero":
				body["fields"].([]any)[0].(map[string]any)["version"] = 0
			case "wrong-kind":
				account["account"] = "primary"
			case "saved-profile":
				metadata := w["metadata"].(map[string]any)
				metadata["credential"] = row
			case "saved-value":
				value[4] = "password"
			case "value-owner":
				value[1] = uuid.NewString()
			case "field-version":
				value[5] = "8"
			case "copy":
				account["copies"] = []any{}
			case "root":
				w["roots"] = []any{}
			case "tunnel":
				m := w["metadata"].(map[string]any)
				p := m["plan"].(resolver.Plan)
				p.TunnelID = uuid.NewString()
				m["plan"] = p
			case "signature":
				row[11] = hex.EncodeToString(make([]byte, 64))
			}
			raw, _ := json.Marshal(body)
			row[4] = string(raw)
			g, err := releaseParseFixture(t, f, w)
			if mode == "signature" || mode == "cancel" {
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if mode == "cancel" {
					cancel()
				}
				_, v, err := f.s.VerifyCredentialRelease(ctx, f.node(), g)
				if err == nil || v != nil {
					t.Fatal("unverified inline prepared")
				}
			} else if err == nil || g != nil {
				t.Fatal("malformed inline accepted", mode)
			}
		})
	}
}

func TestNodeFieldsManifestTrustSurvivesPersistenceAndRejectsForks(t *testing.T) {
	root, b, s, c, a, _, key := credentialTrustFixture(t)
	id := uuid.NewString()
	r := sharedcatalog.NodeFieldsRecord{NodeID: id, Fields: []vaultstore.CredentialField{{Field: "inlinePassword", Version: 1, Present: true}}}
	seal, err := sharedcatalog.SignSelection(b.WorkspaceID, c.Boundary, r, 5, a.Key, key)
	if err != nil {
		t.Fatal(err)
	}
	signed := UnverifiedSelection{Record: r, Boundary: c.Boundary, Seal: seal}
	next, err := s.AdvanceSelection(signed, a)
	if err != nil || s.ValidateAdvance(next) != nil {
		t.Fatal(err)
	}
	raw, err := SealTrustState(root, b, next)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := OpenTrustState(root, b, raw, next.Revision)
	if err != nil || !reflect.DeepEqual(restored, next) {
		t.Fatal("manifest trust lost", err)
	}
	fork := r
	fork.Fields = []vaultstore.CredentialField{{Field: "inlinePassword", Version: 2, Present: true}}
	seal, err = sharedcatalog.SignSelection(b.WorkspaceID, c.Boundary, fork, 5, a.Key, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restored.AdvanceSelection(UnverifiedSelection{Record: fork, Boundary: c.Boundary, Seal: seal}, a); err != ErrCatalogEquivocation {
		t.Fatal("manifest same revision fork", err)
	}
	f, w := inlineReleaseFixture(t, "deleted")
	g, err := releaseParseFixture(t, f, w)
	if err != nil {
		t.Fatal(err)
	}
	observed, v, err := f.s.VerifyCredentialRelease(context.Background(), f.node(), g)
	if err != vaultstore.ErrMissing || v != nil || observed.Catalog["node-fields/"+f.node().String()].Revision == 0 {
		t.Fatal("lost signed tombstone observation", err)
	}
}

func TestNodeFieldsInlineBorrowFailureAlwaysWipes(t *testing.T) {
	for _, mode := range []string{"callback", "panic", "cancel", "private"} {
		t.Run(mode, func(t *testing.T) {
			f, w := inlineReleaseFixture(t, "password")
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
			if mode == "private" {
				private = make([]byte, 32)
			}
			var original []byte
			failure := errors.New("inline callback failed")
			use := func(_ resolver.Plan, values CredentialReleaseValues) error {
				if mode == "private" {
					t.Fatal("invalid key reached callback")
				}
				original = values.Inline.Fields["inlinePassword"]
				delete(values.Inline.Fields, "inlinePassword")
				if mode == "panic" {
					panic(failure)
				}
				if mode == "cancel" {
					cancel()
					return nil
				}
				return failure
			}
			if mode == "panic" {
				func() {
					defer func() {
						if recover() != failure {
							t.Fatal("lost callback panic")
						}
					}()
					_ = v.WithValues(ctx, next, private, use)
				}()
			} else if err := v.WithValues(ctx, next, private, use); err == nil {
				t.Fatal("failed inline borrow succeeded")
			}
			assertReleaseWiped(t, [][]byte{original})
		})
	}
}

func TestNodeFieldsExtendedSavedGraphRequiresExplicitNullManifest(t *testing.T) {
	f, w := releaseGraphFixture(t, "saved", true, false)
	w["formatVersion"], w["nodeFields"] = 3, nil
	g, err := releaseParseFixture(t, f, w)
	if err != nil {
		t.Fatal(err)
	}
	if _, v, err := f.s.VerifyCredentialRelease(context.Background(), f.node(), g); err != nil || v == nil {
		t.Fatal(err)
	}
	w["nodeFields"] = []any{}
	if g, err := releaseParseFixture(t, f, w); err == nil || g != nil {
		t.Fatal("extraneous node fields accepted")
	}
}
