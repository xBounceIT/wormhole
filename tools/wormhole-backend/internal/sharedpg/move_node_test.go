package sharedpg

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestMoveReceiptMatchesOnlySignedRecords(t *testing.T) {
	metadata := vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "Office", Kind: 0}
	encode := func(value any) json.RawMessage {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	edit := NodeEdit{workspace: uuid.New(), user: uuid.New(), signer: vault.KeyRef{ID: uuid.New(), Version: 1}, epoch: 1, sequence: 4}
	edit.node.Boundary = uuid.New()
	seals := nodeRecordSeals{node: vault.RecordSeal{Revision: 2, Signature: bytes.Repeat([]byte{1}, 64)}}
	nodeSeal, _ := seals.hex()
	row := nodeMoveRow{Workspace: edit.workspace, User: edit.user, Epoch: edit.epoch, Sequence: 5,
		Metadata: encode(metadata), Boundary: edit.node.Boundary, Revision: 2, Signer: edit.signer.ID, Version: 1, Seal: string(nodeSeal)}
	check := func(row nodeMoveRow, valid bool) {
		t.Helper()
		receipt, err := edit.verifyMoveReceipt(encode(row), metadata, seals)
		if valid {
			if err != nil || receipt == nil || receipt.Revision() != 2 {
				t.Fatal("valid receipt unavailable", err)
			}
			return
		}
		if receipt != nil || err != ErrAdmissionResponse {
			t.Fatal("accepted a different record", err)
		}
	}
	check(row, true)
	for _, change := range []func(*nodeMoveRow){
		func(r *nodeMoveRow) { r.Workspace = uuid.New() },
		func(r *nodeMoveRow) { r.User = uuid.New() },
		func(r *nodeMoveRow) { r.Sequence = edit.sequence },
		func(r *nodeMoveRow) { r.Epoch++ },
		func(r *nodeMoveRow) { r.Revision++ },
		func(r *nodeMoveRow) { r.Signer = uuid.New() },
		func(r *nodeMoveRow) { r.Seal = "00" },
		func(r *nodeMoveRow) { r.Fields = json.RawMessage("[]") },
		func(r *nodeMoveRow) {
			other := metadata
			parent := uuid.NewString()
			other.ParentID = &parent
			r.Metadata = encode(other)
		},
	} {
		copy := row
		change(&copy)
		check(copy, false)
	}
	fields := []vaultstore.CredentialField{{Field: "inlinePassword", Present: true, Version: 1}}
	edit.fields = &UnverifiedSelection{Record: sharedcatalog.NodeFieldsRecord{NodeID: metadata.ID, Fields: fields}}
	seals.fields = &vault.RecordSeal{Revision: 2, Signature: bytes.Repeat([]byte{2}, 64)}
	_, fieldHex := seals.hex()
	sig := string(fieldHex)
	row.Fields, row.FieldsSeal = encode(fields), &sig
	check(row, true)
	for _, raw := range []string{`null`, `[]`, `[{"field":"inlinePassword","version":1,"present":false}]`,
		`[{"field":"inlinePassword","version":1,"present":true,"extra":1}]`,
		`[{"field":"inlinePassword","version":1,"present":false,"present":true}]`} {
		copy := row
		copy.Fields = json.RawMessage(raw)
		check(copy, false)
	}
	row.FieldsSeal = nil
	check(row, false)
	for _, raw := range []string{`{}`, `{"workspace":null}`, "unknown status"} {
		if receipt, err := edit.verifyMoveReceipt([]byte(raw), metadata, seals); receipt != nil || err != ErrAdmissionResponse {
			t.Fatal("accepted malformed receipt", err)
		}
	}
}
