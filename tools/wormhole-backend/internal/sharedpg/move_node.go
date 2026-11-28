package sharedpg

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"reflect"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const moveNodeSQL = `SELECT wormhole_api_v1.move_node(pg_catalog.decode($1,'hex'),$2::uuid,$3::bigint,$4::bigint,$5::bigint,
 $6::jsonb,$7::uuid,$8::integer,pg_catalog.decode($9,'hex'),pg_catalog.decode($10,'hex'),pg_catalog.decode($11,'hex'),pg_catalog.decode($12,'hex'))`

func (s *Session) NodeMovingSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, `SELECT (pg_catalog.to_regprocedure('wormhole_api_v1.move_node(bytea,uuid,bigint,bigint,bigint,jsonb,uuid,integer,bytea,bytea,bytea,bytea)') IS NOT NULL)::text`)
}

type nodeMoveRow struct {
	Workspace  uuid.UUID       `json:"workspace"`
	User       uuid.UUID       `json:"user"`
	Epoch      uint64          `json:"epoch"`
	Sequence   uint64          `json:"sequence"`
	Metadata   json.RawMessage `json:"metadata"`
	Boundary   uuid.UUID       `json:"boundary"`
	Revision   uint64          `json:"revision"`
	Signer     uuid.UUID       `json:"signer"`
	Version    uint32          `json:"version"`
	Seal       string          `json:"seal"`
	Fields     json.RawMessage `json:"fields"`
	FieldsSeal *string         `json:"fieldsSeal"`
}

// A successful move can remove its writer's inherited visibility. Its receipt
// covers only the exact public records this device signed in this transaction.
type NodeMoveReceipt struct {
	workspace, user, node uuid.UUID
	signer                vault.KeyRef
	seals                 nodeRecordSeals
}

func (r *NodeMoveReceipt) Revision() uint64 { return r.seals.node.Revision }

func (r *NodeMoveReceipt) Advance(trust TrustState) (TrustState, error) {
	if r == nil || !trust.valid() || trust.Account == nil || !trust.Account.Active || trust.Enrollment == nil ||
		trust.WorkspaceID != r.workspace || trust.UserID != r.user || trust.Enrollment.Signing != r.signer {
		return TrustState{}, ErrTrustState
	}
	entries := []catalogFloorObservation{{"node/" + r.node.String(), r.Revision(), r.seals.node}}
	if r.seals.fields != nil {
		entries = append(entries, catalogFloorObservation{"node-fields/" + r.node.String(), r.Revision(), *r.seals.fields})
	}
	for _, entry := range entries {
		if trust.Catalog[entry.key].Revision > entry.revision {
			return TrustState{}, ErrTrustRollback
		}
	}
	return trust.mergeCatalogObservations(*trust.Account, trust.catalogAuthorFloor(r.user), 0, nil, entries...)
}

func (s *Session) CommitNodeMove(ctx context.Context, trust TrustState, edit *NodeEdit, parent *uuid.UUID, keys *vault.UserKeys) (*NodeMoveReceipt, error) {
	if ctx == nil || edit == nil || trust.Account == nil || !trust.Account.Active || edit.workspace != trust.WorkspaceID ||
		edit.user != trust.UserID || edit.node.Seal.Revision >= math.MaxInt64 {
		return nil, ErrConfiguration
	}
	metadata := edit.node.Metadata
	metadata.ParentID = nil
	if parent != nil {
		id := parent.String()
		metadata.ParentID = &id
	}
	if metadata.Validate() != nil || reflect.DeepEqual(metadata.ParentID, edit.node.Metadata.ParentID) {
		return nil, ErrConfiguration
	}
	seals, err := signNodeRecords(trust, keys, edit.signer, edit.node.Boundary, metadata, edit.node.Seal.Revision+1, edit.fields)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	nodeSeal, fieldSeal := seals.hex()
	args := [][]byte{[]byte(metadata.ID), strconv.AppendUint(nil, edit.epoch, 10), strconv.AppendUint(nil, edit.sequence, 10),
		strconv.AppendUint(nil, edit.node.Seal.Revision, 10), raw, []byte(edit.signer.ID.String()), strconv.AppendUint(nil, uint64(edit.signer.Version), 10), nodeSeal, fieldSeal}
	var receipt *NodeMoveReceipt
	err = s.queryAdministration(ctx, trust, moveNodeSQL, args, 1024*1024, 1, func(row [][]byte) error {
		var err error
		receipt, err = edit.verifyMoveReceipt(row[0], metadata, seals)
		return err
	})
	return receipt, err
}

func (edit *NodeEdit) verifyMoveReceipt(raw []byte, metadata vaultstore.NodeMetadata, seals nodeRecordSeals) (*NodeMoveReceipt, error) {
	if len(raw) == 0 || raw[0] != '{' {
		return nil, pinDenial(string(raw), nil)
	}
	var result nodeMoveRow
	if _, err := strictCatalogObject(raw, result, "fields", "fieldsSeal"); err != nil || json.Unmarshal(raw, &result) != nil {
		return nil, ErrAdmissionResponse
	}
	nodeSeal, fieldSeal := seals.hex()
	actual, err := parseTreeMetadata(result.Metadata)
	if err != nil || !reflect.DeepEqual(actual, metadata) || result.Workspace != edit.workspace || result.User != edit.user ||
		result.Epoch != edit.epoch || result.Sequence <= edit.sequence || result.Sequence > math.MaxInt64 || result.Boundary != edit.node.Boundary ||
		result.Revision != seals.node.Revision || result.Signer != edit.signer.ID || result.Version != edit.signer.Version || result.Seal != string(nodeSeal) {
		return nil, ErrAdmissionResponse
	}
	if edit.fields == nil {
		if !bytes.Equal(result.Fields, []byte("null")) || result.FieldsSeal != nil {
			return nil, ErrAdmissionResponse
		}
	} else {
		expected, ok := edit.fields.Record.(sharedcatalog.NodeFieldsRecord)
		var fields []vaultstore.CredentialField
		if !ok || result.FieldsSeal == nil || *result.FieldsSeal != string(fieldSeal) || validateCatalogFields(result.Fields, 1) != nil || json.Unmarshal(result.Fields, &fields) != nil || !reflect.DeepEqual(fields, expected.Fields) {
			return nil, ErrAdmissionResponse
		}
	}
	return &NodeMoveReceipt{workspace: edit.workspace, user: edit.user, node: uuid.MustParse(metadata.ID), signer: edit.signer, seals: seals}, nil
}
