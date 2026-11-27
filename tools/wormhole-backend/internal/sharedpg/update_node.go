package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const readNodeEditSQL = `SELECT status,node_row::text,field_row::text FROM wormhole_api_v1.read_node_edit(
 pg_catalog.decode($1,'hex'),$2::uuid,$3::bigint,pg_catalog.decode($4,'hex'),pg_catalog.decode($5,'hex'))`

const updateNodeSQL = `SELECT wormhole_api_v1.update_node(pg_catalog.decode($1,'hex'),$2::uuid,$3::bigint,$4::bigint,$5::bigint,
 $6::jsonb,$7::uuid,$8::integer,pg_catalog.decode($9,'hex'),pg_catalog.decode($10,'hex'),pg_catalog.decode($11,'hex'),pg_catalog.decode($12,'hex'))`

// NodeEdit contains public verified input. The normal controller must durably
// publish its associated trust observations before it borrows the signing key.
type NodeEdit struct {
	workspace, user uuid.UUID
	node            UnverifiedTreeNode
	fields          *UnverifiedSelection
	signer          vault.KeyRef
	epoch, sequence uint64
}

const nodeEditingAPI = `(pg_catalog.to_regprocedure('wormhole_api_v1.read_node_edit(bytea,uuid,bigint,bytea,bytea)') IS NOT NULL
		AND pg_catalog.to_regprocedure('wormhole_api_v1.update_node(bytea,uuid,bigint,bigint,bigint,jsonb,uuid,integer,bytea,bytea,bytea,bytea)') IS NOT NULL)`

func (s *Session) NodeEditingSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, "SELECT "+nodeEditingAPI+"::text")
}

func (s *Session) ReadNodeEdit(ctx context.Context, trust TrustState, id uuid.UUID, revision uint64) (TrustState, *NodeEdit, error) {
	if ctx == nil || id == uuid.Nil || revision == 0 || revision > math.MaxInt64 || trust.Enrollment == nil {
		return TrustState{}, nil, ErrConfiguration
	}
	var edit *NodeEdit
	var rawFields []byte
	args := [][]byte{[]byte(id.String()), strconv.AppendUint(nil, revision, 10)}
	err := s.queryAdministration(ctx, trust, readNodeEditSQL, args, 2*vault.MaxUserEnrollmentCertificateBytes+1024*1024, 3, func(row [][]byte) error {
		if string(row[0]) != "ready" {
			if row[2] != nil {
				return ErrAdmissionResponse
			}
			return pinDenial(string(row[0]), row[1])
		}
		wire, err := snapshotOptionalRow(row[1], 15)
		if err != nil {
			return err
		}
		page, err := parseTreePage([][][]byte{wire}, s.admission, TreeCursor{}, 1)
		if err != nil || len(page.Nodes) != 1 || page.Next != nil {
			return ErrAdmissionResponse
		}
		node := page.Nodes[0]
		if node.Metadata.ID != id.String() || node.Seal.Revision != revision || node.Permissions&permissions.Write == 0 {
			return ErrAdmissionResponse
		}
		edit = &NodeEdit{workspace: trust.WorkspaceID, user: trust.UserID, node: node, epoch: page.Epoch, sequence: page.ChangeSeq, signer: trust.Enrollment.Signing}
		rawFields = bytes.Clone(row[2])
		return nil
	})
	if err != nil || edit == nil {
		return TrustState{}, nil, err
	}
	author, err := s.NodeAuthor(ctx, id, edit.epoch, edit.sequence)
	if err != nil {
		return TrustState{}, nil, err
	}
	if author == nil {
		return TrustState{}, nil, ErrAdmissionResponse
	}
	observed, err := trust.AdvanceCatalog(edit.node, *author)
	if err != nil {
		return observed, nil, err
	}
	inline := edit.node.Metadata.UseInlinePassword
	next, fields, err := verifyEditableFields(rawFields, s.admission, observed, id, &edit.node, edit.epoch, edit.sequence, inline != nil && *inline)
	if next.Revision != 0 {
		observed = next
	}
	if err != nil {
		return observed, nil, err
	}
	edit.fields = fields
	return observed, edit, nil
}

func signEditedNode(trust TrustState, keys *vault.UserKeys, signer vault.KeyRef, boundary uuid.UUID, metadata vaultstore.NodeMetadata, revision uint64, fields *UnverifiedSelection) ([]byte, []byte, error) {
	seals, err := signNodeRecords(trust, keys, signer, boundary, metadata, revision, fields)
	if err != nil {
		return nil, nil, err
	}
	node, manifest := seals.hex()
	return node, manifest, nil
}

type nodeRecordSeals struct {
	node   vault.RecordSeal
	fields *vault.RecordSeal
}

func (s nodeRecordSeals) hex() ([]byte, []byte) {
	var fields []byte
	if s.fields != nil {
		fields = hex.AppendEncode(nil, s.fields.Signature)
	}
	return hex.AppendEncode(nil, s.node.Signature), fields
}

func signNodeRecords(trust TrustState, keys *vault.UserKeys, signer vault.KeyRef, boundary uuid.UUID, metadata vaultstore.NodeMetadata, revision uint64, fields *UnverifiedSelection) (nodeRecordSeals, error) {
	if keys == nil || trust.Enrollment == nil {
		return nodeRecordSeals{}, ErrConfiguration
	}
	public, err := keys.Public()
	if err != nil {
		return nodeRecordSeals{}, err
	}
	digest := enrollmentPublicDigest(public)
	if signer != trust.Enrollment.Signing || !bytes.Equal(digest[:], trust.Enrollment.PublicDigest) {
		return nodeRecordSeals{}, vault.ErrAuthentication
	}
	key := ed25519.NewKeyFromSeed(keys.SigningSeed)
	defer vault.Wipe(key)
	seal, err := sharedcatalog.SignNode(trust.WorkspaceID, boundary, metadata, revision, signer, key)
	if err != nil {
		return nodeRecordSeals{}, err
	}
	result := nodeRecordSeals{node: seal}
	if fields != nil {
		signed, err := sharedcatalog.SignSelection(trust.WorkspaceID, boundary, fields.Record, revision, signer, key)
		if err != nil {
			return nodeRecordSeals{}, err
		}
		result.fields = &signed
	}
	return result, nil
}

// Metadata returns an independent copy. JSON decoding into an inherited
// pointer can otherwise mutate the authenticated baseline of a pending edit.
func (e *NodeEdit) Metadata() (vaultstore.NodeMetadata, error) {
	var copy vaultstore.NodeMetadata
	raw, err := json.Marshal(e.node.Metadata)
	if err != nil {
		return copy, err
	}
	err = json.Unmarshal(raw, &copy)
	return copy, err
}

func (e *NodeEdit) Snapshot() (uint64, uint64) { return e.epoch, e.sequence }

func (s *Session) CommitNodeEdit(ctx context.Context, trust TrustState, edit *NodeEdit, metadata vaultstore.NodeMetadata, keys *vault.UserKeys) (uint64, error) {
	if ctx == nil || edit == nil || edit.workspace != trust.WorkspaceID || edit.user != trust.UserID || edit.node.Seal.Revision >= math.MaxInt64 || trust.Account == nil || !trust.Account.Active {
		return 0, ErrConfiguration
	}
	original := edit.node.Metadata
	if metadata.Validate() != nil || original.ID != metadata.ID || original.Kind != metadata.Kind || !reflect.DeepEqual(original.ParentID, metadata.ParentID) ||
		!reflect.DeepEqual(original.OwnerUserID, metadata.OwnerUserID) || !reflect.DeepEqual(original.Imported, metadata.Imported) ||
		!reflect.DeepEqual(original.SshKnownHostFingerprint, metadata.SshKnownHostFingerprint) || reflect.DeepEqual(original, metadata) {
		return 0, ErrConfiguration
	}
	raw, err := json.Marshal(metadata)
	if err != nil {
		return 0, err
	}
	revision := edit.node.Seal.Revision + 1
	signer := edit.signer
	seal, fields, err := signEditedNode(trust, keys, signer, edit.node.Boundary, metadata, revision, edit.fields)
	if err != nil {
		return 0, err
	}
	args := [][]byte{[]byte(original.ID), strconv.AppendUint(nil, edit.epoch, 10), strconv.AppendUint(nil, edit.sequence, 10), strconv.AppendUint(nil, revision-1, 10), raw,
		[]byte(signer.ID.String()), strconv.AppendUint(nil, uint64(signer.Version), 10), seal, fields}
	var committed uint64
	err = s.queryAdministration(ctx, trust, updateNodeSQL, args, 128, 1, func(row [][]byte) error {
		if string(row[0]) != "changed" {
			return pinDenial(string(row[0]), nil)
		}
		committed = revision
		return nil
	})
	return committed, err
}

// Matches confirms that readback contains exactly the requested signed node and
// the same field-version manifest, signed by the member making this update.
func (e *NodeEdit) Matches(after *NodeEdit, requested vaultstore.NodeMetadata) bool {
	if e == nil || after == nil {
		return false
	}
	next := after.node.Seal
	if e.workspace != after.workspace || e.user != after.user || e.epoch != after.epoch || e.sequence >= after.sequence || next.Revision != e.node.Seal.Revision+1 || e.signer != after.signer ||
		next.SignerKeyID != e.signer.ID.String() || next.SignerKeyVersion != e.signer.Version || e.node.Boundary != after.node.Boundary ||
		!reflect.DeepEqual(requested, after.node.Metadata) || (e.fields == nil) != (after.fields == nil) {
		return false
	}
	return after.fields == nil || (after.fields.Seal.SignerKeyID == next.SignerKeyID && after.fields.Seal.SignerKeyVersion == next.SignerKeyVersion &&
		reflect.DeepEqual(e.fields.Record, after.fields.Record))
}
