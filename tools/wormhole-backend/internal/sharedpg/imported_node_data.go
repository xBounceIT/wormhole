package sharedpg

import (
	"context"
	"encoding/hex"
	"math"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/workspaceimport"
)

const maxImportedNodeResponseBytes = 2*vault.MaxUserEnrollmentCertificateBytes + 512*1024

const importedNodeDataSQL = `SELECT user_id::text,device_id::text,projection::text,pg_catalog.encode(body,'hex')
 FROM wormhole_api_v1.imported_node_data(pg_catalog.decode($1,'hex'),$2::uuid)`

type UnverifiedImportedNodeData struct {
	workspace, user uuid.UUID
	record          UnverifiedChainRecord
	body            []byte
}

func parseImportedNodeData(rows [][][]byte, request AdmissionRequest, node uuid.UUID) (*UnverifiedImportedNodeData, error) {
	if len(rows) != 1 || len(rows[0]) != 4 {
		return nil, ErrAdmissionResponse
	}
	row := rows[0]
	if string(row[0]) != request.UserID.String() || string(row[1]) != request.DeviceID.String() ||
		len(row[3]) > 2*workspaceimport.MaxNodeDataBytes {
		return nil, ErrAdmissionResponse
	}
	wire, err := snapshotOptionalRow(row[2], 24)
	if err != nil || wire == nil {
		return nil, ErrAdmissionResponse
	}
	epoch, validEpoch := treeNumber(wire[2], 1, math.MaxInt64)
	sequence, validSequence := treeNumber(wire[3], 0, math.MaxInt64)
	if !validEpoch || !validSequence {
		return nil, ErrAdmissionResponse
	}
	return parseImportedNodeProjection(wire, row[3], request, node, epoch, sequence)
}

func parseImportedNodeProjection(wire [][]byte, attachment []byte, request AdmissionRequest, node uuid.UUID, epoch, sequence uint64) (*UnverifiedImportedNodeData, error) {
	if len(attachment) > 2*workspaceimport.MaxNodeDataBytes {
		return nil, ErrAdmissionResponse
	}
	header, err := parseCatalogProjectionEnvelope([][][]byte{wire}, request, node, epoch, sequence)
	if err != nil {
		return nil, err
	}
	metadata, err := parseTreeMetadata(wire[4])
	if err != nil || metadata.ID != node.String() {
		return nil, ErrAdmissionResponse
	}
	var body []byte
	if attachment != nil {
		body, err = hex.AppendDecode(nil, attachment)
		if err != nil || len(body) == 0 {
			return nil, ErrAdmissionResponse
		}
	}
	return &UnverifiedImportedNodeData{workspace: request.WorkspaceID, user: request.UserID,
		record: UnverifiedChainRecord{Node: UnverifiedTreeNode{Metadata: metadata, Boundary: header.Boundary, Seal: header.Seal}, Author: *header.Author},
		body:   body}, nil
}

// ImportedNodeData returns the original import attachment and its current
// signed node. This metadata read uses the admitted session and never fetches a
// note value or credentials. VerifyImportedNodeData must precede any use.
func (s *Session) ImportedNodeData(ctx context.Context, node uuid.UUID) (result *UnverifiedImportedNodeData, err error) {
	if ctx == nil || node == uuid.Nil {
		return nil, ErrConfiguration
	}
	err = s.queryConnection(ctx, node, importedNodeDataSQL, nil, maxImportedNodeResponseBytes, 4, func(rows [][][]byte, request AdmissionRequest) error {
		var decodeErr error
		result, decodeErr = parseImportedNodeData(rows, request, node)
		return decodeErr
	})
	return result, err
}

// VerifyImportedNodeData authenticates the node anchor before interpreting its
// attachment. Publish the returned trust observations durably before using
// the metadata, including observations returned alongside an error.
func (s TrustState) VerifyImportedNodeData(node uuid.UUID, input *UnverifiedImportedNodeData) (TrustState, *workspaceimport.NodeData, error) {
	observed, err := s.verifyImportedNodeProjection(node, input)
	if err != nil {
		return observed, nil, err
	}
	data, err := workspaceimport.DecodeNodeData(input.record.Node.Metadata, input.body)
	return observed, data, err
}

func (s TrustState) verifyImportedNodeProjection(node uuid.UUID, input *UnverifiedImportedNodeData) (TrustState, error) {
	if input == nil || node == uuid.Nil || input.record.Node.Metadata.ID != node.String() ||
		s.WorkspaceID != input.workspace || s.UserID != input.user {
		return TrustState{}, ErrAdmissionResponse
	}
	if s.Account == nil || !s.Account.Active {
		return TrustState{}, ErrTrustState
	}
	observed, err := s.AdvanceCatalog(input.record.Node, input.record.Author)
	if err != nil {
		return observed, err
	}
	if !observed.Account.Active || observed.Account.Signing != s.Account.Signing || observed.Account.Encryption != s.Account.Encryption {
		return observed, vault.ErrAuthentication
	}
	return observed, nil
}
