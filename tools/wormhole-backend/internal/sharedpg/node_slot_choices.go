package sharedpg

import (
	"context"
	"strconv"

	"github.com/google/uuid"
)

const nodeSlotChoicesAvailableSQL = `SELECT (pg_catalog.to_regprocedure(
 'wormhole_api_v1.node_slot_choices(bytea,uuid,bigint,bigint,bigint,uuid,bytea,bytea)') IS NOT NULL)::text`
const nodeSlotChoicesSQL = `SELECT status,epoch::text,change_seq::text,payload::text
 FROM wormhole_api_v1.node_slot_choices(pg_catalog.decode($1,'hex'),$2::uuid,$3::bigint,$4::bigint,$5::bigint,$6::uuid,
 pg_catalog.decode($7,'hex'),pg_catalog.decode($8,'hex'))`

// NodeSlotChoices reads signed metadata for the exact node and snapshot open
// in the editor. PostgreSQL checks the editor's node and boundary grants again.
func (s *Session) NodeSlotChoices(ctx context.Context, trust TrustState, edit *NodeEdit, after uuid.UUID) (TrustState, *AdminSlotPage, error) {
	if ctx == nil || edit == nil || edit.workspace != trust.WorkspaceID || edit.user != trust.UserID {
		return trust, nil, ErrConfiguration
	}
	supported, err := s.serverCapability(ctx, nodeSlotChoicesAvailableSQL)
	if err != nil || !supported {
		return trust, nil, err
	}
	epoch, sequence := strconv.FormatUint(edit.epoch, 10), strconv.FormatUint(edit.sequence, 10)
	var cursor []byte
	if after != uuid.Nil {
		cursor = []byte(after.String())
	}
	args := [][]byte{[]byte(edit.node.Metadata.ID), strconv.AppendUint(nil, edit.node.Seal.Revision, 10), []byte(epoch), []byte(sequence), cursor}
	var page *AdminSlotPage
	err = s.queryAdministration(ctx, trust, nodeSlotChoicesSQL, args, adminSlotPageMaxBytes, 4, func(row [][]byte) error {
		if string(row[0]) != "unavailable" && (string(row[1]) != epoch || string(row[2]) != sequence) {
			return ErrAdmissionResponse
		}
		var e error
		trust, page, e = verifyAdminSlotPage(row, trust, after)
		return e
	})
	if err != nil {
		return trust, nil, err
	}
	return trust, page, nil
}
