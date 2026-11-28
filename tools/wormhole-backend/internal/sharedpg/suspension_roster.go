package sharedpg

import (
	"bytes"
	"context"
	"math"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const suspensionRosterSQL = `SELECT pg_catalog.convert_from(wormhole_api_v1.suspension_signed_roster(
	pg_catalog.decode($1,'hex'),$2::uuid,$3::uuid,$4::bigint),'UTF8')`

// The caller has already verified the signed manifest and the new holders'
// enrollment certificates. A suspension can remove its subject; it cannot
// authorize adding or dropping any other member, even during reconciliation.
func (s *Session) checkSuspensionRoster(ctx context.Context, trust TrustState, request GroupMemberRotationRequest, prior vault.GroupKeyManifest, holders []groupKeyHolder) (bool, error) {
	target := request.Automatic
	if target == nil || target.ID == uuid.Nil || target.Revision < 2 || target.Revision > math.MaxInt64 ||
		prior.WorkspaceID != trust.WorkspaceID || prior.GroupID != request.GroupID ||
		(!request.Reconcile && (target.ID != request.MemberID || target.Revision != request.Suspension)) {
		return false, ErrConfiguration
	}
	supported, err := s.SuspensionReceiptsSupported(ctx)
	if err != nil || !supported {
		return false, err
	}
	args := [][]byte{[]byte(request.GroupID.String()), []byte(target.ID.String()), strconv.AppendUint(nil, target.Revision, 10)}
	var allowed bool
	err = s.queryAuthenticated(ctx, suspensionRosterSQL, args, maxGroupRosterBytes, 1, func(rows [][][]byte, admission AdmissionRequest) error {
		if admission.WorkspaceID != trust.WorkspaceID || admission.UserID != trust.UserID || len(rows) != 1 || len(rows[0]) != 1 {
			return ErrAdmissionResponse
		}
		allowed = sameSuspensionMembers(rows[0][0], prior, holders, target.ID, request.Reconcile)
		return nil
	})
	return allowed, err
}

func sameSuspensionMembers(raw []byte, prior vault.GroupKeyManifest, holders []groupKeyHolder, subject uuid.UUID, reconcile bool) bool {
	digest := groupKeyReviewDigest(GroupKeyRequest{GroupID: prior.GroupID, Revision: prior.GroupRevision}, raw)
	if !bytes.Equal(prior.RosterDigest, digest[:]) {
		return false
	}
	rows, err := snapshotRows(raw, maxGroupRoster, 5)
	if err != nil {
		return false
	}
	remaining := 0
	found := false
	for _, row := range rows {
		user, ok := treeID(row[0])
		if !ok {
			return false
		}
		if user == subject {
			if reconcile || found {
				return false
			}
			found = true
			continue
		}
		if remaining >= len(holders) || holders[remaining].member.ID != user {
			return false
		}
		remaining++
	}
	return remaining == len(holders) && (reconcile || found)
}
