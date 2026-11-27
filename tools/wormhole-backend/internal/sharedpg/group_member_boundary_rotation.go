package sharedpg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"slices"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const memberRotationJobSQL = `SELECT job_id::text,pending::text,next_boundary::text FROM wormhole_api_v1.group_member_rotation_status(` +
	serverCAArguments + `,$10::uuid,$11::uuid)`
const memberBoundaryRotationCall = ` FROM wormhole_api_v1.rotate_member_boundary(` + serverCAArguments +
	`,$10::uuid,$11::uuid,pg_catalog.decode($12,'hex'),$13::jsonb)`

type GroupMemberRotationProgress struct {
	GroupID uuid.UUID
	JobID   uuid.UUID
	Pending int
	Next    uuid.UUID
}

func (s *Session) ReadGroupMemberRotation(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle,
	group, job uuid.UUID) (result *GroupMemberRotationProgress, err error) {
	if ctx == nil || group == uuid.Nil {
		return nil, ErrConfiguration
	}
	if _, err := authenticatedServerCAContext(trust, tls); err != nil {
		return nil, err
	}
	var requested []byte
	if job != uuid.Nil {
		requested = []byte(job.String())
	}
	err = s.queryServerCA(ctx, trust, memberRotationJobSQL, [][]byte{[]byte(group.String()), requested}, 256, 1, 3, func(rows [][][]byte) error {
		if len(rows) == 0 {
			return nil
		}
		if len(rows) != 1 || len(rows[0]) != 3 {
			return ErrAdmissionResponse
		}
		row := rows[0]
		id, ok := treeID(row[0])
		pending, countOK := treeNumber(row[1], 0, 4096)
		if !ok || !countOK || job != uuid.Nil && id != job || job == uuid.Nil && pending == 0 || pending == 0 && row[2] != nil {
			return ErrAdmissionResponse
		}
		var next uuid.UUID
		if row[2] != nil {
			next, ok = treeID(row[2])
			if !ok {
				return ErrAdmissionResponse
			}
		}
		result = &GroupMemberRotationProgress{GroupID: group, JobID: id, Pending: int(pending), Next: next}
		return nil
	})
	return
}

type MemberBoundaryRotationRequest struct {
	JobID, GroupID, BoundaryID uuid.UUID
	Review                     *[32]byte
}

func (r MemberBoundaryRotationRequest) arguments(publication []byte) [][]byte {
	var review []byte
	if r.Review != nil {
		review = hex.AppendEncode(nil, r.Review[:])
	}
	return [][]byte{[]byte(r.JobID.String()), []byte(r.BoundaryID.String()), review, publication}
}

type MemberBoundaryRotationPreparation struct {
	request  MemberBoundaryRotationRequest
	rotation GroupBoundaryRotationPreparation
}

type memberBoundaryRotationSnapshot struct {
	JobID       uuid.UUID        `json:"jobId"`
	BoundaryID  uuid.UUID        `json:"boundaryId"`
	GroupID     uuid.UUID        `json:"groupId"`
	MemberID    uuid.UUID        `json:"memberId"`
	Revision    string           `json:"groupRevision"`
	Affected    permissions.Mask `json:"affected"`
	Epoch       string           `json:"epoch"`
	ChangeSeq   string           `json:"changeSeq"`
	Boundary    string           `json:"boundary"`
	Group       string           `json:"group"`
	GraphDigest string           `json:"graphDigest"`
}

func (s *Session) PrepareMemberBoundaryRotation(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, request MemberBoundaryRotationRequest) (
	observed TrustState, status string, review *[32]byte, plan *MemberBoundaryRotationPreparation, err error) {
	if ctx == nil || request.JobID == uuid.Nil || request.GroupID == uuid.Nil || request.BoundaryID == uuid.Nil {
		return trust, "", nil, nil, ErrConfiguration
	}
	pin, err := authenticatedServerCAContext(trust, tls)
	if err != nil {
		return trust, "", nil, nil, err
	}
	observed = trust
	err = s.queryServerCA(ctx, trust, boundaryRotationMaterialColumns+memberBoundaryRotationCall, request.arguments(nil),
		maxBoundaryRotationGraph+32768, 1, 15, func(rows [][][]byte) error {
			if len(rows) != 1 || len(rows[0]) != 15 {
				return ErrAdmissionResponse
			}
			row := rows[0]
			status = string(row[0])
			if status != "ready" {
				if (!boundaryRotationStatus(status, false) && status != "roster-changed") || slices.ContainsFunc(row[1:], nonNullGrantColumn) {
					return ErrAdmissionResponse
				}
				return nil
			}
			input, boundary, group, digest, e := verifyMemberBoundarySnapshot(request, row[1])
			if e != nil {
				return e
			}
			observed, e = observed.AdvanceBoundary(request.BoundaryID, boundary)
			if e != nil {
				return e
			}
			observed, e = observed.AdvanceGroupKey(request.GroupID, group)
			if e != nil {
				return e
			}
			if request.Review == nil {
				if slices.ContainsFunc(row[2:], nonNullGrantColumn) {
					return ErrAdmissionResponse
				}
				status, review = "review", &digest
				return nil
			}
			prepared := &MemberBoundaryRotationPreparation{request: request, rotation: GroupBoundaryRotationPreparation{
				boundary: boundary, replacement: &group, removedMember: input.MemberID,
				request: GroupBoundaryGrantRequest{GroupID: request.GroupID.String()},
			}}
			if e := prepared.rotation.readCustody(pin, group.Recovery, row[3:]); e != nil {
				return e
			}
			observed, e = prepared.rotation.verifyGraph(ctx, observed, pin, boundaryRotationGraphScope{
				Epoch: input.Epoch, ChangeSeq: input.ChangeSeq, Digest: input.GraphDigest, Affected: input.Affected,
			}, row[2])
			if e != nil {
				return e
			}
			prepared.rotation.trust = cloneTrustState(observed)
			plan = prepared
			return nil
		})
	return
}

func verifyMemberBoundarySnapshot(request MemberBoundaryRotationRequest, raw []byte) (
	memberBoundaryRotationSnapshot, vault.BoundaryManifest, vault.GroupKeyManifest, [32]byte, error) {
	var input memberBoundaryRotationSnapshot
	var boundary vault.BoundaryManifest
	var group vault.GroupKeyManifest
	var digest [32]byte
	if len(raw) > 32768 {
		return input, boundary, group, digest, ErrAdmissionResponse
	}
	if _, err := strictCatalogObject(raw, input); err != nil || json.Unmarshal(raw, &input) != nil ||
		input.JobID != request.JobID || input.BoundaryID != request.BoundaryID || input.GroupID != request.GroupID ||
		input.MemberID == uuid.Nil || !validGroupBoundaryMask(input.Affected) {
		return input, boundary, group, digest, ErrAdmissionResponse
	}
	revision, revisionOK := treeNumber([]byte(input.Revision), 1, math.MaxInt64-1)
	_, epochOK := treeNumber([]byte(input.Epoch), 1, math.MaxInt64)
	_, seqOK := treeNumber([]byte(input.ChangeSeq), 0, math.MaxInt64)
	hash, err := hex.DecodeString(input.GraphDigest)
	if !revisionOK || !epochOK || !seqOK || err != nil || len(hash) != sha256.Size || hex.EncodeToString(hash) != input.GraphDigest {
		return input, boundary, group, digest, ErrAdmissionResponse
	}
	boundaryRaw, e1 := hex.DecodeString(input.Boundary)
	groupRaw, e2 := hex.DecodeString(input.Group)
	boundary, e3 := vault.DecodeBoundaryManifest(boundaryRaw)
	group, e4 := vault.DecodeGroupKeyManifest(groupRaw)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || boundary.OwnerUserID != uuid.Nil || !boundary.OrgEscrow ||
		boundary.PreviousView != nil || boundary.PreviousSecret != nil || group.GroupRevision != revision || group.Key.Key.Version < 2 ||
		group.Signer != boundary.Signer {
		return input, boundary, group, digest, ErrAdmissionResponse
	}
	h := sha256.New()
	h.Write([]byte("wormhole/v1/member-boundary-review:"))
	h.Write(raw)
	copy(digest[:], h.Sum(nil))
	if request.Review != nil && *request.Review != digest {
		return input, boundary, group, digest, vault.ErrAuthentication
	}
	return input, boundary, group, digest, nil
}

func (s *Session) CommitPreparedMemberBoundaryRotation(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle,
	plan *MemberBoundaryRotationPreparation, keys *vault.UserKeys) (TrustState, GroupBoundaryGrantReply, error) {
	if plan == nil || plan.request.Review == nil {
		return trust, GroupBoundaryGrantReply{}, ErrConfiguration
	}
	return s.commitBoundaryRotation(ctx, trust, tls, &plan.rotation, keys, memberBoundaryRotationCall, plan.request.arguments)
}
