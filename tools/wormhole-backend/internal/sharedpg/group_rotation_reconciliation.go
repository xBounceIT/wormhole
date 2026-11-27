package sharedpg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"slices"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const memberReconciliationSignature = "wormhole_api_v1.reconcile_group_member_rotation(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,uuid,bytea,jsonb)"
const memberReconciliationSupportedSQL = "SELECT (pg_catalog.to_regprocedure('" + memberReconciliationSignature + "') IS NOT NULL)::text"
const memberReconciliationCall = ` FROM wormhole_api_v1.reconcile_group_member_rotation(` + serverCAArguments +
	`,$10::uuid,$11::uuid,pg_catalog.decode($12,'hex'),$13::jsonb)`
const memberReconciliationResultSQL = `SELECT status,pg_catalog.convert_from(manifest,'UTF8')` + memberReconciliationCall
const memberReconciliationMaterialSQL = `SELECT status,pg_catalog.convert_from(snapshot,'UTF8'),pg_catalog.convert_from(roster,'UTF8'),` + serverCAKeyColumns +
	`,recipient_id::text,recipient_version::text,encode(recipient_public,'hex'),encode(recipient_signature,'hex')` + memberReconciliationCall

type GroupMemberReconciliationPreview struct {
	JobID         uuid.UUID        `json:"jobId"`
	GroupID       uuid.UUID        `json:"groupId"`
	TargetGroupID uuid.UUID        `json:"targetGroupId"`
	GroupName     string           `json:"groupName"`
	Boundaries    int              `json:"boundaries"`
	Members       []GroupKeyMember `json:"members"`
	Review        string           `json:"review"`
}

type memberReconciliationSnapshot struct {
	RequestJobID   uuid.UUID            `json:"requestJobId"`
	RequestGroupID uuid.UUID            `json:"requestGroupId"`
	JobID          uuid.UUID            `json:"jobId"`
	GroupID        uuid.UUID            `json:"groupId"`
	GroupName      string               `json:"groupName"`
	Revision       string               `json:"groupRevision"`
	RemovedMember  uuid.UUID            `json:"removedMemberId"`
	Previous       string               `json:"previous"`
	RosterDigest   string               `json:"rosterDigest"`
	Pending        []memberRotationRoot `json:"pending"`
	Additional     []memberRotationRoot `json:"additional"`
	Boundaries     int                  `json:"boundaries"`
}

type GroupMemberReconciliationPreparation struct {
	request GroupMemberRotationRequest
	trust   TrustState
	key     GroupKeyPreparation
}

func (r GroupMemberRotationRequest) validReconciliation() bool {
	return r.Reconcile && r.JobID != uuid.Nil && r.GroupID != uuid.Nil && r.MemberID == uuid.Nil &&
		r.Login == "" && r.Revision == 0 && r.Suspension == 0
}

func (r GroupMemberRotationRequest) reconciliationArguments(publication []byte) [][]byte {
	var review []byte
	if r.Review != nil {
		review = hex.AppendEncode(nil, r.Review[:])
	}
	return [][]byte{[]byte(r.GroupID.String()), []byte(r.JobID.String()), review, publication}
}

func (s *Session) GroupMemberReconciliationSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, memberReconciliationSupportedSQL)
}

func reconciliationStatus(status string) bool {
	switch status {
	case "busy", "stale", "incomplete", "unavailable", "unchanged":
		return true
	}
	return false
}

func (s *Session) PrepareGroupMemberReconciliation(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, request GroupMemberRotationRequest) (observed TrustState, reply GroupMemberRotationReply, plan *GroupMemberReconciliationPreparation, err error) {
	observed = trust
	if ctx == nil || !request.validReconciliation() {
		return trust, reply, nil, ErrConfiguration
	}
	pin, err := authenticatedServerCAContext(trust, tls)
	if err != nil {
		return trust, reply, nil, err
	}
	var prior vault.GroupKeyManifest
	err = s.queryServerCA(ctx, trust, memberReconciliationMaterialSQL, request.reconciliationArguments(nil), maxGroupRosterBytes+(1<<20)+8192, 1, 12, func(rows [][][]byte) error {
		if len(rows) != 1 || len(rows[0]) != 12 {
			return ErrAdmissionResponse
		}
		row := rows[0]
		reply.Status = string(row[0])
		if reply.Status != "ready" {
			if !reconciliationStatus(reply.Status) || slices.ContainsFunc(row[1:], nonNullGrantColumn) {
				return ErrAdmissionResponse
			}
			return nil
		}
		input, previous, revision, digest, e := decodeMemberReconciliationSnapshot(request, row[1], row[2])
		if e != nil {
			return e
		}
		observed, e = observed.AdvanceGroupKey(input.GroupID, previous)
		if e != nil {
			return e
		}
		if request.Automatic != nil && (input.GroupID != request.GroupID || input.RemovedMember != request.Automatic.ID) {
			reply = GroupMemberRotationReply{Status: "incomplete"}
			return nil
		}
		var holders []groupKeyHolder
		if !bytes.Equal(row[2], []byte("[]")) {
			observed, holders, e = verifyGroupKeyRoster(observed, row[2])
			if e != nil {
				return e
			}
		}
		members := make([]GroupKeyMember, 0, len(holders))
		for _, holder := range holders {
			if holder.member.ID == input.RemovedMember {
				return vault.ErrAuthentication
			}
			members = append(members, holder.member)
		}
		if request.Review == nil {
			if slices.ContainsFunc(row[3:], nonNullGrantColumn) {
				return ErrAdmissionResponse
			}
			reply = GroupMemberRotationReply{Status: "reconcile-review", Reconciliation: &GroupMemberReconciliationPreview{
				JobID: request.JobID, GroupID: request.GroupID, TargetGroupID: input.GroupID, GroupName: input.GroupName,
				Boundaries: input.Boundaries, Members: members, Review: hex.EncodeToString(digest[:]),
			}}
			return nil
		}
		custody, e := parsePersonalImportSigner([][][]byte{row[3:]}, trust.WorkspaceID)
		if e != nil || custody.recipient.Encryption != previous.Recovery {
			return ErrAdmissionResponse
		}
		if e := vault.VerifyOrganisationRecoveryRecipient(custody.recipient, custody.certificate, trust.WorkspaceID, pin.Signer, pin.Organisation); e != nil {
			return e
		}
		keyRequest := GroupKeyRequest{GroupID: input.GroupID, Revision: revision}
		rosterDigest := groupKeyReviewDigest(keyRequest, row[2])
		keyRequest.Review = &rosterDigest
		prior = previous
		plan = &GroupMemberReconciliationPreparation{request: request, trust: cloneTrustState(observed),
			key: GroupKeyPreparation{request: keyRequest, previous: previous.Key.Key, holders: holders, custody: custody}}
		return nil
	})
	if err == nil && plan != nil && request.Automatic != nil {
		var allowed bool
		allowed, err = s.checkSuspensionRoster(ctx, trust, request, prior, plan.key.holders)
		if !allowed {
			plan, reply = nil, GroupMemberRotationReply{Status: "incomplete"}
		}
	}
	return
}

func decodeMemberReconciliationSnapshot(request GroupMemberRotationRequest, raw, roster []byte) (input memberReconciliationSnapshot, previous vault.GroupKeyManifest, revision uint64, digest [32]byte, err error) {
	if len(raw) > 1<<20 || len(roster) == 0 || len(roster) > maxGroupRosterBytes {
		return input, previous, 0, digest, ErrAdmissionResponse
	}
	if _, err := strictCatalogObject(raw, input); err != nil || json.Unmarshal(raw, &input) != nil ||
		input.RequestJobID != request.JobID || input.RequestGroupID != request.GroupID || input.JobID == uuid.Nil || input.GroupID == uuid.Nil ||
		(input.JobID == request.JobID) != (input.GroupID == request.GroupID) || input.RemovedMember == uuid.Nil || !adminGroupText(input.GroupName, 256) ||
		len(input.Pending) == 0 || input.Additional == nil || len(input.Pending)+len(input.Additional) > 4096 {
		return input, previous, 0, digest, ErrAdmissionResponse
	}
	revision, valid := treeNumber([]byte(input.Revision), 1, math.MaxInt64-1)
	manifest, err := hex.DecodeString(input.Previous)
	if !valid || err != nil {
		return input, previous, 0, digest, ErrAdmissionResponse
	}
	previous, err = vault.DecodeGroupKeyManifest(manifest)
	if err != nil || previous.GroupID != input.GroupID || previous.GroupRevision >= revision || previous.Key.Key.Version < 2 || previous.Key.Key.Version >= math.MaxInt32 {
		return input, previous, 0, digest, ErrAdmissionResponse
	}
	current := sha256.Sum256(roster)
	prior := groupKeyReviewDigest(GroupKeyRequest{GroupID: input.GroupID, Revision: previous.GroupRevision}, roster)
	if input.RosterDigest != hex.EncodeToString(current[:]) || bytes.Equal(prior[:], previous.RosterDigest) {
		return input, previous, 0, digest, vault.ErrAuthentication
	}
	boundaries := make(map[uuid.UUID]permissions.Mask)
	for _, roots := range [][]memberRotationRoot{input.Pending, input.Additional} {
		for _, root := range roots {
			if root.BoundaryID == uuid.Nil || root.Key.ID == uuid.Nil || root.Key.Version == 0 || root.Key.Version >= math.MaxInt32 ||
				(root.Purpose != permissions.View && root.Purpose != permissions.Use) || boundaries[root.BoundaryID]&root.Purpose != 0 {
				return input, previous, 0, digest, ErrAdmissionResponse
			}
			boundaries[root.BoundaryID] |= root.Purpose
		}
	}
	if len(boundaries) != input.Boundaries {
		return input, previous, 0, digest, ErrAdmissionResponse
	}
	hash := sha256.New()
	hash.Write([]byte("wormhole/v1/rotation-reconciliation-review:"))
	hash.Write(raw)
	copy(digest[:], hash.Sum(nil))
	if request.Review != nil && *request.Review != digest {
		return input, previous, 0, digest, vault.ErrAuthentication
	}
	return input, previous, revision, digest, nil
}

func (s *Session) CommitPreparedGroupMemberReconciliation(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle,
	plan *GroupMemberReconciliationPreparation, keys *vault.UserKeys) (observed TrustState, reply GroupMemberRotationReply, err error) {
	observed = trust
	if ctx == nil || plan == nil || plan.request.Review == nil || keys == nil || len(keys.SigningSeed) != 32 || len(keys.EncryptionPrivate) != 32 {
		return trust, reply, ErrConfiguration
	}
	expected := plan.trust
	expected.Revision = trust.Revision
	if !reflect.DeepEqual(trust, expected) {
		return trust, reply, ErrTrustState
	}
	pin, err := authenticatedServerCAContext(trust, tls)
	if err != nil {
		return trust, reply, err
	}
	manifest, copies, err := plan.key.authenticatedCopies(trust, pin, keys)
	if err != nil {
		return trust, reply, err
	}
	publication, err := json.Marshal(groupKeyPublication{string(manifest), copies})
	if err != nil {
		return trust, reply, err
	}
	err = s.queryServerCA(ctx, trust, memberReconciliationResultSQL, plan.request.reconciliationArguments(publication), 8192, 1, 2, func(rows [][][]byte) error {
		if len(rows) != 1 || len(rows[0]) != 2 {
			return ErrAdmissionResponse
		}
		reply.Status = string(rows[0][0])
		if reply.Status != "reconciled" {
			if !reconciliationStatus(reply.Status) || rows[0][1] != nil {
				return ErrAdmissionResponse
			}
			return nil
		}
		if !bytes.Equal(manifest, rows[0][1]) {
			return vault.ErrAuthentication
		}
		committed, e := vault.DecodeGroupKeyManifest(manifest)
		if e != nil {
			return e
		}
		observed, e = observed.AdvanceGroupKey(plan.key.request.GroupID, committed)
		return e
	})
	return
}
