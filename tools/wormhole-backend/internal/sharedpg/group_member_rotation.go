package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"slices"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const memberRotationSignature = "wormhole_api_v1.rotate_group_member(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,uuid,bigint,uuid,bytea,jsonb)"
const memberRotationSupportedSQL = "SELECT (pg_catalog.to_regprocedure('" + memberRotationSignature + "') IS NOT NULL)::text"
const scopedMemberRotationSignature = "wormhole_api_v1.rotate_group_member(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,uuid,bigint,uuid,bytea,jsonb,bigint)"
const scopedMemberRotationSupportedSQL = "SELECT (pg_catalog.to_regprocedure('" + scopedMemberRotationSignature + "') IS NOT NULL)::text"
const memberRotationCallArguments = ` FROM wormhole_api_v1.rotate_group_member(` + serverCAArguments +
	`,$10::uuid,$11::uuid,$12::bigint,$13::uuid,pg_catalog.decode($14,'hex'),$15::jsonb`
const memberRotationCall = memberRotationCallArguments + ")"
const memberRotationResultColumns = `SELECT status,pg_catalog.convert_from(manifest,'UTF8'),pending::text`
const memberRotationMaterialColumns = memberRotationResultColumns + `,
 pg_catalog.convert_from(snapshot,'UTF8'),pg_catalog.convert_from(roster,'UTF8'),` + serverCAKeyColumns +
	`,recipient_id::text,recipient_version::text,encode(recipient_public,'hex'),encode(recipient_signature,'hex')`

type GroupMemberRotationRequest struct {
	JobID, GroupID, MemberID uuid.UUID
	Revision                 uint64
	Suspension               uint64
	Review                   *[32]byte
	Login                    string
	Reconcile                bool
	// The native worker supplies this scope. Interactive reviews have their own
	// explicit roster confirmation.
	Automatic *SuspendedAccount `json:"-"`
}

func (r GroupMemberRotationRequest) valid() bool {
	return r.JobID != uuid.Nil && r.GroupID != uuid.Nil && r.MemberID != uuid.Nil && r.Revision > 0 &&
		r.Revision < math.MaxInt64 && r.Suspension <= math.MaxInt64 && r.Login == "" && !r.Reconcile
}

func (r GroupMemberRotationRequest) call() string {
	if r.Suspension != 0 {
		return memberRotationCallArguments + ",$16::bigint)"
	}
	return memberRotationCall
}

func (r GroupMemberRotationRequest) arguments(publication []byte) [][]byte {
	var review []byte
	if r.Review != nil {
		review = hex.AppendEncode(nil, r.Review[:])
	}
	args := [][]byte{[]byte(r.JobID.String()), []byte(r.GroupID.String()), strconv.AppendUint(nil, r.Revision, 10), []byte(r.MemberID.String()), review, publication}
	if r.Suspension != 0 {
		args = append(args, strconv.AppendUint(nil, r.Suspension, 10))
	}
	return args
}

type GroupMemberRotationPreview struct {
	JobID      uuid.UUID        `json:"jobId"`
	GroupID    uuid.UUID        `json:"groupId"`
	MemberID   uuid.UUID        `json:"memberId"`
	Revision   string           `json:"revision"`
	Suspension string           `json:"suspension,omitempty"`
	Review     string           `json:"review"`
	Remaining  []GroupKeyMember `json:"remaining"`
	Boundaries int              `json:"boundaries"`
}

type GroupMemberRotationReceipt struct {
	JobID   uuid.UUID `json:"jobId"`
	Pending int       `json:"pending"`
}

type GroupMemberRotationReply struct {
	Status         string                            `json:"status"`
	Preview        *GroupMemberRotationPreview       `json:"preview,omitempty"`
	Addition       *GroupMemberAdditionPreview       `json:"addition,omitempty"`
	Reconciliation *GroupMemberReconciliationPreview `json:"reconciliation,omitempty"`
	Receipt        *GroupMemberRotationReceipt       `json:"receipt,omitempty"`
}

type groupKeyPublication struct {
	Manifest string          `json:"manifest"`
	Copies   json.RawMessage `json:"copies"`
}

type memberRotationRoot struct {
	BoundaryID uuid.UUID        `json:"boundaryId"`
	Purpose    permissions.Mask `json:"purpose"`
	Key        vault.KeyRef     `json:"key"`
}

type memberRotationSnapshot struct {
	JobID        uuid.UUID            `json:"jobId"`
	GroupID      uuid.UUID            `json:"groupId"`
	MemberID     uuid.UUID            `json:"memberId"`
	Revision     string               `json:"groupRevision"`
	Suspension   string               `json:"suspension,omitempty"`
	Manifest     string               `json:"manifest"`
	RosterDigest string               `json:"rosterDigest"`
	Roots        []memberRotationRoot `json:"roots"`
}

type GroupMemberRotationPreparation struct {
	request    GroupMemberRotationRequest
	trust      TrustState
	key        GroupKeyPreparation
	boundaries int
}

func (s *Session) GroupMemberRotationSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, memberRotationSupportedSQL)
}

func (s *Session) PrepareGroupMemberRotation(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, request GroupMemberRotationRequest) (observed TrustState, reply GroupMemberRotationReply, plan *GroupMemberRotationPreparation, err error) {
	if ctx == nil || !request.valid() {
		return trust, reply, nil, ErrConfiguration
	}
	pin, err := authenticatedServerCAContext(trust, tls)
	if err != nil {
		return trust, reply, nil, err
	}
	if request.Suspension != 0 {
		supported, err := s.serverCapability(ctx, scopedMemberRotationSupportedSQL)
		if err != nil {
			return trust, reply, nil, err
		}
		if !supported {
			return trust, GroupMemberRotationReply{Status: "unsupported"}, nil, nil
		}
	}
	observed = trust
	var prior vault.GroupKeyManifest
	err = s.queryServerCA(ctx, trust, memberRotationMaterialColumns+request.call(), request.arguments(nil), maxGroupRosterBytes+(1<<20), 1, 14, func(rows [][][]byte) error {
		if len(rows) != 1 || len(rows[0]) != 14 {
			return ErrAdmissionResponse
		}
		row := rows[0]
		reply.Status = string(row[0])
		if reply.Status != "ready" {
			if slices.ContainsFunc(row[3:], nonNullGrantColumn) {
				return ErrAdmissionResponse
			}
			return acceptMemberRotationResult(&observed, request, &reply, row[1], row[2])
		}
		if row[1] != nil || row[2] != nil {
			return ErrAdmissionResponse
		}
		snapshot, previous, digest, count, e := decodeMemberRotationSnapshot(request, row[3], row[4])
		if e != nil {
			return e
		}
		observed, e = observed.AdvanceGroupKey(request.GroupID, previous)
		if e != nil {
			return e
		}
		var holders []groupKeyHolder
		if !bytes.Equal(row[4], []byte("[]")) {
			observed, holders, e = verifyGroupKeyRoster(observed, row[4])
			if e != nil {
				return e
			}
		}
		members := make([]GroupKeyMember, 0, len(holders))
		for _, holder := range holders {
			if holder.member.ID == request.MemberID {
				return vault.ErrAuthentication
			}
			members = append(members, holder.member)
		}
		if request.Review == nil {
			if slices.ContainsFunc(row[5:], nonNullGrantColumn) {
				return ErrAdmissionResponse
			}
			reply = GroupMemberRotationReply{Status: "review", Preview: &GroupMemberRotationPreview{JobID: request.JobID, GroupID: request.GroupID,
				MemberID: request.MemberID, Revision: snapshot.Revision, Suspension: snapshot.Suspension,
				Review: hex.EncodeToString(digest[:]), Remaining: members, Boundaries: count}}
			return nil
		}
		custody, e := parsePersonalImportSigner([][][]byte{row[5:]}, trust.WorkspaceID)
		if e != nil || custody.recipient.Encryption != previous.Recovery {
			return ErrAdmissionResponse
		}
		if e := vault.VerifyOrganisationRecoveryRecipient(custody.recipient, custody.certificate, trust.WorkspaceID, pin.Signer, pin.Organisation); e != nil {
			return e
		}
		keyRequest := GroupKeyRequest{GroupID: request.GroupID, Revision: request.Revision}
		rosterDigest := groupKeyReviewDigest(keyRequest, row[4])
		keyRequest.Review = &rosterDigest
		prior = previous
		plan = &GroupMemberRotationPreparation{request: request, trust: cloneTrustState(observed), boundaries: count,
			key: GroupKeyPreparation{request: keyRequest, holders: holders, custody: custody, previous: previous.Key.Key}}
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

func decodeMemberRotationSnapshot(request GroupMemberRotationRequest, raw, roster []byte) (memberRotationSnapshot, vault.GroupKeyManifest, [32]byte, int, error) {
	var snapshot memberRotationSnapshot
	var previous vault.GroupKeyManifest
	var digest [32]byte
	if len(raw) > 1<<20 || len(roster) == 0 || len(roster) > maxGroupRosterBytes {
		return snapshot, previous, digest, 0, ErrAdmissionResponse
	}
	var expected memberRotationSnapshot
	if request.Suspension != 0 {
		expected.Suspension = strconv.FormatUint(request.Suspension, 10)
	}
	if _, err := strictCatalogObject(raw, expected); err != nil ||
		json.Unmarshal(raw, &snapshot) != nil || snapshot.GroupID != request.GroupID ||
		snapshot.JobID != request.JobID || snapshot.MemberID != request.MemberID || snapshot.Revision != strconv.FormatUint(request.Revision, 10) ||
		snapshot.Suspension != expected.Suspension || snapshot.Roots == nil || len(snapshot.Roots) > 4096 {
		return snapshot, previous, digest, 0, ErrAdmissionResponse
	}
	rosterDigest := sha256.Sum256(roster)
	if snapshot.RosterDigest != hex.EncodeToString(rosterDigest[:]) {
		return snapshot, previous, digest, 0, vault.ErrAuthentication
	}
	body, err := hex.DecodeString(snapshot.Manifest)
	if err != nil {
		return snapshot, previous, digest, 0, ErrAdmissionResponse
	}
	previous, err = vault.DecodeGroupKeyManifest(body)
	if err != nil || previous.GroupRevision >= request.Revision || previous.Key.Key.Version >= math.MaxInt32 {
		return snapshot, previous, digest, 0, ErrAdmissionResponse
	}
	boundaries := make(map[uuid.UUID]permissions.Mask)
	for _, root := range snapshot.Roots {
		if root.BoundaryID == uuid.Nil || root.Key.ID == uuid.Nil || root.Key.Version == 0 || root.Key.Version >= math.MaxInt32 ||
			(root.Purpose != permissions.View && root.Purpose != permissions.Use) || boundaries[root.BoundaryID]&root.Purpose != 0 {
			return snapshot, previous, digest, 0, ErrAdmissionResponse
		}
		boundaries[root.BoundaryID] |= root.Purpose
	}
	hash := sha256.New()
	hash.Write([]byte("wormhole/v1/member-rotation-review:"))
	hash.Write(raw)
	copy(digest[:], hash.Sum(nil))
	if request.Review != nil && *request.Review != digest {
		return snapshot, previous, digest, 0, vault.ErrAuthentication
	}
	return snapshot, previous, digest, len(boundaries), nil
}

func acceptMemberRotationResult(trust *TrustState, request GroupMemberRotationRequest, reply *GroupMemberRotationReply, manifest, pending []byte) error {
	switch reply.Status {
	case "busy", "stale", "rotation-pending", "incomplete", "unavailable":
		if manifest == nil && pending == nil {
			return nil
		}
	case "rotated":
		if request.Suspension != 0 && request.Review == nil {
			return ErrAdmissionResponse
		}
		count, ok := treeNumber(pending, 0, 4096)
		group, err := vault.DecodeGroupKeyManifest(manifest)
		if !ok || err != nil || group.GroupRevision != request.Revision || group.Key.Key.Version < 2 {
			return ErrAdmissionResponse
		}
		next, err := trust.AdvanceGroupKey(request.GroupID, group)
		*trust = next
		if err != nil {
			return err
		}
		reply.Receipt = &GroupMemberRotationReceipt{JobID: request.JobID, Pending: int(count)}
		return nil
	}
	return ErrAdmissionResponse
}

func (s *Session) CommitPreparedGroupMemberRotation(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, plan *GroupMemberRotationPreparation,
	keys *vault.UserKeys) (observed TrustState, reply GroupMemberRotationReply, err error) {
	observed = trust
	if ctx == nil || keys == nil || len(keys.SigningSeed) != ed25519.SeedSize || len(keys.EncryptionPrivate) != 32 || plan == nil || plan.request.Review == nil {
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
	err = s.queryServerCA(ctx, trust, memberRotationResultColumns+plan.request.call(), plan.request.arguments(publication), 8192, 1, 3, func(rows [][][]byte) error {
		if len(rows) != 1 || len(rows[0]) != 3 {
			return ErrAdmissionResponse
		}
		row := rows[0]
		reply.Status = string(row[0])
		if reply.Status == "rotated" && !bytes.Equal(row[1], manifest) {
			// The same id may have been committed before the reply was received.
			// Its signed generation and receipt are verified below.
			if previous, e := vault.DecodeGroupKeyManifest(row[1]); e != nil || previous.Key.Key.ID != plan.key.previous.ID ||
				previous.Key.Key.Version != plan.key.previous.Version+1 || !bytes.Equal(previous.RosterDigest, plan.key.request.Review[:]) {
				return vault.ErrAuthentication
			}
		}
		if err := acceptMemberRotationResult(&observed, plan.request, &reply, row[1], row[2]); err != nil {
			return err
		}
		if reply.Receipt != nil && reply.Receipt.Pending > plan.boundaries {
			return vault.ErrAuthentication
		}
		return nil
	})
	return
}
