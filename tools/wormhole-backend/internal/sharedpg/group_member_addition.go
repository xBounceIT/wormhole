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

const memberAdditionSignature = "wormhole_api_v1.add_keyed_group_member(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,uuid,bigint,text,bytea,jsonb)"
const memberAdditionSupportedSQL = "SELECT (pg_catalog.to_regprocedure('" + memberAdditionSignature + "') IS NOT NULL)::text"
const memberAdditionCall = ` FROM wormhole_api_v1.add_keyed_group_member(` + serverCAArguments +
	`,$10::uuid,$11::uuid,$12::bigint,$13::text,pg_catalog.decode($14,'hex'),$15::jsonb)`
const memberAdditionResultSQL = `SELECT status,pg_catalog.convert_from(manifest,'UTF8')` + memberAdditionCall
const memberAdditionMaterialSQL = `SELECT status,pg_catalog.convert_from(manifest,'UTF8'),pg_catalog.convert_from(snapshot,'UTF8'),
 pg_catalog.convert_from(roster,'UTF8'),escrow::text,
 sign_id::text,sign_version::text,encode(sign_enc,'hex'),encode(sign_ciphertext,'hex'),encode(sign_proof,'hex'),
 org_id::text,org_version::text,encode(org_enc,'hex'),encode(org_ciphertext,'hex'),encode(org_proof,'hex'),
 encode(org_public,'hex'),encode(org_certificate,'hex')` + memberAdditionCall
const maxMemberAdditionScope = 8 << 20

type GroupMemberAdditionPreview struct {
	JobID      uuid.UUID      `json:"jobId"`
	GroupID    uuid.UUID      `json:"groupId"`
	Revision   string         `json:"revision"`
	Review     string         `json:"review"`
	Member     GroupKeyMember `json:"member"`
	Boundaries int            `json:"boundaries"`
}

type memberAdditionBoundary struct {
	ID            uuid.UUID        `json:"id"`
	GrantRevision string           `json:"grantRevision"`
	Mask          permissions.Mask `json:"mask"`
	Manifest      string           `json:"manifest"`
	Keys          []vault.KeyRef   `json:"keys"`
}

type memberAdditionSnapshot struct {
	JobID        uuid.UUID                `json:"jobId"`
	GroupID      uuid.UUID                `json:"groupId"`
	MemberID     uuid.UUID                `json:"memberId"`
	Revision     string                   `json:"groupRevision"`
	Epoch        string                   `json:"epoch"`
	ChangeSeq    string                   `json:"changeSeq"`
	Previous     string                   `json:"previous"`
	PriorRoster  string                   `json:"priorRoster"`
	RosterDigest string                   `json:"rosterDigest"`
	Boundaries   []memberAdditionBoundary `json:"boundaries"`
}

type memberAdditionRoot struct {
	key      vault.KeyRef
	purpose  vault.BoundaryPurpose
	boundary vault.BoundaryManifest
	escrow   vault.SignedKeyCopy
}

// A prepared addition retains authenticated escrow copies and signed public
// manifests. Keys are opened only after the owner commits the trust floors.
type GroupMemberAdditionPreparation struct {
	request GroupMemberRotationRequest
	trust   TrustState
	key     GroupKeyPreparation
	custody boundaryKeyCustody
	roots   []memberAdditionRoot
}

func (r GroupMemberRotationRequest) ValidAddition() bool {
	return r.JobID != uuid.Nil && r.GroupID != uuid.Nil && r.MemberID == uuid.Nil && r.Revision > 0 &&
		r.Revision < math.MaxInt64 && r.Suspension == 0 && adminGroupText(r.Login, 256) && !r.Reconcile
}

func (r GroupMemberRotationRequest) additionArguments(publication []byte) [][]byte {
	var review []byte
	if r.Review != nil {
		review = hex.AppendEncode(nil, r.Review[:])
	}
	return [][]byte{[]byte(r.JobID.String()), []byte(r.GroupID.String()), strconv.AppendUint(nil, r.Revision, 10), []byte(r.Login), review, publication}
}

func (s *Session) GroupMemberAdditionSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, memberAdditionSupportedSQL)
}

func (s *Session) PrepareGroupMemberAddition(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, request GroupMemberRotationRequest) (observed TrustState, reply GroupMemberRotationReply, plan *GroupMemberAdditionPreparation, err error) {
	observed = trust
	if ctx == nil || !request.ValidAddition() {
		return trust, reply, nil, ErrConfiguration
	}
	pin, err := authenticatedServerCAContext(trust, tls)
	if err != nil {
		return trust, reply, nil, err
	}
	err = s.queryServerCA(ctx, trust, memberAdditionMaterialSQL, request.additionArguments(nil), 2*maxMemberAdditionScope+2*maxGroupRosterBytes+32768, 1, 17, func(rows [][][]byte) error {
		if len(rows) != 1 || len(rows[0]) != 17 {
			return ErrAdmissionResponse
		}
		row := rows[0]
		reply.Status = string(row[0])
		if reply.Status != "ready" {
			if slices.ContainsFunc(row[2:], nonNullGrantColumn) {
				return ErrAdmissionResponse
			}
			return acceptMemberAdditionResult(&observed, request, &reply, row[1])
		}
		if row[1] != nil {
			return ErrAdmissionResponse
		}
		input, previous, digest, e := decodeMemberAdditionSnapshot(request, row[2], row[3])
		if e != nil {
			return e
		}
		observed, e = observed.AdvanceGroupKey(request.GroupID, previous)
		if e != nil {
			return e
		}
		var holders []groupKeyHolder
		observed, holders, e = verifyGroupKeyRoster(observed, row[3])
		if e != nil {
			return e
		}
		var member GroupKeyMember
		for _, holder := range holders {
			if holder.member.ID == input.MemberID && holder.member.Login == request.Login {
				member = holder.member
				break
			}
		}
		if member.ID == uuid.Nil {
			return vault.ErrAuthentication
		}
		prepared := &GroupMemberAdditionPreparation{request: request}
		observed, e = prepared.observeBoundaries(observed, input.Boundaries, previous.Signer)
		if e != nil {
			return e
		}
		if request.Review == nil {
			if slices.ContainsFunc(row[4:], nonNullGrantColumn) {
				return ErrAdmissionResponse
			}
			reply.Status = "review-add"
			reply.Addition = &GroupMemberAdditionPreview{JobID: request.JobID, GroupID: request.GroupID, Revision: input.Revision,
				Review: hex.EncodeToString(digest[:]), Member: member, Boundaries: len(input.Boundaries)}
			return nil
		}
		if e := prepared.custody.readCustody(pin, previous.Recovery, row[5:]); e != nil {
			return e
		}
		if e := prepared.readEscrow(pin, observed.UserID, input, row[4]); e != nil {
			return e
		}
		keyRequest := GroupKeyRequest{GroupID: request.GroupID, Revision: request.Revision}
		rosterDigest := groupKeyReviewDigest(keyRequest, row[3])
		keyRequest.Review = &rosterDigest
		prepared.key = GroupKeyPreparation{request: keyRequest, previous: previous.Key.Key, holders: holders,
			custody: personalImportSigner{recipient: prepared.custody.recipient}}
		prepared.trust = cloneTrustState(observed)
		plan = prepared
		return nil
	})
	return
}

func decodeMemberAdditionSnapshot(request GroupMemberRotationRequest, raw, roster []byte) (input memberAdditionSnapshot, previous vault.GroupKeyManifest, digest [32]byte, err error) {
	if len(raw) > maxMemberAdditionScope+maxGroupRosterBytes+32768 || len(roster) == 0 || len(roster) > maxGroupRosterBytes {
		return input, previous, digest, ErrAdmissionResponse
	}
	if _, err := strictCatalogObject(raw, input); err != nil || json.Unmarshal(raw, &input) != nil || input.JobID != request.JobID ||
		input.GroupID != request.GroupID || input.MemberID == uuid.Nil || input.Revision != strconv.FormatUint(request.Revision, 10) ||
		input.Boundaries == nil || len(input.Boundaries) > 4096 {
		return input, previous, digest, ErrAdmissionResponse
	}
	if _, ok := treeNumber([]byte(input.Epoch), 1, math.MaxInt64); !ok {
		return input, previous, digest, ErrAdmissionResponse
	}
	if _, ok := treeNumber([]byte(input.ChangeSeq), 0, math.MaxInt64); !ok {
		return input, previous, digest, ErrAdmissionResponse
	}
	rosterHash := sha256.Sum256(roster)
	if hex.EncodeToString(rosterHash[:]) != input.RosterDigest {
		return input, previous, digest, vault.ErrAuthentication
	}
	body, err := hex.DecodeString(input.Previous)
	if err != nil {
		return input, previous, digest, ErrAdmissionResponse
	}
	previous, err = vault.DecodeGroupKeyManifest(body)
	if err != nil || previous.GroupRevision >= request.Revision || previous.Key.Key.Version >= math.MaxInt32 {
		return input, previous, digest, ErrAdmissionResponse
	}
	if err := validateMemberAdditionRoster(previous, input.MemberID, []byte(input.PriorRoster), roster); err != nil {
		return input, previous, digest, err
	}
	hash := sha256.New()
	hash.Write([]byte("wormhole/v1/member-addition-review:"))
	hash.Write(raw)
	copy(digest[:], hash.Sum(nil))
	if request.Review != nil && *request.Review != digest {
		return input, previous, digest, vault.ErrAuthentication
	}
	return input, previous, digest, nil
}

func validateMemberAdditionRoster(previous vault.GroupKeyManifest, member uuid.UUID, prior, current []byte) error {
	if len(prior) == 0 || len(prior) > maxGroupRosterBytes {
		return ErrAdmissionResponse
	}
	digest := groupKeyReviewDigest(GroupKeyRequest{GroupID: previous.GroupID, Revision: previous.GroupRevision}, prior)
	if !bytes.Equal(previous.RosterDigest, digest[:]) {
		return vault.ErrAuthentication
	}
	before, e1 := snapshotRows(prior, maxGroupRoster, 5)
	after, e2 := snapshotRows(current, maxGroupRoster, 5)
	if e1 != nil || e2 != nil || len(after) != len(before)+1 {
		return ErrAdmissionResponse
	}
	index := slices.IndexFunc(after, func(row [][]byte) bool { return string(row[0]) == member.String() })
	if index < 0 || !slices.EqualFunc(before, slices.Delete(after, index, index+1), func(a, b [][]byte) bool {
		return slices.EqualFunc(a, b, bytes.Equal)
	}) {
		return vault.ErrAuthentication
	}
	return nil
}

func (plan *GroupMemberAdditionPreparation) observeBoundaries(trust TrustState, scopes []memberAdditionBoundary, signer vault.KeyRef) (TrustState, error) {
	var previous uuid.UUID
	seen := make(map[vault.KeyRef]bool)
	for _, scope := range scopes {
		if !validGroupBoundaryMask(scope.Mask) || bytes.Compare(scope.ID[:], previous[:]) <= 0 {
			return trust, ErrAdmissionResponse
		}
		if _, ok := treeNumber([]byte(scope.GrantRevision), 1, math.MaxInt64); !ok {
			return trust, ErrAdmissionResponse
		}
		previous = scope.ID
		raw, e1 := hex.DecodeString(scope.Manifest)
		boundary, e2 := vault.DecodeBoundaryManifest(raw)
		if e1 != nil || e2 != nil || !boundary.Active || !boundary.OrgEscrow || boundary.OwnerUserID != uuid.Nil ||
			boundary.Signer != signer || boundary.PreviousView != nil || boundary.PreviousSecret != nil {
			return trust, ErrAdmissionResponse
		}
		var e error
		trust, e = trust.AdvanceBoundary(scope.ID, boundary)
		if e != nil {
			return trust, e
		}
		var exact []vault.KeyRef
		if scope.Mask&permissions.View != 0 {
			exact = append(exact, boundary.View.Key)
			plan.roots = append(plan.roots, memberAdditionRoot{key: boundary.View.Key, purpose: vault.BoundaryView, boundary: boundary})
		}
		if scope.Mask&permissions.Use != 0 {
			exact = append(exact, boundary.Secret.Key)
			plan.roots = append(plan.roots, memberAdditionRoot{key: boundary.Secret.Key, purpose: vault.BoundarySecret, boundary: boundary})
		}
		if !slices.Equal(exact, scope.Keys) {
			return trust, ErrAdmissionResponse
		}
		for _, key := range exact {
			if seen[key] {
				return trust, ErrAdmissionResponse
			}
			seen[key] = true
		}
	}
	return trust, nil
}

func (plan *GroupMemberAdditionPreparation) readEscrow(pin vault.UserKeyTrust, user uuid.UUID, input memberAdditionSnapshot, raw []byte) error {
	var escrow []json.RawMessage
	if len(raw) > maxMemberAdditionScope || json.Unmarshal(raw, &escrow) != nil || escrow == nil || len(escrow) != len(plan.roots) {
		return ErrAdmissionResponse
	}
	request := AdmissionRequest{WorkspaceID: pin.WorkspaceID, UserID: user}
	epoch, sequence := parseGroupGrantRevision(input.Epoch), parseGroupGrantRevision(input.ChangeSeq)
	for i, root := range plan.roots {
		copy, err := parseBoundaryRootCopy(escrow[i], request, root.key, plan.custody.recipient.Encryption, epoch, sequence, 24)
		if err != nil || copy.Author != nil || copy.group != nil || copy.Binding.Issuer != pin.Signer {
			return ErrAdmissionResponse
		}
		if err := vault.VerifyKeyCopy(copy.Binding, copy.Copy, pin.Organisation); err != nil {
			return err
		}
		plan.roots[i].escrow = copy.Copy
	}
	return nil
}

func acceptMemberAdditionResult(trust *TrustState, request GroupMemberRotationRequest, reply *GroupMemberRotationReply, raw []byte) error {
	switch reply.Status {
	case "busy", "stale", "rotation-pending", "incomplete", "unavailable", "account-unavailable", "unchanged":
		if raw == nil {
			return nil
		}
	case "added":
		manifest, err := vault.DecodeGroupKeyManifest(raw)
		if err != nil || manifest.GroupRevision != request.Revision || manifest.Key.Key.Version < 2 {
			return ErrAdmissionResponse
		}
		next, err := trust.AdvanceGroupKey(request.GroupID, manifest)
		*trust = next
		if err != nil {
			return err
		}
		reply.Receipt = &GroupMemberRotationReceipt{JobID: request.JobID}
		return nil
	}
	return ErrAdmissionResponse
}

func (s *Session) CommitPreparedGroupMemberAddition(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, plan *GroupMemberAdditionPreparation, keys *vault.UserKeys) (observed TrustState, reply GroupMemberRotationReply, err error) {
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
	publication, manifest, err := plan.wrap(ctx, trust, pin, keys)
	if err != nil {
		return trust, reply, err
	}
	err = s.queryServerCA(ctx, trust, memberAdditionResultSQL, plan.request.additionArguments(publication), 8192, 1, 2, func(rows [][][]byte) error {
		if len(rows) != 1 || len(rows[0]) != 2 {
			return ErrAdmissionResponse
		}
		row := rows[0]
		reply.Status = string(row[0])
		if reply.Status == "added" && !bytes.Equal(row[1], manifest) {
			committed, e := vault.DecodeGroupKeyManifest(row[1])
			if e != nil || committed.Key.Key.ID != plan.key.previous.ID || committed.Key.Key.Version != plan.key.previous.Version+1 ||
				!bytes.Equal(committed.RosterDigest, plan.key.request.Review[:]) {
				return vault.ErrAuthentication
			}
		}
		return acceptMemberAdditionResult(&observed, plan.request, &reply, row[1])
	})
	return
}

func (plan *GroupMemberAdditionPreparation) wrap(ctx context.Context, trust TrustState, pin vault.UserKeyTrust, keys *vault.UserKeys) ([]byte, []byte, error) {
	var org vault.UserKeys
	defer org.Wipe()
	var err error
	org.SigningSeed, err = openServerCAOrgCopy(trust, pin.Signer, plan.custody.signing, keys.EncryptionPrivate, keys.SigningSeed)
	if err != nil {
		return nil, nil, err
	}
	org.EncryptionPrivate, err = openServerCAOrgCopy(trust, plan.custody.recipient.Encryption, plan.custody.encryption, keys.EncryptionPrivate, keys.SigningSeed)
	if err != nil {
		return nil, nil, err
	}
	if err := verifyEscrowKeyPair(&org, vault.UserPublicKeys{Signing: pin.Organisation, Encryption: plan.custody.recipient.PublicKey}); err != nil {
		return nil, nil, err
	}
	signer := ed25519.NewKeyFromSeed(org.SigningSeed)
	defer vault.Wipe(signer)
	manifest, groupCopies, err := prepareGroupKeyCopies(trust.WorkspaceID, &plan.key, signer, org.SigningSeed)
	if err != nil {
		return nil, nil, err
	}
	group, err := vault.DecodeGroupKeyManifest(manifest)
	if err != nil {
		return nil, nil, err
	}
	roots := make([]personalImportCopy, 0, len(plan.roots))
	issuer := vault.KeyCopyTrust{Issuer: pin.Signer, Public: pin.Organisation}
	for _, root := range plan.roots {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		scope := vault.BoundaryTrust{WorkspaceID: trust.WorkspaceID, BoundaryID: root.boundary.BoundaryID,
			Signer: pin.Signer, Organisation: pin.Organisation, MinimumRevision: root.boundary.Revision}
		binding := vault.KeyCopyBinding{WorkspaceID: trust.WorkspaceID, Key: root.key, Holder: group.Recovery, Issuer: pin.Signer}
		seed, err := vault.OpenBoundaryKeyCopy(org.EncryptionPrivate, binding, root.escrow, issuer, root.boundary, scope, root.purpose)
		if err != nil {
			return nil, nil, err
		}
		binding.Holder = group.Key.Key
		copy, err := vault.SealKeyCopy(seed, binding, group.Key.Public, org.SigningSeed)
		vault.Wipe(seed)
		if err != nil {
			return nil, nil, err
		}
		roots = append(roots, personalImportCopy{Binding: binding, SignedKeyCopy: copy})
	}
	publication, err := json.Marshal(struct {
		Manifest string               `json:"manifest"`
		Copies   json.RawMessage      `json:"copies"`
		Roots    []personalImportCopy `json:"roots"`
	}{string(manifest), groupCopies, roots})
	if err == nil && len(publication) > maxMemberAdditionScope {
		err = ErrResultLimit
	}
	return publication, manifest, err
}
