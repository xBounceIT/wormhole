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
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const groupBoundaryGrantSignature = "wormhole_api_v1.grant_group_boundary(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bigint,uuid,uuid,bigint,integer,bytea,jsonb)"
const groupBoundaryGrantSupportedSQL = "SELECT (pg_catalog.to_regprocedure('" + groupBoundaryGrantSignature + "') IS NOT NULL)::text"
const groupBoundaryGrantCall = ` FROM wormhole_api_v1.grant_group_boundary(` + serverCAArguments +
	`,$10::uuid,$11::bigint,$12::uuid,$13::uuid,$14::bigint,$15::integer,pg_catalog.decode($16,'hex'),$17::jsonb)`
const groupBoundaryGrantMaterialSQL = `SELECT status,pg_catalog.convert_from(snapshot,'UTF8'),pg_catalog.convert_from(roster,'UTF8'),
 sign_id::text,sign_version::text,pg_catalog.encode(sign_enc,'hex'),pg_catalog.encode(sign_ciphertext,'hex'),pg_catalog.encode(sign_proof,'hex'),
 org_id::text,org_version::text,pg_catalog.encode(org_enc,'hex'),pg_catalog.encode(org_ciphertext,'hex'),pg_catalog.encode(org_proof,'hex'),
 pg_catalog.encode(org_public,'hex'),pg_catalog.encode(org_certificate,'hex'),escrow::text` + groupBoundaryGrantCall

type GroupBoundaryGrantRequest struct {
	NodeID        string           `json:"nodeId"`
	NodeRevision  string           `json:"nodeRevision"`
	BoundaryID    string           `json:"boundaryId"`
	GroupID       string           `json:"groupId"`
	GroupRevision string           `json:"groupRevision"`
	Mask          permissions.Mask `json:"mask"`
	Review        string           `json:"review,omitempty"`
}

func (r GroupBoundaryGrantRequest) Valid() bool {
	return validGroupBoundaryMask(r.Mask) && r.validSelection()
}

func (r GroupBoundaryGrantRequest) ValidRotation() bool {
	return r.Mask <= permissions.Use && r.validSelection()
}

func (r GroupBoundaryGrantRequest) validSelection() bool {
	for _, value := range []string{r.NodeID, r.BoundaryID, r.GroupID} {
		if _, ok := treeID([]byte(value)); !ok {
			return false
		}
	}
	for _, version := range []string{r.NodeRevision, r.GroupRevision} {
		if _, ok := treeNumber([]byte(version), 1, math.MaxInt64); !ok {
			return false
		}
	}
	if r.Review != "" {
		digest, err := hex.DecodeString(r.Review)
		return err == nil && len(digest) == sha256.Size && hex.EncodeToString(digest) == r.Review
	}
	return true
}

func validGroupBoundaryMask(mask permissions.Mask) bool {
	return mask > 0 && mask & ^(permissions.View|permissions.Use) == 0
}

func (r GroupBoundaryGrantRequest) arguments(copies []byte) [][]byte {
	return [][]byte{[]byte(r.NodeID), []byte(r.NodeRevision), []byte(r.BoundaryID), []byte(r.GroupID), []byte(r.GroupRevision),
		strconv.AppendUint(nil, uint64(r.Mask), 10), adminArgument(r.Review), copies}
}

type GroupBoundaryGrantPreview struct {
	GroupBoundaryGrantRequest
	PreviousMask permissions.Mask `json:"previousMask"`
	Members      []GroupKeyMember `json:"members,omitempty"`
}

type GroupBoundaryGrantReply struct {
	Status  string                     `json:"status"`
	Preview *GroupBoundaryGrantPreview `json:"preview,omitempty"`
}

type groupBoundaryGrantSnapshot struct {
	GroupBoundaryGrantRequest
	BoundaryRevision string           `json:"boundaryRevision"`
	Boundary         string           `json:"boundary"`
	Group            string           `json:"group"`
	GrantRevision    string           `json:"grantRevision"`
	PreviousMask     permissions.Mask `json:"previousMask"`
}

type groupBoundaryGrantRoot struct {
	key     vault.KeyRef
	purpose vault.BoundaryPurpose
}

// GroupBoundaryGrantPreparation contains only authenticated ciphertext. The
// owning process commits the observed trust before opening any escrow keys.
type GroupBoundaryGrantPreparation struct {
	request    GroupBoundaryGrantRequest
	trust      TrustState
	boundary   vault.BoundaryManifest
	group      vault.GroupKeyManifest
	added      permissions.Mask
	recipient  vault.OrganisationRecoveryRecipient
	signing    vault.SignedKeyCopy
	encryption vault.SignedKeyCopy
	escrow     []UnverifiedKeyCopy
}

func (s *Session) GroupBoundaryGrantsSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, groupBoundaryGrantSupportedSQL)
}

func (s *Session) PrepareGroupBoundaryGrant(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, request GroupBoundaryGrantRequest) (observed TrustState, reply GroupBoundaryGrantReply, plan *GroupBoundaryGrantPreparation, err error) {
	if ctx == nil || !request.Valid() {
		return trust, reply, nil, ErrConfiguration
	}
	pin, err := authenticatedServerCAContext(trust, tls)
	if err != nil {
		return trust, reply, nil, err
	}
	observed = trust
	err = s.queryServerCA(ctx, trust, groupBoundaryGrantMaterialSQL, request.arguments(nil), maxGroupRosterBytes+32768, 1, 16, func(rows [][][]byte) error {
		if len(rows) != 1 || len(rows[0]) != 16 {
			return ErrAdmissionResponse
		}
		row := rows[0]
		reply.Status = string(row[0])
		if reply.Status != "ready" {
			if !groupBoundaryGrantStatus(reply.Status, false) || slices.ContainsFunc(row[1:], nonNullGrantColumn) {
				return ErrAdmissionResponse
			}
			return nil
		}
		var state *GroupBoundaryGrantPreparation
		var preview *GroupBoundaryGrantPreview
		var e error
		observed, state, preview, e = verifyGroupBoundaryGrantSnapshot(trust, request, row[1], row[2])
		if e != nil {
			return e
		}
		if request.Review == "" {
			if slices.ContainsFunc(row[3:], nonNullGrantColumn) {
				return ErrAdmissionResponse
			}
			reply = GroupBoundaryGrantReply{Status: "review", Preview: preview}
			return nil
		}
		if err := state.readCustody(pin, row[3:]); err != nil {
			return err
		}
		plan = state
		return nil
	})
	return
}

func nonNullGrantColumn(raw []byte) bool { return raw != nil }

func groupBoundaryGrantStatus(status string, committing bool) bool {
	switch status {
	case "busy", "stale", "unavailable", "key-required", "rotation-required", "unchanged":
		return true
	case "changed":
		return committing
	}
	return false
}

func verifyGroupBoundaryGrantSnapshot(trust TrustState, request GroupBoundaryGrantRequest, raw, roster []byte) (TrustState, *GroupBoundaryGrantPreparation, *GroupBoundaryGrantPreview, error) {
	var snapshot groupBoundaryGrantSnapshot
	want := request
	want.Review = ""
	if len(raw) > 32768 {
		return trust, nil, nil, ErrAdmissionResponse
	}
	if _, err := strictCatalogObject(raw, snapshot); err != nil {
		return trust, nil, nil, err
	}
	if json.Unmarshal(raw, &snapshot) != nil ||
		snapshot.GroupBoundaryGrantRequest != want || snapshot.PreviousMask == want.Mask ||
		snapshot.PreviousMask&want.Mask != snapshot.PreviousMask {
		return trust, nil, nil, ErrAdmissionResponse
	}
	if _, ok := treeNumber([]byte(snapshot.BoundaryRevision), 1, math.MaxInt64); !ok {
		return trust, nil, nil, ErrAdmissionResponse
	}
	if rev, ok := treeNumber([]byte(snapshot.GrantRevision), 0, math.MaxInt64); !ok || (rev == 0) != (snapshot.PreviousMask == 0) {
		return trust, nil, nil, ErrAdmissionResponse
	}
	hasher := sha256.New()
	hasher.Write([]byte("wormhole/v1/group-boundary-review:"))
	hasher.Write(raw)
	digest := hex.EncodeToString(hasher.Sum(nil))
	if request.Review != "" && request.Review != digest {
		return trust, nil, nil, vault.ErrAuthentication
	}
	boundaryRaw, err := hex.DecodeString(snapshot.Boundary)
	if err != nil {
		return trust, nil, nil, ErrAdmissionResponse
	}
	boundary, err := vault.DecodeBoundaryManifest(boundaryRaw)
	if err != nil || boundary.OwnerUserID != uuid.Nil || boundary.PreviousView != nil || boundary.PreviousSecret != nil || !boundary.OrgEscrow {
		return trust, nil, nil, ErrAdmissionResponse
	}
	observed, err := trust.AdvanceBoundary(uuid.MustParse(request.BoundaryID), boundary)
	if err != nil {
		return observed, nil, nil, err
	}
	groupRaw, err := hex.DecodeString(snapshot.Group)
	if err != nil {
		return observed, nil, nil, ErrAdmissionResponse
	}
	group, err := vault.DecodeGroupKeyManifest(groupRaw)
	if err != nil || group.Signer != boundary.Signer || group.GroupRevision >= parseGroupGrantRevision(request.GroupRevision) {
		return observed, nil, nil, ErrAdmissionResponse
	}
	observed, err = observed.AdvanceGroupKey(uuid.MustParse(request.GroupID), group)
	if err != nil {
		return observed, nil, nil, err
	}
	review := groupKeyReviewDigest(GroupKeyRequest{GroupID: group.GroupID, Revision: group.GroupRevision}, roster)
	if !bytes.Equal(review[:], group.RosterDigest) {
		return observed, nil, nil, vault.ErrAuthentication
	}
	observed, holders, err := verifyGroupKeyRoster(observed, roster)
	if err != nil {
		return observed, nil, nil, err
	}
	preview := &GroupBoundaryGrantPreview{GroupBoundaryGrantRequest: want, PreviousMask: snapshot.PreviousMask, Members: make([]GroupKeyMember, 0, len(holders))}
	preview.Review = digest
	for _, holder := range holders {
		preview.Members = append(preview.Members, holder.member)
	}
	return observed, &GroupBoundaryGrantPreparation{request: request, trust: cloneTrustState(observed), boundary: boundary, group: group,
		added: request.Mask &^ snapshot.PreviousMask}, preview, nil
}

func parseGroupGrantRevision(revision string) uint64 {
	value, _ := strconv.ParseUint(revision, 10, 63)
	return value
}

func (plan *GroupBoundaryGrantPreparation) roots() []groupBoundaryGrantRoot {
	var roots []groupBoundaryGrantRoot
	if plan.added&permissions.View != 0 {
		roots = append(roots, groupBoundaryGrantRoot{plan.boundary.View.Key, vault.BoundaryView})
	}
	if plan.added&permissions.Use != 0 {
		roots = append(roots, groupBoundaryGrantRoot{plan.boundary.Secret.Key, vault.BoundarySecret})
	}
	return roots
}

func (plan *GroupBoundaryGrantPreparation) readCustody(pin vault.UserKeyTrust, row [][]byte) error {
	signID, signing, e1 := parseServerCAOrgCopy(row[:5])
	encID, encryption, e2 := parseServerCAOrgCopy(row[5:10])
	public, e3 := hex.DecodeString(string(row[10]))
	proof, e4 := hex.DecodeString(string(row[11]))
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || signID != pin.Signer || encID != plan.group.Recovery {
		return ErrAdmissionResponse
	}
	recipient := vault.OrganisationRecoveryRecipient{WorkspaceID: plan.trust.WorkspaceID,
		Signer: signID, Encryption: encID, PublicKey: public}
	if err := vault.VerifyOrganisationRecoveryRecipient(recipient, proof, plan.trust.WorkspaceID, pin.Signer, pin.Organisation); err != nil {
		return err
	}
	roots := plan.roots()
	var wires []json.RawMessage
	if len(row[12]) > 8192 || json.Unmarshal(row[12], &wires) != nil || len(wires) != len(roots) {
		return ErrAdmissionResponse
	}
	var epoch, sequence uint64
	for i, encoded := range wires {
		columns, err := snapshotOptionalRow(encoded, 24)
		if err != nil || columns == nil {
			return ErrAdmissionResponse
		}
		if i == 0 {
			var epochOK, sequenceOK bool
			epoch, epochOK = treeNumber(columns[1], 1, math.MaxInt64)
			sequence, sequenceOK = treeNumber(columns[2], 0, math.MaxInt64)
			if !epochOK || !sequenceOK {
				return ErrAdmissionResponse
			}
		}
		request := AdmissionRequest{WorkspaceID: plan.trust.WorkspaceID, UserID: plan.trust.UserID}
		copy, err := parseKeyCopyProjection([][][]byte{columns}, request, roots[i].key, encID, epoch, sequence)
		if err != nil || copy.Author != nil || copy.Binding.Issuer != pin.Signer {
			return ErrAdmissionResponse
		}
		if err := vault.VerifyKeyCopy(copy.Binding, copy.Copy, pin.Organisation); err != nil {
			return err
		}
		plan.escrow = append(plan.escrow, *copy)
	}
	plan.signing, plan.encryption, plan.recipient = signing, encryption, recipient
	return nil
}

func (s *Session) CommitPreparedGroupBoundaryGrant(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, plan *GroupBoundaryGrantPreparation, keys *vault.UserKeys) (reply GroupBoundaryGrantReply, err error) {
	if ctx == nil || keys == nil || len(keys.SigningSeed) != 32 || len(keys.EncryptionPrivate) != 32 ||
		plan == nil || plan.request.Review == "" {
		return reply, ErrConfiguration
	}
	// The account owner publishes all observations from one operation under a
	// single local revision. The authenticated state must otherwise match exactly.
	expected := plan.trust
	expected.Revision = trust.Revision
	if !reflect.DeepEqual(trust, expected) {
		return reply, ErrTrustState
	}
	pin, err := authenticatedServerCAContext(trust, tls)
	if err != nil {
		return reply, err
	}
	copies, err := plan.wrapRoots(trust, pin, keys)
	if err != nil {
		return reply, err
	}
	err = s.queryServerCA(ctx, trust, "SELECT status"+groupBoundaryGrantCall, plan.request.arguments(copies), 64, 1, 1, func(rows [][][]byte) error {
		if len(rows) != 1 || len(rows[0]) != 1 || !groupBoundaryGrantStatus(string(rows[0][0]), true) {
			return ErrAdmissionResponse
		}
		reply.Status = string(rows[0][0])
		return nil
	})
	return
}

func (plan *GroupBoundaryGrantPreparation) wrapRoots(trust TrustState, pin vault.UserKeyTrust, keys *vault.UserKeys) ([]byte, error) {
	var org vault.UserKeys
	defer org.Wipe()
	var err error
	org.SigningSeed, err = openServerCAOrgCopy(trust, pin.Signer, plan.signing, keys.EncryptionPrivate, keys.SigningSeed)
	if err != nil {
		return nil, err
	}
	org.EncryptionPrivate, err = openServerCAOrgCopy(trust, plan.recipient.Encryption, plan.encryption, keys.EncryptionPrivate, keys.SigningSeed)
	if err != nil {
		return nil, err
	}
	if err := verifyEscrowKeyPair(&org, vault.UserPublicKeys{Encryption: plan.recipient.PublicKey, Signing: pin.Organisation}); err != nil {
		return nil, err
	}
	scope := vault.BoundaryTrust{WorkspaceID: trust.WorkspaceID, BoundaryID: plan.boundary.BoundaryID, Signer: pin.Signer,
		Organisation: pin.Organisation, MinimumRevision: plan.boundary.Revision}
	issuer := vault.KeyCopyTrust{Issuer: pin.Signer, Public: pin.Organisation}
	roots := plan.roots()
	if len(plan.escrow) != len(roots) {
		return nil, ErrAdmissionResponse
	}
	copies := make([]personalImportCopy, 0, len(roots))
	for i, root := range roots {
		escrow := plan.escrow[i]
		seed, err := vault.OpenBoundaryKeyCopy(org.EncryptionPrivate, escrow.Binding, escrow.Copy, issuer, plan.boundary, scope, root.purpose)
		if err != nil {
			return nil, err
		}
		binding := vault.KeyCopyBinding{WorkspaceID: trust.WorkspaceID, Key: root.key, Holder: plan.group.Key.Key, Issuer: pin.Signer}
		wrapped, err := vault.SealKeyCopy(seed, binding, plan.group.Key.Public, org.SigningSeed)
		vault.Wipe(seed)
		if err != nil {
			return nil, err
		}
		copies = append(copies, personalImportCopy{Binding: binding, SignedKeyCopy: wrapped})
	}
	return json.Marshal(copies)
}
