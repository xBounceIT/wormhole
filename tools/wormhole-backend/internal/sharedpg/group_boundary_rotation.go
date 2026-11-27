package sharedpg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"reflect"
	"slices"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const maxBoundaryRotationGraph = 48 << 20
const boundaryRotationSignature = "wormhole_api_v1.rotate_group_boundary(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bigint,uuid,uuid,bigint,integer,bytea,jsonb)"
const boundaryRotationSupportedSQL = "SELECT (pg_catalog.to_regprocedure('" + boundaryRotationSignature + "') IS NOT NULL)::text"
const boundaryRotationCall = ` FROM wormhole_api_v1.rotate_group_boundary(` + serverCAArguments +
	`,$10::uuid,$11::bigint,$12::uuid,$13::uuid,$14::bigint,$15::integer,pg_catalog.decode($16,'hex'),$17::jsonb)`
const boundaryRotationMaterialColumns = `SELECT status,pg_catalog.convert_from(snapshot,'UTF8'),graph::text,
 sign_id::text,sign_version::text,pg_catalog.encode(sign_enc,'hex'),pg_catalog.encode(sign_ciphertext,'hex'),pg_catalog.encode(sign_proof,'hex'),
 org_id::text,org_version::text,pg_catalog.encode(org_enc,'hex'),pg_catalog.encode(org_ciphertext,'hex'),pg_catalog.encode(org_proof,'hex'),
 pg_catalog.encode(org_public,'hex'),pg_catalog.encode(org_certificate,'hex')`
const boundaryRotationMaterialSQL = boundaryRotationMaterialColumns + boundaryRotationCall

type boundaryRotationSnapshot struct {
	groupBoundaryGrantSnapshot
	Epoch       string `json:"epoch"`
	ChangeSeq   string `json:"changeSeq"`
	GraphDigest string `json:"graphDigest"`
}

type boundaryRotationGraphScope struct {
	Epoch, ChangeSeq, Digest string
	Affected                 permissions.Mask
}

func (input boundaryRotationSnapshot) graphScope() boundaryRotationGraphScope {
	return boundaryRotationGraphScope{input.Epoch, input.ChangeSeq, input.GraphDigest, input.PreviousMask &^ input.Mask}
}

type boundaryRotationHolder struct {
	Kind     string       `json:"kind"`
	Subject  uuid.UUID    `json:"subject"`
	Key      vault.KeyRef `json:"key"`
	Manifest string       `json:"manifest"`
	Proof    string       `json:"proof"`
}

type boundaryRotationRootWire struct {
	Purpose    vault.BoundaryPurpose    `json:"purpose"`
	Escrow     json.RawMessage          `json:"escrow"`
	Recipients []boundaryRotationHolder `json:"recipients"`
	DEKs       []json.RawMessage        `json:"deks"`
}

type GroupBoundaryRotationPreparation struct {
	request  GroupBoundaryGrantRequest
	trust    TrustState
	boundary vault.BoundaryManifest
	roots    []vault.BoundaryRootRotation
	boundaryKeyCustody
	replacement   *vault.GroupKeyManifest
	removedMember uuid.UUID
	excludedUser  uuid.UUID
}

type boundaryKeyCustody struct {
	recipient  vault.OrganisationRecoveryRecipient
	proof      []byte
	signing    vault.SignedKeyCopy
	encryption vault.SignedKeyCopy
}

func (s *Session) GroupBoundaryRotationSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, boundaryRotationSupportedSQL)
}

func (s *Session) PrepareGroupBoundaryRotation(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, request GroupBoundaryGrantRequest) (observed TrustState, reply GroupBoundaryGrantReply, plan *GroupBoundaryRotationPreparation, err error) {
	if ctx == nil || !request.ValidRotation() {
		return trust, reply, nil, ErrConfiguration
	}
	pin, err := authenticatedServerCAContext(trust, tls)
	if err != nil {
		return trust, reply, nil, err
	}
	observed = trust
	err = s.queryServerCA(ctx, trust, boundaryRotationMaterialSQL, request.arguments(nil), maxBoundaryRotationGraph+32768, 1, 15, func(rows [][][]byte) error {
		if len(rows) != 1 || len(rows[0]) != 15 {
			return ErrAdmissionResponse
		}
		row := rows[0]
		reply.Status = string(row[0])
		if reply.Status != "ready" {
			if !boundaryRotationStatus(reply.Status, false) || slices.ContainsFunc(row[1:], nonNullGrantColumn) {
				return ErrAdmissionResponse
			}
			return nil
		}
		input, e := decodeBoundaryRotationSnapshot(request, row[1])
		if e != nil {
			return e
		}
		boundary, group, e := input.manifests()
		if e != nil {
			return e
		}
		observed, e = observed.AdvanceBoundary(uuid.MustParse(request.BoundaryID), boundary)
		if e != nil {
			return e
		}
		observed, e = observed.AdvanceGroupKey(uuid.MustParse(request.GroupID), group)
		if e != nil {
			return e
		}
		if request.Review == "" {
			if slices.ContainsFunc(row[2:], nonNullGrantColumn) {
				return ErrAdmissionResponse
			}
			reply = GroupBoundaryGrantReply{Status: "review", Preview: &GroupBoundaryGrantPreview{
				GroupBoundaryGrantRequest: input.GroupBoundaryGrantRequest, PreviousMask: input.PreviousMask,
			}}
			return nil
		}
		prepared := &GroupBoundaryRotationPreparation{request: request, boundary: boundary}
		if e := prepared.readCustody(pin, group.Recovery, row[3:]); e != nil {
			return e
		}
		observed, e = prepared.verifyGraph(ctx, observed, pin, input.graphScope(), row[2])
		if e != nil {
			return e
		}
		prepared.trust = cloneTrustState(observed)
		plan = prepared
		return nil
	})
	return
}

func boundaryRotationStatus(status string, committing bool) bool {
	switch status {
	case "unavailable", "stale", "busy", "unchanged":
		return true
	case "changed":
		return committing
	}
	return false
}

func decodeBoundaryRotationSnapshot(request GroupBoundaryGrantRequest, raw []byte) (boundaryRotationSnapshot, error) {
	var input boundaryRotationSnapshot
	want := request
	want.Review = ""
	if len(raw) > 32768 {
		return input, ErrAdmissionResponse
	}
	if _, err := strictCatalogObject(raw, input); err != nil {
		return input, err
	}
	if json.Unmarshal(raw, &input) != nil || input.GroupBoundaryGrantRequest != want ||
		!validGroupBoundaryMask(input.PreviousMask) || want.Mask == input.PreviousMask || want.Mask&input.PreviousMask != want.Mask {
		return input, ErrAdmissionResponse
	}
	for _, revision := range []string{input.BoundaryRevision, input.GrantRevision, input.Epoch} {
		if _, ok := treeNumber([]byte(revision), 1, math.MaxInt64); !ok {
			return input, ErrAdmissionResponse
		}
	}
	if _, ok := treeNumber([]byte(input.ChangeSeq), 0, math.MaxInt64); !ok {
		return input, ErrAdmissionResponse
	}
	graphDigest, err := hex.DecodeString(input.GraphDigest)
	if err != nil || len(graphDigest) != sha256.Size || hex.EncodeToString(graphDigest) != input.GraphDigest {
		return input, ErrAdmissionResponse
	}
	hash := sha256.New()
	hash.Write([]byte("wormhole/v1/boundary-rotation-review:"))
	hash.Write(raw)
	digest := hex.EncodeToString(hash.Sum(nil))
	if request.Review != "" && request.Review != digest {
		return input, vault.ErrAuthentication
	}
	input.Review = digest
	return input, nil
}

func (input boundaryRotationSnapshot) manifests() (vault.BoundaryManifest, vault.GroupKeyManifest, error) {
	var group vault.GroupKeyManifest
	boundaryRaw, e1 := hex.DecodeString(input.Boundary)
	groupRaw, e2 := hex.DecodeString(input.Group)
	boundary, e3 := vault.DecodeBoundaryManifest(boundaryRaw)
	if e1 != nil || e2 != nil || e3 != nil || boundary.OwnerUserID != uuid.Nil || !boundary.OrgEscrow ||
		boundary.PreviousView != nil || boundary.PreviousSecret != nil {
		return boundary, group, ErrAdmissionResponse
	}
	group, err := vault.DecodeGroupKeyManifest(groupRaw)
	if err != nil || group.Signer != boundary.Signer || group.GroupRevision >= parseGroupGrantRevision(input.GroupRevision) {
		return boundary, group, ErrAdmissionResponse
	}
	return boundary, group, nil
}

func (plan *boundaryKeyCustody) readCustody(pin vault.UserKeyTrust, recipientKey vault.KeyRef, row [][]byte) error {
	signer, signing, e1 := parseServerCAOrgCopy(row[:5])
	encryptionKey, encryption, e2 := parseServerCAOrgCopy(row[5:10])
	public, e3 := hex.DecodeString(string(row[10]))
	proof, e4 := hex.DecodeString(string(row[11]))
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || signer != pin.Signer || encryptionKey != recipientKey {
		return ErrAdmissionResponse
	}
	recipient := vault.OrganisationRecoveryRecipient{WorkspaceID: pin.WorkspaceID, Signer: signer, Encryption: encryptionKey, PublicKey: public}
	if err := vault.VerifyOrganisationRecoveryRecipient(recipient, proof, pin.WorkspaceID, pin.Signer, pin.Organisation); err != nil {
		return err
	}
	plan.recipient, plan.proof, plan.signing, plan.encryption = recipient, proof, signing, encryption
	return nil
}

func (plan *GroupBoundaryRotationPreparation) verifyGraph(ctx context.Context, trust TrustState, pin vault.UserKeyTrust, input boundaryRotationGraphScope, raw []byte) (TrustState, error) {
	if len(raw) == 0 || len(raw) > maxBoundaryRotationGraph {
		return trust, ErrAdmissionResponse
	}
	hash := sha256.Sum256(raw)
	if input.Digest != hex.EncodeToString(hash[:]) {
		return trust, vault.ErrAuthentication
	}
	var wires []boundaryRotationRootWire
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wires); err != nil || len(wires) == 0 || len(wires) > 2 || decoder.Decode(new(any)) != io.EOF {
		return trust, ErrAdmissionResponse
	}
	selected := input.Affected
	request := AdmissionRequest{WorkspaceID: pin.WorkspaceID, UserID: trust.UserID}
	epoch, sequence := parseGroupGrantRevision(input.Epoch), parseGroupGrantRevision(input.ChangeSeq)
	for _, wire := range wires {
		var root vault.BoundaryKey
		var bit permissions.Mask
		switch wire.Purpose {
		case vault.BoundaryView:
			root, bit = plan.boundary.View, permissions.View
		case vault.BoundarySecret:
			root, bit = plan.boundary.Secret, permissions.Use
		default:
			return trust, ErrAdmissionResponse
		}
		if selected&bit == 0 || (bit == permissions.Use && selected&permissions.View != 0) ||
			len(wire.Recipients) == 0 || len(wire.Recipients) > 1024 || wire.DEKs == nil || len(wire.DEKs) > 8192 {
			return trust, ErrAdmissionResponse
		}
		selected &^= bit
		escrow, err := parseBoundaryRootCopy(wire.Escrow, request, root.Key, plan.recipient.Encryption, epoch, sequence, 24)
		if err != nil || escrow.group != nil || escrow.Author != nil || escrow.Binding.Issuer != pin.Signer {
			return trust, ErrAdmissionResponse
		}
		if err := vault.VerifyKeyCopy(escrow.Binding, escrow.Copy, pin.Organisation); err != nil {
			return trust, err
		}
		res := vault.BoundaryRootRotation{Purpose: wire.Purpose, Escrow: escrow.Copy}
		for _, holder := range wire.Recipients {
			if err := ctx.Err(); err != nil {
				return trust, err
			}
			next, endpoint, err := plan.verifyHolder(trust, holder)
			trust = next
			if err != nil {
				return trust, err
			}
			res.Recipients = append(res.Recipients, endpoint)
		}
		for _, raw := range wire.DEKs {
			if err := ctx.Err(); err != nil {
				return trust, err
			}
			row, e := snapshotOptionalRow(raw, 24)
			if e != nil || row == nil {
				return trust, ErrAdmissionResponse
			}
			key, e := releaseKeyRef(row, 3)
			if e != nil {
				return trust, e
			}
			copy, e := parseKeyCopyProjection([][][]byte{row}, request, key, root.Key, epoch, sequence)
			if e != nil {
				return trust, e
			}
			issuer, e := verifyRotationCopyIssuer(pin, *copy)
			if e != nil {
				return trust, e
			}
			res.DEKs = append(res.DEKs, vault.BoundaryRotationDEK{Binding: copy.Binding, Copy: copy.Copy, Issuer: issuer})
		}
		plan.roots = append(plan.roots, res)
	}
	if selected != 0 {
		return trust, ErrAdmissionResponse
	}
	return trust, nil
}

func (plan *GroupBoundaryRotationPreparation) verifyHolder(trust TrustState, holder boundaryRotationHolder) (TrustState, vault.BoundaryKey, error) {
	var key vault.BoundaryKey
	var err error
	if plan.boundary.OwnerUserID != uuid.Nil && holder.Kind != "org" {
		return trust, key, vault.ErrPolicy
	}
	switch holder.Kind {
	case "org":
		if holder.Key != plan.recipient.Encryption || holder.Subject != uuid.Nil || holder.Manifest != "" || holder.Proof != "" {
			return trust, key, ErrAdmissionResponse
		}
		key = vault.BoundaryKey{Key: holder.Key, Public: plan.recipient.PublicKey}
	case "user":
		if holder.Manifest != "" || holder.Subject == uuid.Nil || holder.Subject == plan.excludedUser {
			return trust, key, ErrAdmissionResponse
		}
		var issued []groupKeyHolder
		trust, issued, err = verifyGroupKeyRoster(trust, []byte(holder.Proof))
		if err != nil {
			return trust, key, err
		}
		if len(issued) != 1 || issued[0].member.ID != holder.Subject || issued[0].key.Key != holder.Key {
			return trust, key, vault.ErrAuthentication
		}
		key = issued[0].key
	case "group":
		if holder.Subject == uuid.Nil || holder.Subject.String() == plan.request.GroupID && plan.replacement == nil {
			return trust, key, ErrAdmissionResponse
		}
		body, e := hex.DecodeString(holder.Manifest)
		if e != nil {
			return trust, key, ErrAdmissionResponse
		}
		group, e := vault.DecodeGroupKeyManifest(body)
		if e != nil || group.Key.Key != holder.Key || group.Recovery != plan.recipient.Encryption {
			return trust, key, ErrAdmissionResponse
		}
		replacing := plan.replacement != nil && holder.Subject == plan.replacement.GroupID
		if replacing && group.Key.Key != plan.replacement.Key.Key {
			return trust, key, vault.ErrAuthentication
		}
		trust, e = trust.AdvanceGroupKey(holder.Subject, group)
		if e != nil {
			return trust, key, e
		}
		digest := groupKeyReviewDigest(GroupKeyRequest{GroupID: group.GroupID, Revision: group.GroupRevision}, []byte(holder.Proof))
		if !bytes.Equal(group.RosterDigest, digest[:]) {
			return trust, key, vault.ErrAuthentication
		}
		var roster []groupKeyHolder
		trust, roster, err = verifyGroupKeyRoster(trust, []byte(holder.Proof))
		for _, member := range roster {
			if member.member.ID == plan.excludedUser || replacing && member.member.ID == plan.removedMember {
				return trust, key, vault.ErrAuthentication
			}
		}
		key = group.Key
	default:
		err = ErrAdmissionResponse
	}
	return trust, key, err
}

func verifyRotationCopyIssuer(pin vault.UserKeyTrust, copy UnverifiedKeyCopy) (vault.KeyCopyTrust, error) {
	issuer := vault.KeyCopyTrust{Issuer: copy.Binding.Issuer, Public: pin.Organisation}
	if copy.Author != nil {
		author := copy.Author
		authorPin := pin
		authorPin.UserID = author.State.UserID
		if author.EnrollmentCertificate != nil {
			if err := vault.VerifyHistoricalUserEnrollmentCertificate(*author.EnrollmentCertificate, authorPin); err != nil {
				return issuer, err
			}
		} else if author.Certificate != nil {
			if err := vault.VerifyUserKeyCertificate(*author.Certificate, pin.WorkspaceID, authorPin.UserID, issuer.Issuer,
				"user-sign", pin.Signer, pin.Organisation, 1); err != nil {
				return issuer, err
			}
		} else {
			return issuer, vault.ErrAuthentication
		}
		issuer.Public = author.signingPublic()
	} else if issuer.Issuer != pin.Signer {
		return issuer, vault.ErrAuthentication
	}
	return issuer, vault.VerifyKeyCopy(copy.Binding, copy.Copy, issuer.Public)
}

type boundaryRotationPublication struct {
	Manifest string                   `json:"manifest"`
	Copies   []vault.RewrappedKeyCopy `json:"copies"`
}

func (s *Session) CommitPreparedGroupBoundaryRotation(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle,
	plan *GroupBoundaryRotationPreparation, keys *vault.UserKeys) (observed TrustState, reply GroupBoundaryGrantReply, err error) {
	if plan == nil || plan.request.Review == "" {
		return trust, reply, ErrConfiguration
	}
	return s.commitBoundaryRotation(ctx, trust, tls, plan, keys, boundaryRotationCall, plan.request.arguments)
}

func (s *Session) commitBoundaryRotation(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle,
	plan *GroupBoundaryRotationPreparation, keys *vault.UserKeys, call string, arguments func([]byte) [][]byte) (observed TrustState, reply GroupBoundaryGrantReply, err error) {
	observed = trust
	if ctx == nil || keys == nil || len(keys.SigningSeed) != 32 || len(keys.EncryptionPrivate) != 32 {
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
	rotation, err := plan.prepareRoots(ctx, trust, pin, keys)
	if err != nil {
		return trust, reply, err
	}
	manifest, err := vault.EncodeBoundaryManifest(rotation.Manifest)
	if err != nil {
		return trust, reply, err
	}
	publication, err := json.Marshal(boundaryRotationPublication{Manifest: string(manifest), Copies: rotation.Copies})
	if err != nil {
		return trust, reply, err
	}
	err = s.queryServerCA(ctx, trust, "SELECT status,pg_catalog.convert_from(snapshot,'UTF8')"+call,
		arguments(publication), 16384, 1, 2, func(rows [][][]byte) error {
			if len(rows) != 1 || len(rows[0]) != 2 {
				return ErrAdmissionResponse
			}
			status := string(rows[0][0])
			if !boundaryRotationStatus(status, true) && !(call == memberBoundaryRotationCall && status == "roster-changed") &&
				!(call == accountBoundaryRotationCall && status == "group-rotation-required") {
				return ErrAdmissionResponse
			}
			reply.Status = string(rows[0][0])
			if reply.Status == "changed" {
				if !bytes.Equal(rows[0][1], manifest) {
					return vault.ErrAuthentication
				}
				observed, err = observed.AdvanceBoundary(plan.boundary.BoundaryID, rotation.Manifest)
				return err
			}
			if rows[0][1] != nil {
				return ErrAdmissionResponse
			}
			return nil
		})
	return
}

func (plan *boundaryKeyCustody) openOrgKeys(trust TrustState, pin vault.UserKeyTrust, keys *vault.UserKeys) (*vault.UserKeys, error) {
	var org vault.UserKeys
	var err error
	org.SigningSeed, err = openServerCAOrgCopy(trust, pin.Signer, plan.signing, keys.EncryptionPrivate, keys.SigningSeed)
	if err != nil {
		return nil, err
	}
	org.EncryptionPrivate, err = openServerCAOrgCopy(trust, plan.recipient.Encryption, plan.encryption, keys.EncryptionPrivate, keys.SigningSeed)
	if err != nil {
		org.Wipe()
		return nil, err
	}
	return &org, nil
}

func (plan *GroupBoundaryRotationPreparation) prepareRoots(ctx context.Context, trust TrustState, pin vault.UserKeyTrust, keys *vault.UserKeys) (*vault.PreparedBoundaryRotation, error) {
	org, err := plan.openOrgKeys(trust, pin, keys)
	if err != nil {
		return nil, err
	}
	defer org.Wipe()
	scope := vault.BoundaryTrust{WorkspaceID: trust.WorkspaceID, BoundaryID: plan.boundary.BoundaryID,
		Signer: pin.Signer, Organisation: pin.Organisation, MinimumRevision: plan.boundary.Revision}
	if plan.boundary.OwnerUserID != uuid.Nil {
		return vault.PreparePersonalBoundaryRotation(ctx, plan.boundary, scope, plan.excludedUser, plan.recipient, plan.proof, org, plan.roots)
	}
	return vault.PrepareBoundaryRotation(ctx, plan.boundary, scope, plan.recipient, plan.proof, org, plan.roots)
}
