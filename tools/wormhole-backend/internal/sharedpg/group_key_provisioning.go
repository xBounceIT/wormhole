package sharedpg

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const maxGroupRoster = 64
const maxGroupRosterBytes = 3 * 1024 * 1024

const groupKeySupportedSQL = `SELECT (pg_catalog.to_regprocedure('wormhole_api_v1.group_key_material(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bigint,bytea)') IS NOT NULL)::text`
const groupKeyMaterialSQL = `SELECT status,pg_catalog.convert_from(roster,'UTF8'),pg_catalog.convert_from(manifest,'UTF8'),
 ` + serverCAKeyColumns + `,recipient_id::text,recipient_version::text,pg_catalog.encode(recipient_public,'hex'),pg_catalog.encode(recipient_signature,'hex')
 FROM wormhole_api_v1.group_key_material(` + serverCAArguments + `,$10::uuid,$11::bigint,pg_catalog.decode($12,'hex'))`
const commitGroupKeySQL = `SELECT status,pg_catalog.convert_from(manifest,'UTF8')
 FROM wormhole_api_v1.commit_group_key(` + serverCAArguments + `,$10::uuid,$11::bigint,$12::text,$13::jsonb)`

type GroupKeyRequest struct {
	GroupID  uuid.UUID
	Revision uint64
	Review   *[32]byte
}

type GroupKeyMember struct {
	ID    uuid.UUID `json:"id"`
	Login string    `json:"login"`
}

type GroupKeyPreview struct {
	GroupID  uuid.UUID        `json:"groupId"`
	Revision string           `json:"revision"`
	Review   string           `json:"review"`
	Members  []GroupKeyMember `json:"members"`
}

type GroupKeyReply struct {
	Status  string           `json:"status"`
	Preview *GroupKeyPreview `json:"preview,omitempty"`
}

type groupKeyHolder struct {
	member        GroupKeyMember
	key           vault.BoundaryKey
	signing       vault.KeyRef
	stateSequence uint64
}

// GroupKeyPreparation stays native. The signing seed remains encrypted until a
// confirmation has been checked and the member observations are durable.
type GroupKeyPreparation struct {
	request  GroupKeyRequest
	holders  []groupKeyHolder
	custody  personalImportSigner
	previous vault.KeyRef
}

func (s *Session) GroupKeySupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, groupKeySupportedSQL)
}

func (s *Session) PrepareGroupKey(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, request GroupKeyRequest) (observed TrustState, reply GroupKeyReply, plan *GroupKeyPreparation, err error) {
	if ctx == nil || request.GroupID == uuid.Nil || request.Revision == 0 || request.Revision >= math.MaxInt64 {
		return trust, reply, nil, ErrConfiguration
	}
	pin, err := authenticatedServerCAContext(trust, tls)
	if err != nil {
		return trust, reply, nil, err
	}
	args := groupKeyArguments(request)
	var review []byte
	if request.Review != nil {
		review = hex.AppendEncode(nil, request.Review[:])
	}
	observed = trust
	err = s.queryServerCA(ctx, trust, groupKeyMaterialSQL, append(args, review), maxGroupRosterBytes+8192, 1, 12, func(rows [][][]byte) error {
		if len(rows) != 1 || len(rows[0]) != 12 {
			return ErrAdmissionResponse
		}
		row := rows[0]
		reply.Status = string(row[0])
		if reply.Status == "issued" {
			return ErrAdmissionResponse
		}
		if reply.Status != "ready" {
			return decodeGroupKeyStatus(request, &observed, reply.Status, row[1], row[2], row[3:])
		}
		if trust.Catalog["group-key/"+request.GroupID.String()].Revision != 0 {
			return vault.ErrRollback
		}
		if row[2] != nil || len(row[1]) == 0 {
			return ErrAdmissionResponse
		}
		digest := groupKeyReviewDigest(request, row[1])
		var holders []groupKeyHolder
		var e error
		observed, holders, e = verifyGroupKeyRoster(trust, row[1])
		if e != nil {
			return e
		}
		if request.Review == nil {
			if slices.ContainsFunc(row[3:], func(col []byte) bool { return col != nil }) {
				return ErrAdmissionResponse
			}
			preview := &GroupKeyPreview{GroupID: request.GroupID, Revision: strconv.FormatUint(request.Revision, 10),
				Review: hex.EncodeToString(digest[:]), Members: make([]GroupKeyMember, 0, len(holders))}
			for _, holder := range holders {
				preview.Members = append(preview.Members, holder.member)
			}
			reply = GroupKeyReply{Status: "review", Preview: preview}
			return nil
		}
		if digest != *request.Review {
			return vault.ErrAuthentication
		}
		custody, e := parsePersonalImportSigner([][][]byte{row[3:]}, trust.WorkspaceID)
		if e != nil {
			return e
		}
		if e := vault.VerifyOrganisationRecoveryRecipient(custody.recipient, custody.certificate, trust.WorkspaceID, pin.Signer, pin.Organisation); e != nil {
			return e
		}
		plan = &GroupKeyPreparation{request: request, holders: holders, custody: custody}
		return nil
	})
	return
}

func groupKeyArguments(request GroupKeyRequest) [][]byte {
	return [][]byte{[]byte(request.GroupID.String()), strconv.AppendUint(nil, request.Revision, 10)}
}

func groupKeyReviewDigest(request GroupKeyRequest, roster []byte) (digest [32]byte) {
	hash := sha256.New()
	hash.Write([]byte("wormhole/v1/group-key-review:" + request.GroupID.String() + ":" + strconv.FormatUint(request.Revision, 10) + ":"))
	hash.Write(roster)
	copy(digest[:], hash.Sum(nil))
	return digest
}

func decodeGroupKeyStatus(request GroupKeyRequest, trust *TrustState, status string, roster, manifest []byte, extra [][]byte) error {
	if roster != nil || slices.ContainsFunc(extra, func(col []byte) bool { return col != nil }) {
		return ErrAdmissionResponse
	}
	switch status {
	case "issued", "provisioned":
		if len(manifest) == 0 || (status == "issued" && request.Review == nil) {
			return ErrAdmissionResponse
		}
		m, err := vault.DecodeGroupKeyManifest(manifest)
		if err != nil {
			return err
		}
		if status == "issued" && (m.GroupRevision != request.Revision || !bytes.Equal(m.RosterDigest, request.Review[:])) {
			return vault.ErrAuthentication
		}
		next, err := trust.AdvanceGroupKey(request.GroupID, m)
		if next.Revision != 0 {
			*trust = next
		}
		return err
	case "unavailable", "stale", "busy", "no-members", "too-large", "incomplete":
		if manifest == nil {
			return nil
		}
	}
	return ErrAdmissionResponse
}

func verifyGroupKeyRoster(trust TrustState, raw []byte) (TrustState, []groupKeyHolder, error) {
	if len(raw) == 0 || len(raw) > maxGroupRosterBytes || !utf8.Valid(raw) {
		return trust, nil, ErrAdmissionResponse
	}
	rows, err := snapshotRows(raw, maxGroupRoster, 5)
	if err != nil || len(rows) == 0 {
		return trust, nil, ErrAdmissionResponse
	}
	return verifyGroupKeyRosterRows(trust, rows)
}

func verifyGroupKeyRosterRows(trust TrustState, rows [][][]byte) (TrustState, []groupKeyHolder, error) {
	pin, err := trust.accountTrust()
	if err != nil {
		return trust, nil, err
	}
	holders := make([]groupKeyHolder, 0, len(rows))
	seen := make(map[uuid.UUID]bool, len(rows))
	var previous uuid.UUID
	for _, row := range rows {
		user, userOK := treeID(row[0])
		key, keyOK := treeID(row[1])
		version, versionOK := treeNumber(row[2], 1, math.MaxInt32)
		stateRaw, stateErr := hex.AppendDecode(nil, row[3])
		certRaw, certErr := hex.AppendDecode(nil, row[4])
		if !userOK || !keyOK || !versionOK || stateErr != nil || certErr != nil ||
			bytes.Compare(user[:], previous[:]) <= 0 || seen[key] {
			return trust, nil, ErrAdmissionResponse
		}
		reference := vault.KeyRef{ID: key, Version: uint32(version)}
		previous, seen[key] = user, true
		state, err := vault.DecodeUserKeyState(stateRaw)
		if err != nil || state.UserID != user {
			return trust, nil, vault.ErrAuthentication
		}
		cert, err := vault.DecodeUserEnrollmentCertificate(certRaw)
		if err != nil || cert.Rekey.EncryptionKeyID != key || cert.Rekey.KeyVersion != uint32(version) ||
			!adminGroupText(cert.Manifest.Context.LoginName, 256) {
			return trust, nil, vault.ErrAuthentication
		}
		author := UnverifiedNodeAuthor{State: &state, EnrollmentCertificate: &cert}
		floor := trust.catalogAuthorFloor(user)
		userPin := pin
		userPin.UserID, userPin.MinimumSequence = user, floor.Revision
		if user == trust.UserID && trust.Account != nil {
			userPin.MinimumSequence = max(userPin.MinimumSequence, trust.Account.Sequence)
		}
		if err := vault.VerifyUserKeyState(state, userPin); err != nil {
			return trust, nil, err
		}
		material := trust.catalogAuthorMaterial(author)
		verifyErr := vault.VerifyUserEnrollmentCertificate(cert, state, userPin, material.minimum)
		var revision uint64
		if verifyErr == nil {
			revision = cert.Manifest.Revision
		}
		next, err := trust.mergeCatalogAuthor(author, material, floor, state.Sequence, revision, verifyErr)
		if next.Revision != 0 {
			trust = next
		}
		if err != nil {
			return trust, nil, err
		}
		holders = append(holders, groupKeyHolder{
			member:  GroupKeyMember{user, cert.Manifest.Context.LoginName},
			key:     vault.BoundaryKey{Key: reference, Public: cert.Rekey.Public.Encryption},
			signing: material.selection.Signing, stateSequence: state.Sequence,
		})
	}
	return trust, holders, nil
}

func (s TrustState) AdvanceGroupKey(expected uuid.UUID, manifest vault.GroupKeyManifest) (TrustState, error) {
	pin, err := s.accountTrust()
	if err != nil {
		return TrustState{}, err
	}
	key := "group-key/" + expected.String()
	if err := vault.VerifyGroupKeyManifest(manifest, s.WorkspaceID, expected, pin.Signer, pin.Organisation, uint32(s.Catalog[key].Revision)); err != nil {
		return s, err
	}
	return s.mergeCatalogObservations(vault.UserKeyState{}, CatalogFloor{}, 0, nil,
		catalogFloorObservation{key, uint64(manifest.Key.Key.Version), manifest})
}

func (s *Session) CommitPreparedGroupKey(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, plan *GroupKeyPreparation,
	keys *vault.UserKeys) (observed TrustState, reply GroupKeyReply, err error) {
	if ctx == nil || keys == nil || plan == nil || plan.request.Review == nil {
		return trust, reply, ErrConfiguration
	}
	pin, err := authenticatedServerCAContext(trust, tls)
	if err != nil {
		return trust, reply, err
	}
	manifest, copies, err := plan.authenticatedCopies(trust, pin, keys)
	if err != nil {
		return trust, reply, err
	}
	observed = trust
	args := append(groupKeyArguments(plan.request), manifest, copies)
	err = s.queryServerCA(ctx, trust, commitGroupKeySQL, args, 8192, 1, 2, func(rows [][][]byte) error {
		if len(rows) != 1 || len(rows[0]) != 2 {
			return ErrAdmissionResponse
		}
		reply.Status = string(rows[0][0])
		if reply.Status == "issued" && !bytes.Equal(rows[0][1], manifest) {
			return vault.ErrAuthentication
		}
		return decodeGroupKeyStatus(plan.request, &observed, reply.Status, nil, rows[0][1], nil)
	})
	return
}

func (plan *GroupKeyPreparation) authenticatedCopies(trust TrustState, pin vault.UserKeyTrust, keys *vault.UserKeys) ([]byte, []byte, error) {
	seed, err := openServerCAOrgCopy(trust, pin.Signer, plan.custody.copy, keys.EncryptionPrivate, keys.SigningSeed)
	if err != nil {
		return nil, nil, err
	}
	defer vault.Wipe(seed)
	if len(seed) != ed25519.SeedSize {
		return nil, nil, vault.ErrAuthentication
	}
	signer := ed25519.NewKeyFromSeed(seed)
	defer vault.Wipe(signer)
	if !bytes.Equal(signer.Public().(ed25519.PublicKey), pin.Organisation) {
		return nil, nil, vault.ErrAuthentication
	}
	return prepareGroupKeyCopies(trust.WorkspaceID, plan, signer, seed)
}

func prepareGroupKeyCopies(workspace uuid.UUID, plan *GroupKeyPreparation, signer ed25519.PrivateKey, signerSeed []byte) ([]byte, []byte, error) {
	var seed [32]byte
	defer vault.Wipe(seed[:])
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, nil, err
	}
	private, err := ecdh.X25519().NewPrivateKey(seed[:])
	if err != nil {
		return nil, nil, vault.ErrFormat
	}
	reference := plan.previous
	if reference.ID == uuid.Nil {
		id, err := uuid.NewRandom()
		if err != nil {
			return nil, nil, err
		}
		reference = vault.KeyRef{ID: id, Version: 1}
	} else {
		reference.Version++
	}
	m := vault.GroupKeyManifest{FormatVersion: 1, WorkspaceID: workspace, GroupID: plan.request.GroupID,
		GroupRevision: plan.request.Revision, RosterDigest: plan.request.Review[:],
		Key:      vault.BoundaryKey{Key: reference, Public: private.PublicKey().Bytes()},
		Recovery: plan.custody.recipient.Encryption, Signer: plan.custody.recipient.Signer}
	m, err = vault.SignGroupKeyManifest(m, signer)
	if err != nil {
		return nil, nil, err
	}
	raw, err := vault.EncodeGroupKeyManifest(m)
	if err != nil {
		return nil, nil, err
	}
	recipients := make([]vault.BoundaryKey, 0, len(plan.holders)+1)
	for _, holder := range plan.holders {
		recipients = append(recipients, holder.key)
	}
	recipients = append(recipients, vault.BoundaryKey{Key: m.Recovery, Public: plan.custody.recipient.PublicKey})
	copies := make([]personalImportCopy, 0, len(recipients))
	for _, recipient := range recipients {
		binding := vault.KeyCopyBinding{WorkspaceID: workspace, Key: m.Key.Key, Holder: recipient.Key, Issuer: m.Signer}
		copy, err := vault.SealKeyCopy(seed[:], binding, recipient.Public, signerSeed)
		if err != nil {
			return nil, nil, err
		}
		copies = append(copies, personalImportCopy{Binding: binding, SignedKeyCopy: copy})
	}
	encoded, err := json.Marshal(copies)
	return raw, encoded, err
}
