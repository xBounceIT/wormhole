package sharedpg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"slices"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const personalRootRecoverySignature = "wormhole_api_v1.restore_personal_roots(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bigint,bytea,jsonb)"
const personalRootRecoverySupportedSQL = "SELECT (pg_catalog.to_regprocedure('" + personalRootRecoverySignature + "') IS NOT NULL)::text"
const personalRootRecoveryCall = ` FROM wormhole_api_v1.restore_personal_roots(` + serverCAArguments + `,$10::uuid,$11::bigint,pg_catalog.decode($12,'hex'),$13::jsonb)`
const personalRootRecoveryMaterialSQL = `SELECT status,document,sign_id::text,sign_version::text,encode(sign_enc,'hex'),
    encode(sign_ciphertext,'hex'),encode(sign_proof,'hex'),org_id::text,org_version::text,encode(org_enc,'hex'),
    encode(org_ciphertext,'hex'),encode(org_proof,'hex'),encode(org_public,'hex'),encode(org_certificate,'hex')` + personalRootRecoveryCall
const maxPersonalRootRecoveryDocument = 4*vault.MaxUserEnrollmentCertificateBytes + 32768

type PersonalRootRecoveryRequest struct {
	AccountID  uuid.UUID
	Suspension uint64
	Review     *[32]byte
}

type PersonalRootRecoveryReply struct {
	Status      string `json:"status"`
	Review      string `json:"review,omitempty"`
	Enrollment  string `json:"enrollment,omitempty"`
	CanReenroll bool   `json:"canReenroll,omitempty"`
}

type personalRootRecoveryDocument struct {
	AccountID           uuid.UUID                    `json:"accountId"`
	Suspension          string                       `json:"suspension"`
	Manifest            []byte                       `json:"manifest"`
	Roster              json.RawMessage              `json:"roster"`
	PreviousCertificate []byte                       `json:"previousCertificate"`
	PreviousSequence    string                       `json:"previousSequence"`
	PreviousEncryption  vault.KeyRef                 `json:"previousEncryption"`
	PreviousSigning     vault.KeyRef                 `json:"previousSigning"`
	Signing             vault.KeyRef                 `json:"signing"`
	Recovery            vault.KeyRef                 `json:"recovery"`
	Roots               []workspaceAdminRecoveryCopy `json:"roots"`
}

type PersonalRootRecoveryPreparation struct {
	request  PersonalRootRecoveryRequest
	trust    TrustState
	manifest vault.BoundaryManifest
	holder   vault.BoundaryKey
	copies   []workspaceAdminRecoveryCopy
	boundaryKeyCustody
}

func (r PersonalRootRecoveryRequest) arguments(publication []byte) [][]byte {
	var review []byte
	if r.Review != nil {
		review = hex.AppendEncode(nil, r.Review[:])
	}
	return [][]byte{[]byte(r.AccountID.String()), strconv.AppendUint(nil, r.Suspension, 10), review, publication}
}

func (s *Session) PersonalRootRecoverySupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, personalRootRecoverySupportedSQL)
}

func personalRootRecoveryStatus(status string) bool {
	switch status {
	case "unavailable", "stale", "busy", "rotation-required", "enrollment-required", "unchanged":
		return true
	}
	return false
}

func (s *Session) PreparePersonalRootRecovery(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, request PersonalRootRecoveryRequest) (
	observed TrustState, reply PersonalRootRecoveryReply, plan *PersonalRootRecoveryPreparation, err error) {
	if ctx == nil || request.AccountID == uuid.Nil || request.AccountID == trust.UserID || request.Suspension == 0 || request.Suspension > math.MaxInt64 {
		return trust, reply, nil, ErrConfiguration
	}
	pin, err := authenticatedServerCAContext(trust, tls)
	if err != nil {
		return trust, reply, nil, err
	}
	policy, err := trust.Policy()
	if err != nil || !policy.OrgEscrow || (policy.Profile != vault.Default && policy.Profile != vault.Standard) {
		return trust, reply, nil, vault.ErrPolicy
	}
	observed = trust
	err = s.queryServerCA(ctx, trust, personalRootRecoveryMaterialSQL, request.arguments(nil), maxPersonalRootRecoveryDocument, 1, 14,
		func(rows [][][]byte) error {
			if len(rows) != 1 || len(rows[0]) != 14 {
				return ErrAdmissionResponse
			}
			row := rows[0]
			reply.Status = string(row[0])
			if reply.Status != "ready" {
				if personalRootRecoveryStatus(reply.Status) && !slices.ContainsFunc(row[1:], nonNullGrantColumn) {
					return nil
				}
				return ErrAdmissionResponse
			}
			var parsed PersonalRootRecoveryPreparation
			var digest [32]byte
			var recipient vault.KeyRef
			observed, parsed, digest, recipient, err = verifyPersonalRootRecoveryDocument(trust, pin, request, row[1])
			if err != nil {
				return err
			}
			if request.Review == nil {
				if slices.ContainsFunc(row[2:], nonNullGrantColumn) {
					return ErrAdmissionResponse
				}
				reply = PersonalRootRecoveryReply{Status: "review", Review: hex.EncodeToString(digest[:]), Enrollment: parsed.holder.Key.ID.String()}
				return nil
			}
			if err := parsed.readCustody(pin, recipient, row[2:]); err != nil {
				return err
			}
			parsed.trust = cloneTrustState(observed)
			plan = &parsed
			return nil
		})
	return
}

func verifyPersonalRootRecoveryDocument(trust TrustState, pin vault.UserKeyTrust, request PersonalRootRecoveryRequest, raw []byte) (
	observed TrustState, plan PersonalRootRecoveryPreparation, digest [32]byte, recipient vault.KeyRef, err error) {
	defer func() {
		if observed.Revision > trust.Revision {
			observed.Revision = trust.Revision + 1
		}
	}()
	var doc personalRootRecoveryDocument
	if len(raw) > maxPersonalRootRecoveryDocument {
		return trust, plan, digest, recipient, ErrAdmissionResponse
	}
	if _, err := strictCatalogObject(raw, doc); err != nil || json.Unmarshal(raw, &doc) != nil || doc.AccountID != request.AccountID ||
		doc.Suspension != strconv.FormatUint(request.Suspension, 10) || len(doc.Roots) != 2 || doc.Recovery.ID == uuid.Nil || doc.Recovery.Version == 0 {
		return trust, plan, digest, recipient, ErrAdmissionResponse
	}
	h := sha256.New()
	h.Write([]byte("wormhole/v1/personal-root-recovery:"))
	h.Write(raw)
	copy(digest[:], h.Sum(nil))
	if request.Review != nil && *request.Review != digest {
		return trust, plan, digest, recipient, vault.ErrAuthentication
	}
	manifest, err := vault.DecodeBoundaryManifest(doc.Manifest)
	if err != nil || !manifest.Active || !manifest.OrgEscrow || manifest.OwnerUserID != request.AccountID ||
		manifest.BoundaryID != personalImportBoundaryID(trust.WorkspaceID, request.AccountID) || manifest.PreviousView != nil || manifest.PreviousSecret != nil {
		return trust, plan, digest, recipient, vault.ErrAuthentication
	}
	observed, err = trust.AdvanceBoundary(manifest.BoundaryID, manifest)
	if err != nil {
		return observed, plan, digest, recipient, err
	}
	previous, err := vault.DecodeUserEnrollmentCertificate(doc.PreviousCertificate)
	pin.UserID = request.AccountID
	priorSequence, ok := treeNumber([]byte(doc.PreviousSequence), 1, math.MaxInt64)
	if err != nil || !ok || vault.VerifyHistoricalUserEnrollmentCertificate(previous, pin) != nil ||
		doc.PreviousEncryption != (vault.KeyRef{ID: previous.Rekey.EncryptionKeyID, Version: previous.Rekey.KeyVersion}) ||
		doc.PreviousSigning != (vault.KeyRef{ID: previous.Rekey.SigningKeyID, Version: previous.Rekey.KeyVersion}) {
		return observed, plan, digest, recipient, vault.ErrAuthentication
	}
	rows, err := snapshotRows(doc.Roster, 1, 5)
	if err != nil || len(rows) != 1 || string(rows[0][0]) != request.AccountID.String() {
		return observed, plan, digest, recipient, ErrAdmissionResponse
	}
	observed, holders, err := verifyGroupKeyRosterRows(observed, rows)
	if err != nil {
		return observed, plan, digest, recipient, err
	}
	if len(holders) != 1 || holders[0].member.ID != request.AccountID || holders[0].member.Login != previous.Manifest.Context.LoginName ||
		holders[0].key.Key.ID == doc.PreviousEncryption.ID || holders[0].signing.ID == doc.PreviousSigning.ID ||
		holders[0].signing != doc.Signing || holders[0].stateSequence <= priorSequence {
		return observed, plan, digest, recipient, vault.ErrAuthentication
	}
	for i, root := range []vault.BoundaryKey{manifest.View, manifest.Secret} {
		c := doc.Roots[i]
		binding := vault.KeyCopyBinding{WorkspaceID: trust.WorkspaceID, Key: root.Key, Holder: doc.Recovery, Issuer: pin.Signer}
		if c.KeyRef != root.Key || root.Key.Version < 2 || vault.VerifyKeyCopy(binding, accountRecoverySignedCopy(c), pin.Organisation) != nil {
			return observed, plan, digest, recipient, vault.ErrAuthentication
		}
	}
	plan = PersonalRootRecoveryPreparation{request: request, manifest: manifest, holder: holders[0].key, copies: doc.Roots}
	return observed, plan, digest, doc.Recovery, nil
}

func (s *Session) CommitPreparedPersonalRootRecovery(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle,
	plan *PersonalRootRecoveryPreparation, keys *vault.UserKeys) (PersonalRootRecoveryReply, error) {
	var reply PersonalRootRecoveryReply
	if ctx == nil || plan == nil || plan.request.Review == nil || keys == nil {
		return reply, ErrConfiguration
	}
	expected := plan.trust
	expected.Revision = trust.Revision
	if !reflect.DeepEqual(trust, expected) {
		return reply, ErrTrustState
	}
	pin, err := authenticatedServerCAContext(trust, tls)
	if err != nil {
		return reply, err
	}
	publication, err := plan.wrapForOwner(ctx, trust, pin, keys)
	if err != nil {
		return reply, err
	}
	err = s.queryServerCA(ctx, trust, "SELECT status"+personalRootRecoveryCall, plan.request.arguments(publication), 128, 1, 1, func(rows [][][]byte) error {
		if len(rows) != 1 || len(rows[0]) != 1 {
			return ErrAdmissionResponse
		}
		reply.Status = string(rows[0][0])
		if reply.Status != "changed" && !personalRootRecoveryStatus(reply.Status) {
			return ErrAdmissionResponse
		}
		return nil
	})
	return reply, err
}

func (plan *PersonalRootRecoveryPreparation) wrapForOwner(ctx context.Context, trust TrustState, pin vault.UserKeyTrust, keys *vault.UserKeys) ([]byte, error) {
	org, err := plan.openOrgKeys(trust, pin, keys)
	if err != nil {
		return nil, err
	}
	defer org.Wipe()
	if err := verifyEscrowKeyPair(org, vault.UserPublicKeys{Encryption: plan.recipient.PublicKey, Signing: pin.Organisation}); err != nil {
		return nil, err
	}
	scope := vault.BoundaryTrust{WorkspaceID: trust.WorkspaceID, BoundaryID: plan.manifest.BoundaryID,
		Signer: pin.Signer, Organisation: pin.Organisation, MinimumRevision: plan.manifest.Revision}
	issuer := vault.KeyCopyTrust{Issuer: pin.Signer, Public: pin.Organisation}
	var publication [2]workspaceAdminRecoveryCopy
	for i, purpose := range []vault.BoundaryPurpose{vault.BoundaryView, vault.BoundarySecret} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c := plan.copies[i]
		binding := vault.KeyCopyBinding{WorkspaceID: trust.WorkspaceID, Key: c.KeyRef, Holder: plan.recipient.Encryption, Issuer: pin.Signer}
		seed, err := vault.OpenBoundaryKeyCopy(org.EncryptionPrivate, binding, accountRecoverySignedCopy(c), issuer, plan.manifest, scope, purpose)
		if err != nil {
			return nil, err
		}
		binding.Holder = plan.holder.Key
		sealed, err := vault.SealKeyCopy(seed, binding, plan.holder.Public, org.SigningSeed)
		vault.Wipe(seed)
		if err != nil {
			return nil, err
		}
		publication[i] = workspaceAdminRecoveryCopy{KeyRef: c.KeyRef, Enc: sealed.Envelope.Enc, Ciphertext: sealed.Envelope.Ciphertext, Signature: sealed.Signature}
	}
	return json.Marshal(publication)
}
