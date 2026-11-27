package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/workspaceimport"
)

const workspaceImportBoundarySQL = `SELECT pg_catalog.encode(wormhole_api_v1.workspace_import_boundary(` + serverCAArguments + `,$10::boolean),'hex')`
const personalImportSignerSQL = `SELECT ` + serverCAKeyColumns + `,recipient_id::text,recipient_version::text,
 pg_catalog.encode(recipient_public,'hex'),pg_catalog.encode(recipient_signature,'hex')
 FROM wormhole_api_v1.personal_import_signer(` + serverCAArguments + `)`
const provisionPersonalImportBoundarySQL = `SELECT pg_catalog.encode(wormhole_api_v1.provision_personal_import_boundary(` + serverCAArguments +
	`,$10::text,$11::jsonb),'hex')`

const workspaceImportDestinationsAvailableSQL = `SELECT
 (pg_catalog.to_regprocedure('wormhole_api_v1.workspace_import_boundary(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,boolean)') IS NOT NULL
  AND pg_catalog.to_regprocedure('wormhole_api_v1.personal_import_signer(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea)') IS NOT NULL
  AND pg_catalog.to_regprocedure('wormhole_api_v1.provision_personal_import_boundary(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,text,jsonb)') IS NOT NULL)::text`

func (s *Session) WorkspaceImportDestinationsSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, workspaceImportDestinationsAvailableSQL)
}

func personalImportBoundaryID(workspace, owner uuid.UUID) uuid.UUID {
	id := sha256.Sum256([]byte("wormhole/v1/personal-import-boundary:" + workspace.String() + ":" + owner.String()))
	id[6] = 0x80 | id[6]&0x0f
	id[8] = 0x80 | id[8]&0x0f
	return uuid.UUID(id[:16])
}

// WorkspaceImportBoundary reads and authenticates the selected destination.
// The native owner must durably record any returned trust observations, even
// on error, before using a manifest.
// A nil personal result means a custodian has yet to provision that destination.
func (s *Session) WorkspaceImportBoundary(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, scope workspaceimport.Destination) (observed TrustState, result *vault.BoundaryManifest, err error) {
	if ctx == nil || (scope != workspaceimport.Personal && scope != workspaceimport.Shared) {
		return TrustState{}, nil, ErrConfiguration
	}
	if _, err := authenticatedServerCAContext(trust, tls); err != nil {
		return TrustState{}, nil, err
	}
	personal := scope == workspaceimport.Personal
	err = s.queryServerCA(ctx, trust, workspaceImportBoundarySQL, [][]byte{strconv.AppendBool(nil, personal)},
		2*vault.MaxBoundaryManifestBytes, 1, 1, func(rows [][][]byte) error {
			var e error
			observed, result, e = decodeImportBoundary(rows, trust, personal, personal)
			return e
		})
	if err != nil {
		return observed, nil, err
	}
	return observed, result, nil
}

func decodeImportBoundary(rows [][][]byte, trust TrustState, personal, allowMissing bool) (TrustState, *vault.BoundaryManifest, error) {
	if len(rows) != 1 || len(rows[0]) != 1 || len(rows[0][0]) > 2*vault.MaxBoundaryManifestBytes {
		return TrustState{}, nil, ErrAdmissionResponse
	}
	owner, expected := uuid.Nil, uuid.Nil
	if personal {
		owner, expected = trust.UserID, personalImportBoundaryID(trust.WorkspaceID, trust.UserID)
	}
	if rows[0][0] == nil && allowMissing {
		if trust.Catalog["boundary/"+expected.String()].Revision != 0 {
			return TrustState{}, nil, vault.ErrRollback
		}
		return TrustState{}, nil, nil
	}
	raw, err := hex.AppendDecode(nil, rows[0][0])
	if err != nil {
		return TrustState{}, nil, ErrAdmissionResponse
	}
	m, err := vault.DecodeBoundaryManifest(raw)
	if err != nil {
		return TrustState{}, nil, err
	}
	if m.OwnerUserID != owner || (personal && m.BoundaryID != expected) {
		return TrustState{}, nil, vault.ErrAuthentication
	}
	observed, err := trust.AdvanceBoundary(m.BoundaryID, m)
	if err != nil {
		return observed, nil, err
	}
	if !m.OrgEscrow {
		return observed, nil, vault.ErrPolicy
	}
	return observed, &m, nil
}

// EnsurePersonalImportBoundary recovers an existing destination by identity or
// provisions one for the admitted custodian. The original view/secret roots are
// never replaced by a retry. Fresh-factor policy belongs to the native caller.
func (s *Session) EnsurePersonalImportBoundary(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, keys *vault.UserKeys) (TrustState, *vault.BoundaryManifest, error) {
	if ctx == nil || keys == nil {
		return TrustState{}, nil, ErrConfiguration
	}
	pin, err := authenticatedServerCAContext(trust, tls)
	if err != nil {
		return TrustState{}, nil, err
	}
	policy, err := trust.Policy()
	if err != nil || !policy.OrgEscrow {
		return TrustState{}, nil, vault.ErrPolicy
	}
	public, err := keys.Public()
	if err != nil {
		return TrustState{}, nil, err
	}
	digest := enrollmentPublicDigest(public)
	if !bytes.Equal(digest[:], trust.Enrollment.PublicDigest) {
		return TrustState{}, nil, vault.ErrAuthentication
	}
	if observed, current, err := s.WorkspaceImportBoundary(ctx, trust, tls, workspaceimport.Personal); err != nil || current != nil {
		return observed, current, err
	}
	var material personalImportSigner
	err = s.queryServerCA(ctx, trust, personalImportSignerSQL, nil, 1024, 1, 9, func(rows [][][]byte) error {
		var e error
		material, e = parsePersonalImportSigner(rows, trust.WorkspaceID)
		return e
	})
	if err != nil {
		return TrustState{}, nil, err
	}
	if err := vault.VerifyOrganisationRecoveryRecipient(material.recipient, material.certificate, trust.WorkspaceID, pin.Signer, pin.Organisation); err != nil {
		return TrustState{}, nil, err
	}
	seed, err := openServerCAOrgCopy(trust, pin.Signer, material.copy, keys.EncryptionPrivate, keys.SigningSeed)
	if err != nil {
		return TrustState{}, nil, err
	}
	defer vault.Wipe(seed)
	if len(seed) != ed25519.SeedSize {
		return TrustState{}, nil, vault.ErrAuthentication
	}
	signer := ed25519.NewKeyFromSeed(seed)
	defer vault.Wipe(signer)
	if !bytes.Equal(signer.Public().(ed25519.PublicKey), pin.Organisation) {
		return TrustState{}, nil, vault.ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		return TrustState{}, nil, err
	}
	manifest, copies, err := preparePersonalImportBoundary(trust, material.recipient, public.Encryption, signer)
	if err != nil {
		return TrustState{}, nil, err
	}
	var observed TrustState
	var result *vault.BoundaryManifest
	err = s.queryServerCA(ctx, trust, provisionPersonalImportBoundarySQL, [][]byte{manifest, copies},
		2*vault.MaxBoundaryManifestBytes, 1, 1, func(rows [][][]byte) error {
			var e error
			observed, result, e = decodeImportBoundary(rows, trust, true, false)
			return e
		})
	if err != nil {
		return observed, nil, err
	}
	return observed, result, nil
}

type personalImportSigner struct {
	recipient   vault.OrganisationRecoveryRecipient
	certificate []byte
	copy        vault.SignedKeyCopy
}

type personalImportCopy struct {
	Binding vault.KeyCopyBinding `json:"binding"`
	vault.SignedKeyCopy
}

func parsePersonalImportSigner(rows [][][]byte, workspace uuid.UUID) (personalImportSigner, error) {
	if len(rows) != 1 || len(rows[0]) != 9 {
		return personalImportSigner{}, ErrAdmissionResponse
	}
	r := rows[0]
	signer, copy, err := parseServerCAOrgCopy(r[:5])
	holder, ok := treeID(r[5])
	version, validVersion := treeNumber(r[6], 1, math.MaxInt32)
	if err != nil || !ok || !validVersion || len(r[7]) != 64 || len(r[8]) != 128 {
		return personalImportSigner{}, ErrAdmissionResponse
	}
	public, err := hex.AppendDecode(nil, r[7])
	proof, certErr := hex.AppendDecode(nil, r[8])
	if err != nil || certErr != nil {
		return personalImportSigner{}, ErrAdmissionResponse
	}
	return personalImportSigner{recipient: vault.OrganisationRecoveryRecipient{WorkspaceID: workspace,
		Signer: signer, Encryption: vault.KeyRef{ID: holder, Version: uint32(version)}, PublicKey: public},
		certificate: proof, copy: copy}, nil
}

func preparePersonalImportBoundary(trust TrustState, recipient vault.OrganisationRecoveryRecipient, ownerPublic []byte, signer ed25519.PrivateKey) ([]byte, []byte, error) {
	var view, secret [32]byte
	defer vault.Wipe(view[:])
	defer vault.Wipe(secret[:])
	viewRoot, err := newBoundaryRoot(view[:])
	if err != nil {
		return nil, nil, err
	}
	secretRoot, err := newBoundaryRoot(secret[:])
	if err != nil {
		return nil, nil, err
	}
	m, err := vault.SignBoundaryManifest(vault.BoundaryManifest{
		FormatVersion: vault.FormatVersion, WorkspaceID: trust.WorkspaceID, BoundaryID: personalImportBoundaryID(trust.WorkspaceID, trust.UserID),
		OwnerUserID: trust.UserID, Revision: 1, OrgEscrow: true, Active: true, View: viewRoot, Secret: secretRoot, Signer: recipient.Signer,
	}, signer)
	if err != nil {
		return nil, nil, err
	}
	body, err := vault.EncodeBoundaryManifest(m)
	if err != nil {
		return nil, nil, err
	}
	// The fixed order binds each root to the owner and then the organisation.
	copies := make([]personalImportCopy, 0, 4)
	for _, item := range []struct {
		key  vault.KeyRef
		seed []byte
	}{{viewRoot.Key, view[:]}, {secretRoot.Key, secret[:]}} {
		for _, holder := range []vault.BoundaryKey{
			{Key: trust.Enrollment.Encryption, Public: ownerPublic}, {Key: recipient.Encryption, Public: recipient.PublicKey},
		} {
			binding := vault.KeyCopyBinding{
				WorkspaceID: trust.WorkspaceID, Key: item.key, Holder: holder.Key, Issuer: m.Signer,
			}
			copy, err := vault.SealKeyCopy(item.seed, binding, holder.Public, signer[:ed25519.SeedSize])
			if err != nil {
				return nil, nil, err
			}
			copies = append(copies, personalImportCopy{Binding: binding, SignedKeyCopy: copy})
		}
	}
	encoded, err := json.Marshal(copies)
	return body, encoded, err
}
