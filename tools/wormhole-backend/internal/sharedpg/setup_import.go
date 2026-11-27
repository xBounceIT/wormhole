package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/workspaceimport"
)

var ErrSetupImportConflict = errors.New("workspace_setup_import_approval_changed")

const setupImportReceiptSQL = `SELECT pg_catalog.encode(approval,'hex'),pg_catalog.encode(signature,'hex')
 FROM wormhole_api_v1.setup_import_receipt(` + serverCAArguments + `,$10::uuid)`
const commitSetupImportSQL = `SELECT wormhole_api_v1.commit_setup_import(` + serverCAArguments +
	`,$10::uuid,pg_catalog.decode($11,'hex'),pg_catalog.decode($12,'hex'),$13::text,pg_catalog.decode($14,'hex'))`
const setupImportSupportedSQL = `SELECT
 (pg_catalog.to_regprocedure('wormhole_api_v1.setup_import_receipt(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid)') IS NOT NULL
 AND pg_catalog.to_regprocedure('wormhole_api_v1.commit_setup_import(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bytea,bytea,text,bytea)') IS NOT NULL)::text`

func (s *Session) SetupImportSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, setupImportSupportedSQL)
}

func setupImportApprovalMessage(target workspaceimport.Target, approval [sha256.Size]byte) []byte {
	data := []byte("wormhole/v1/setup-import-approval\x00")
	for _, id := range []uuid.UUID{target.WorkspaceID, target.UserID, target.RequestID} {
		data = append(data, id[:]...)
	}
	return append(data, approval[:]...)
}

func setupImportActor(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, target workspaceimport.Target, keys *vault.UserKeys) (vault.UserPublicKeys, error) {
	if ctx == nil || keys == nil || target.RequestID == uuid.Nil || target.WorkspaceID != trust.WorkspaceID || target.UserID != trust.UserID {
		return vault.UserPublicKeys{}, ErrConfiguration
	}
	if _, err := authenticatedServerCAContext(trust, tls); err != nil {
		return vault.UserPublicKeys{}, err
	}
	public, err := keys.Public()
	if err != nil {
		return vault.UserPublicKeys{}, err
	}
	digest := enrollmentPublicDigest(public)
	if !bytes.Equal(digest[:], trust.Enrollment.PublicDigest) {
		return vault.UserPublicKeys{}, vault.ErrAuthentication
	}
	return public, nil
}

// SetupImportCommitted verifies the actor's proof before accepting a receipt
// or deciding whether it describes the currently reviewed source and choices.
func (s *Session) SetupImportCommitted(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, target workspaceimport.Target, approval [sha256.Size]byte, keys *vault.UserKeys) (bool, error) {
	public, err := setupImportActor(ctx, trust, tls, target, keys)
	if err != nil {
		return false, err
	}
	var found, matches bool
	err = s.queryServerCA(ctx, trust, setupImportReceiptSQL, [][]byte{[]byte(target.RequestID.String())}, 256, 1, 2, func(rows [][][]byte) error {
		if len(rows) == 0 {
			return nil
		}
		if len(rows) != 1 || len(rows[0]) != 2 || len(rows[0][0]) != 2*sha256.Size || len(rows[0][1]) != 2*ed25519.SignatureSize {
			return ErrAdmissionResponse
		}
		var actual [sha256.Size]byte
		_, decodeErr := hex.Decode(actual[:], rows[0][0])
		proof, proofErr := hex.DecodeString(string(rows[0][1]))
		if decodeErr != nil || proofErr != nil || !ed25519.Verify(public.Signing, setupImportApprovalMessage(target, actual), proof) {
			return vault.ErrAuthentication
		}
		found, matches = true, actual == approval
		return nil
	})
	if err == nil && found && !matches {
		return false, ErrSetupImportConflict
	}
	return found && err == nil, err
}

func (s *Session) CommitSetupWorkspaceImport(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, target workspaceimport.Target, approval [sha256.Size]byte,
	keys *vault.UserKeys, sealed *workspaceimport.SealedImport) error {
	public, err := setupImportActor(ctx, trust, tls, target, keys)
	if err != nil {
		return err
	}
	if err := sealed.VerifyPostgresAuthor(trust.WorkspaceID, trust.UserID, trust.Enrollment.Signing, public.Signing); err != nil {
		return err
	}
	body, signature := sealed.PostgresPayload()
	defer vault.Wipe(body)
	if len(body) > 128*1024*1024 {
		return ErrResultLimit
	}
	private := ed25519.NewKeyFromSeed(keys.SigningSeed)
	defer vault.Wipe(private)
	proof := ed25519.Sign(private, setupImportApprovalMessage(target, approval))
	args := [][]byte{[]byte(target.RequestID.String()), hex.AppendEncode(nil, approval[:]), hex.AppendEncode(nil, proof), body, hex.AppendEncode(nil, signature)}
	return s.queryServerCA(ctx, trust, commitSetupImportSQL, args, 64, 1, 1, func(rows [][][]byte) error {
		if len(rows) != 1 || len(rows[0]) != 1 {
			return ErrAdmissionResponse
		}
		if result := string(rows[0][0]); result != "imported" && result != "already-imported" {
			return ErrAdmissionResponse
		}
		return nil
	})
}
