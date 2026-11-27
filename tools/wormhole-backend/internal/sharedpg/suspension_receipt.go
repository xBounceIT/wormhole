package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"math"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const suspensionReceiptCapability = "SELECT (pg_catalog.to_regprocedure('wormhole_api_v1.suspend_account(bytea,uuid,bigint,bigint,bytea,bytea,bytea)') IS NOT NULL)::text"
const suspensionSignerSQL = "SELECT " + serverCAKeyColumns + " FROM wormhole_api_v1.suspension_rotation_signer(" + serverCAArguments + ")"
const signedSuspensionSQL = `SELECT status,payload::text FROM wormhole_api_v1.suspend_account(
	pg_catalog.decode($1,'hex'),$2::uuid,$3::bigint,$4::bigint,pg_catalog.decode($5,'hex'),pg_catalog.decode($6,'hex'),pg_catalog.decode($7,'hex'))`
const suspensionReceiptsSQL = `SELECT actor_id::text,account_id::text,revision::text,pg_catalog.encode(signature,'hex')
	FROM wormhole_api_v1.suspension_rotation_receipts(pg_catalog.decode($1,'hex'),$2::bigint,$3::uuid) r ORDER BY r.account_id`

// The signature authorizes key rotation for one committed suspension. Restoring
// a backup changes the workspace epoch; re-enabling an account changes its revision.
type suspensionReceipt struct {
	workspace uuid.UUID
	epoch     int64
	actor     uuid.UUID
	account   uuid.UUID
	revision  int64
	signer    vault.KeyRef
}

func (r suspensionReceipt) message() ([]byte, error) {
	if r.workspace == uuid.Nil || r.epoch < 1 || r.actor == uuid.Nil || r.account == uuid.Nil ||
		r.actor == r.account || r.revision < 2 || r.signer.ID == uuid.Nil || r.signer.Version == 0 || r.signer.Version > math.MaxInt32 {
		return nil, ErrConfiguration
	}
	msg := []byte("wormhole/v1/suspension-rotation\x00")
	msg = append(msg, r.workspace[:]...)
	msg = binary.BigEndian.AppendUint64(msg, uint64(r.epoch))
	msg = append(msg, r.actor[:]...)
	msg = append(msg, r.account[:]...)
	msg = binary.BigEndian.AppendUint64(msg, uint64(r.revision))
	msg = append(msg, r.signer.ID[:]...)
	return binary.BigEndian.AppendUint32(msg, r.signer.Version), nil
}

func (r suspensionReceipt) verify(signature []byte, pin vault.UserKeyTrust, epoch int64) error {
	message, err := r.message()
	if err != nil {
		return err
	}
	if r.workspace != pin.WorkspaceID || r.signer != pin.Signer || r.epoch != epoch ||
		len(pin.Organisation) != ed25519.PublicKeySize || !ed25519.Verify(pin.Organisation, message, signature) {
		return vault.ErrAuthentication
	}
	return nil
}

func (s *Session) SuspensionReceiptsSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, suspensionReceiptCapability)
}

func (s *Session) SuspendWithReceipt(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, epoch int64,
	request WorkspaceAccessRequest, keys *vault.UserKeys) (reply WorkspaceAccessReply, err error) {
	if keys == nil || len(keys.SigningSeed) != ed25519.SeedSize || len(keys.EncryptionPrivate) != 32 ||
		!request.Valid() || request.Action != "disable-account" || request.Revision == "" {
		return reply, ErrConfiguration
	}
	pin, err := authenticatedServerCAContext(trust, tls)
	if err != nil {
		return reply, err
	}
	revision, err := strconv.ParseInt(request.Revision, 10, 64)
	if err != nil || revision == math.MaxInt64 {
		return reply, ErrConfiguration
	}
	receipt := suspensionReceipt{trust.WorkspaceID, epoch, trust.UserID, uuid.MustParse(request.TargetID), revision + 1, pin.Signer}
	message, err := receipt.message()
	if err != nil {
		return reply, err
	}
	var signature []byte
	err = s.queryServerCA(ctx, trust, suspensionSignerSQL, nil, 1024, 1, 5, func(rows [][][]byte) error {
		if len(rows) == 0 {
			return nil
		}
		if len(rows) != 1 || len(rows[0]) != 5 {
			return ErrAdmissionResponse
		}
		key, copy, err := parseServerCAOrgCopy(rows[0])
		if err != nil || key != pin.Signer {
			return ErrAdmissionResponse
		}
		seed, err := openServerCAOrgCopy(trust, key, copy, keys.EncryptionPrivate, keys.SigningSeed)
		if err != nil {
			return err
		}
		defer vault.Wipe(seed)
		if len(seed) != ed25519.SeedSize {
			return vault.ErrAuthentication
		}
		private := ed25519.NewKeyFromSeed(seed)
		defer vault.Wipe(private)
		if !bytes.Equal(private.Public().(ed25519.PublicKey), pin.Organisation) {
			return vault.ErrAuthentication
		}
		signature = ed25519.Sign(private, message)
		return nil
	})
	if err != nil {
		return reply, err
	}
	if signature == nil {
		return s.WorkspaceAccess(ctx, trust, request)
	}
	args := [][]byte{[]byte(request.TargetID), []byte(request.Revision), strconv.AppendInt(nil, epoch, 10), hex.AppendEncode(nil, signature)}
	err = s.queryAdministration(ctx, trust, signedSuspensionSQL, args, workspaceAccessMaxBytes, 2, func(row [][]byte) error {
		reply, err = parseWorkspaceAccessReply(row, request, trust.DeviceID)
		return err
	})
	return reply, err
}

type SuspendedAccount struct {
	ID       uuid.UUID
	Revision uint64
}

const SuspensionReceiptPageSize = 25

func (s *Session) ReadSuspensionReceipts(ctx context.Context, pin vault.UserKeyTrust, epoch int64, after uuid.UUID) ([]SuspendedAccount, error) {
	if ctx == nil || epoch < 1 || pin.WorkspaceID == uuid.Nil || pin.UserID == uuid.Nil || len(pin.Organisation) != ed25519.PublicKeySize {
		return nil, ErrConfiguration
	}
	var cursor []byte
	if after != uuid.Nil {
		cursor = []byte(after.String())
	}
	var accounts []SuspendedAccount
	err := s.queryAuthenticatedRows(ctx, suspensionReceiptsSQL, [][]byte{strconv.AppendInt(nil, epoch, 10), cursor},
		8192, SuspensionReceiptPageSize, 4, func(rows [][][]byte, admission AdmissionRequest) error {
			if admission.WorkspaceID != pin.WorkspaceID || admission.UserID != pin.UserID {
				return ErrAuthentication
			}
			var e error
			accounts, e = verifySuspensionReceipts(rows, pin, epoch, after)
			return e
		})
	return accounts, err
}

func verifySuspensionReceipts(rows [][][]byte, pin vault.UserKeyTrust, epoch int64, after uuid.UUID) ([]SuspendedAccount, error) {
	var accounts []SuspendedAccount
	for _, row := range rows {
		if len(row) != 4 {
			return nil, ErrAdmissionResponse
		}
		actor, actorOK := treeID(row[0])
		account, accountOK := treeID(row[1])
		revision, revisionOK := treeNumber(row[2], 2, math.MaxInt64)
		signature, err := hex.AppendDecode(nil, row[3])
		if !actorOK || !accountOK || !revisionOK || err != nil || bytes.Compare(after[:], account[:]) >= 0 || account == pin.UserID {
			return nil, ErrAdmissionResponse
		}
		receipt := suspensionReceipt{pin.WorkspaceID, epoch, actor, account, int64(revision), pin.Signer}
		if err := receipt.verify(signature, pin, epoch); err != nil {
			return nil, err
		}
		accounts = append(accounts, SuspendedAccount{account, revision})
		after = account
	}
	return accounts, nil
}
