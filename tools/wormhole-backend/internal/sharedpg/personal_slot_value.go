package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"math"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const personalSlotAvailableSQL = `SELECT (pg_catalog.to_regprocedure(
 'wormhole_api_v1.personal_slot_value(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,text,bigint,bytea,uuid,bytea,uuid,bytea,bytea)') IS NOT NULL)::text`
const personalSlotSQL = `SELECT status,epoch::text,change_seq::text,slot_row::text,value_row::text,credential_row::text
 FROM wormhole_api_v1.personal_slot_value(` + serverCAArguments + `,$10::uuid,$11,$12::bigint,pg_catalog.decode($13,'hex'),
 $14::uuid,pg_catalog.decode($15,'hex'),$16::uuid,pg_catalog.decode($17,'hex'),pg_catalog.decode($18,'hex'))`

func (s *Session) PersonalSlotSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, personalSlotAvailableSQL)
}

func (s *Session) ReadPersonalSlot(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, slot uuid.UUID, name string) (TrustState, *SlotReview, string, error) {
	if ctx == nil || slot == uuid.Nil || (name != "" && !adminGroupText(name, 1024)) {
		return trust, nil, "", ErrConfiguration
	}
	if _, err := authenticatedServerCAContext(trust, tls); err != nil {
		return trust, nil, "", err
	}
	args := [][]byte{[]byte(slot.String()), []byte(name), nil, nil, nil, nil, nil, nil, nil}
	return s.personalSlotQuery(ctx, trust, slot, name, "review", args)
}

func (s *Session) personalSlotQuery(ctx context.Context, trust TrustState, slot uuid.UUID, name, expected string, args [][]byte) (TrustState, *SlotReview, string, error) {
	var reviewed *SlotReview
	var status string
	err := s.queryServerCA(ctx, trust, personalSlotSQL, args, 3*adminSlotPageMaxBytes, 1, 6, func(rows [][][]byte) error {
		var err error
		trust, reviewed, status, err = verifyPersonalSlot(rows, trust, slot, name, expected)
		return err
	})
	if err != nil {
		return trust, nil, "", err
	}
	return trust, reviewed, status, nil
}

func verifyPersonalSlot(rows [][][]byte, trust TrustState, id uuid.UUID, name, expected string) (TrustState, *SlotReview, string, error) {
	if len(rows) != 1 || len(rows[0]) != 6 {
		return trust, nil, "", ErrAdmissionResponse
	}
	row := rows[0]
	if string(row[0]) != expected && row[4] != nil {
		return trust, nil, "", ErrAdmissionResponse
	}
	baseRevision := trust.Revision
	trust, choice, status, err := verifyNamedSlot([][][]byte{{row[0], row[1], row[2], row[3], row[5]}}, trust, id, name, expected, true)
	if err != nil || choice == nil {
		return trust, nil, status, err
	}
	choice.Choice.UserID = trust.UserID.String()
	choice.Choice.ValueRevision = "0"
	if choice.credential != nil {
		choice.Choice.Provider = choice.credential.Record.Metadata.Provider
	}
	if row[4] == nil {
		if _, seen := trust.Catalog["slot-value/"+id.String()+"/"+trust.UserID.String()]; seen || expected == "saved" {
			return trust, nil, "", ErrAdmissionResponse
		}
		return trust, choice, status, nil
	}
	wire, err := snapshotOptionalRow(row[4], 24)
	if err != nil {
		return trust, nil, "", err
	}
	epoch, _ := treeNumber(row[1], 1, math.MaxInt64)
	seq, _ := treeNumber(row[2], 0, math.MaxInt64)
	scope := sharedcatalog.SelectionScope{Kind: "slot-value", Subject: id, User: trust.UserID}
	request := AdmissionRequest{WorkspaceID: trust.WorkspaceID, UserID: trust.UserID, DeviceID: trust.DeviceID}
	value, author, err := parseSelectionProjection([][][]byte{wire}, request, scope, epoch, seq)
	if err != nil {
		return trust, nil, "", err
	}
	previous := trust
	previous.Revision = baseRevision
	next, err := previous.AdvanceSelection(*value, *author)
	if next.Revision != 0 {
		next.Revision = max(next.Revision, trust.Revision)
		trust = next
	}
	record := value.Record.(sharedcatalog.SlotValueRecord)
	if err != nil && !(record.Deleted && errors.Is(err, vaultstore.ErrMissing)) {
		return trust, nil, "", err
	}
	if value.Boundary != personalImportBoundaryID(trust.WorkspaceID, trust.UserID) {
		return trust, nil, "", ErrAdmissionResponse
	}
	for _, other := range []*UnverifiedNodeAuthor{choice.slotAuthor, choice.credentialAuthor} {
		if other != nil && author.State.UserID == other.State.UserID && author.State.Sequence != other.State.Sequence {
			return trust, nil, "", ErrAdmissionResponse
		}
	}
	if expected == "review" && value.Seal.Revision >= math.MaxInt64 {
		return trust, nil, "unavailable", nil
	}
	choice.value = value
	choice.Choice.HasAssignment = !record.Deleted
	choice.Choice.ValueRevision = strconv.FormatUint(value.Seal.Revision, 10)
	return trust, choice, status, nil
}

func (s *Session) CommitPersonalSlot(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, r *SlotReview, keys *vault.UserKeys) (TrustState, string, error) {
	if ctx == nil || r == nil || !r.personal || r.workspace != trust.WorkspaceID || r.user != trust.UserID || keys == nil {
		return trust, "", ErrConfiguration
	}
	if _, err := authenticatedServerCAContext(trust, tls); err != nil {
		return trust, "", err
	}
	pub, err := keys.Public()
	if err != nil {
		return trust, "", err
	}
	digest := enrollmentPublicDigest(pub)
	if !bytes.Equal(digest[:], trust.Enrollment.PublicDigest) {
		return trust, "", vault.ErrAuthentication
	}
	if r.Unchanged() {
		return trust, "unchanged", nil
	}
	slot := r.slot.Record.(sharedcatalog.SlotRecord)
	record := sharedcatalog.SlotValueRecord{SlotID: slot.ID, UserID: trust.UserID.String(), Deleted: r.credential == nil}
	var revision uint64
	var oldSeal, credentialID, credentialSeal []byte
	if r.value == nil {
		id, err := uuid.NewRandom()
		if err != nil {
			return trust, "", err
		}
		record.ID = id.String()
	} else {
		record.ID = r.value.Record.(sharedcatalog.SlotValueRecord).ID
		revision = r.value.Seal.Revision
		oldSeal = hex.AppendEncode(nil, r.value.Seal.Signature)
	}
	if revision >= math.MaxInt64 {
		return trust, "", ErrConfiguration
	}
	name := ""
	if credential := r.credential; credential != nil {
		record.CredentialID = credential.Record.Metadata.ID
		name = credential.Record.Metadata.Name
		credentialID = []byte(record.CredentialID)
		credentialSeal = hex.AppendEncode(nil, credential.Seal.Signature)
	}
	key := ed25519.NewKeyFromSeed(keys.SigningSeed)
	defer vault.Wipe(key)
	boundary := personalImportBoundaryID(trust.WorkspaceID, trust.UserID)
	seal, err := sharedcatalog.SignSelection(trust.WorkspaceID, boundary, record, revision+1, trust.Enrollment.Signing, key)
	if err != nil {
		return trust, "", err
	}
	args := [][]byte{[]byte(slot.ID), []byte(name), strconv.AppendUint(nil, revision, 10), hex.AppendEncode(nil, r.slot.Seal.Signature),
		[]byte(record.ID), oldSeal, credentialID, credentialSeal, hex.AppendEncode(nil, seal.Signature)}
	next, receipt, status, err := s.personalSlotQuery(ctx, trust, uuid.MustParse(slot.ID), name, "saved", args)
	if err != nil {
		return next, "", err
	}
	if receipt != nil && (receipt.value == nil || receipt.value.Record != record || !bytes.Equal(receipt.value.Seal.Signature, seal.Signature) ||
		!bytes.Equal(receipt.slot.Seal.Signature, r.slot.Seal.Signature) ||
		(r.credential != nil && !bytes.Equal(receipt.credential.Seal.Signature, r.credential.Seal.Signature))) {
		return next, "", vault.ErrAuthentication
	}
	return next, status, nil
}
