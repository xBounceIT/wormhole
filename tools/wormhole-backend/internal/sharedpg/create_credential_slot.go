package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const createSlotAvailableSQL = `SELECT (pg_catalog.to_regprocedure(
 'wormhole_api_v1.create_credential_slot(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,text,text,boolean,uuid,bytea,bytea)') IS NOT NULL)::text`
const createSlotSQL = `SELECT status,epoch::text,change_seq::text,payload::text
 FROM wormhole_api_v1.create_credential_slot(` + serverCAArguments + `,$10::uuid,$11,$12,$13::boolean,$14::uuid,
 pg_catalog.decode($15,'hex'),pg_catalog.decode($16,'hex'))`

func (s *Session) CreateCredentialSlotSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, createSlotAvailableSQL)
}

func (slot AdminCredentialSlot) Valid() bool {
	return slot.ID != uuid.Nil && adminGroupText(slot.Name, 1024) && strings.TrimSpace(slot.Name) != "" &&
		(slot.Protocol == "ssh" || slot.Protocol == "rdp" || slot.Protocol == "vnc")
}

// CreateCredentialSlot creates only an empty slot. The ID stays stable across
// retries. Return authenticated floors even when later receipt checks fail.
func (s *Session) CreateCredentialSlot(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, manifest vault.BoundaryManifest,
	slot AdminCredentialSlot, keys *vault.UserKeys) (observed TrustState, status string, err error) {
	if ctx == nil || !slot.Valid() || keys == nil {
		return trust, "", ErrConfiguration
	}
	if _, err = authenticatedServerCAContext(trust, tls); err != nil {
		return trust, "", err
	}
	observed, err = trust.AdvanceBoundary(manifest.BoundaryID, manifest)
	if err != nil || observed.Revision != trust.Revision || manifest.OwnerUserID != uuid.Nil || !manifest.OrgEscrow {
		if err == nil {
			err = vault.ErrPolicy
		}
		return observed, "", err
	}
	pub, err := keys.Public()
	if err != nil {
		return trust, "", err
	}
	digest := enrollmentPublicDigest(pub)
	if !bytes.Equal(digest[:], trust.Enrollment.PublicDigest) {
		return trust, "", vault.ErrAuthentication
	}
	record := sharedcatalog.SlotRecord{ID: slot.ID.String(), Name: slot.Name, Protocol: slot.Protocol, AllowSelfService: slot.AllowSelfService}
	private := ed25519.NewKeyFromSeed(keys.SigningSeed)
	defer vault.Wipe(private)
	seal, err := sharedcatalog.SignSelection(trust.WorkspaceID, manifest.BoundaryID, record, 1, trust.Enrollment.Signing, private)
	if err != nil {
		return trust, "", err
	}
	encoded, err := vault.EncodeBoundaryManifest(manifest)
	if err != nil {
		return trust, "", err
	}
	manifestDigest := sha256.Sum256(encoded)
	args := [][]byte{[]byte(record.ID), []byte(record.Name), []byte(record.Protocol), strconv.AppendBool(nil, slot.AllowSelfService),
		[]byte(manifest.BoundaryID.String()), hex.AppendEncode(nil, manifestDigest[:]), hex.AppendEncode(nil, seal.Signature)}
	err = s.queryServerCA(ctx, trust, createSlotSQL, args, adminSlotPageMaxBytes, 1, 4, func(rows [][][]byte) error {
		var e error
		observed, status, e = verifyCreatedSlot(rows, trust, slot.ID, manifest.BoundaryID, record, seal)
		return e
	})
	return observed, status, err
}

func verifyCreatedSlot(rows [][][]byte, trust TrustState, id, boundary uuid.UUID, record sharedcatalog.SlotRecord, seal vault.RecordSeal) (TrustState, string, error) {
	if len(rows) != 1 || len(rows[0]) != 4 {
		return trust, "", ErrAdmissionResponse
	}
	row := rows[0]
	status := string(row[0])
	if status != "saved" {
		if (status == "busy" || status == "stale" || status == "unavailable") && row[1] == nil && row[2] == nil && row[3] == nil {
			return trust, status, nil
		}
		return trust, "", ErrAdmissionResponse
	}
	epoch, epochOK := treeNumber(row[1], 1, math.MaxInt64)
	seq, seqOK := treeNumber(row[2], 0, math.MaxInt64)
	if !epochOK || !seqOK || len(row[3]) > adminSlotPageMaxBytes || !utf8.Valid(row[3]) {
		return trust, "", ErrAdmissionResponse
	}
	item, err := snapshotOptionalRow(row[3], 24)
	if err != nil {
		return trust, "", err
	}
	req := AdmissionRequest{WorkspaceID: trust.WorkspaceID, UserID: trust.UserID, DeviceID: trust.DeviceID}
	value, author, err := parseSelectionProjection([][][]byte{item}, req, sharedcatalog.SelectionScope{Kind: "slot", Subject: id}, epoch, seq)
	if err != nil {
		return trust, "", err
	}
	next, err := trust.AdvanceSelection(*value, *author)
	if err != nil {
		return next, "", err
	}
	if value.Boundary != boundary || value.Record != record || !bytes.Equal(value.Seal.Signature, seal.Signature) || author.State.UserID != trust.UserID {
		return next, "", vault.ErrAuthentication
	}
	return next, status, nil
}
