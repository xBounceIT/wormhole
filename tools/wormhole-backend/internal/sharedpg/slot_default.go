package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"math"
	"strconv"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const slotDefaultAvailableSQL = `SELECT (pg_catalog.to_regprocedure(
 'wormhole_api_v1.slot_default(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,text,bigint,bytea,uuid,bytea,bytea)') IS NOT NULL)::text`
const slotDefaultSQL = `SELECT status,epoch::text,change_seq::text,slot_row::text,credential_row::text
 FROM wormhole_api_v1.slot_default(` + serverCAArguments + `,$10::uuid,$11,$12::bigint,pg_catalog.decode($13,'hex'),
 $14::uuid,pg_catalog.decode($15,'hex'),pg_catalog.decode($16,'hex'))`

// SlotDefaultChoice is the public confirmation. The native review retains the
// signed inputs until the controller has durably committed their trust floors.
type SlotDefaultChoice struct {
	SlotID             string `json:"slotId"`
	SlotName           string `json:"slotName"`
	SlotRevision       string `json:"slotRevision"`
	Protocol           string `json:"protocol"`
	CredentialName     string `json:"credentialName"`
	CredentialID       string `json:"credentialId"`
	CredentialRevision string `json:"credentialRevision"`
	HasDefault         bool   `json:"hasDefault"`
}

type SlotDefaultReview struct {
	Choice          SlotDefaultChoice
	workspace, user uuid.UUID
	slot            *UnverifiedSelection
	credential      *UnverifiedCredential
}

func (s *Session) SlotDefaultSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, slotDefaultAvailableSQL)
}

func (s *Session) ReadSlotDefault(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, id uuid.UUID, name string) (TrustState, *SlotDefaultReview, string, error) {
	if ctx == nil || id == uuid.Nil || (name != "" && !adminGroupText(name, 1024)) {
		return trust, nil, "", ErrConfiguration
	}
	if _, err := authenticatedServerCAContext(trust, tls); err != nil {
		return trust, nil, "", err
	}
	args := [][]byte{[]byte(id.String()), []byte(name), nil, nil, nil, nil, nil}
	var review *SlotDefaultReview
	var status string
	err := s.queryServerCA(ctx, trust, slotDefaultSQL, args, 2*adminSlotPageMaxBytes, 1, 5, func(rows [][][]byte) error {
		var err error
		trust, review, status, err = verifySlotDefault(rows, trust, id, name, "review")
		return err
	})
	if err != nil {
		return trust, nil, "", err
	}
	return trust, review, status, nil
}

func verifySlotDefault(rows [][][]byte, trust TrustState, id uuid.UUID, name, expected string) (TrustState, *SlotDefaultReview, string, error) {
	if len(rows) != 1 || len(rows[0]) != 5 {
		return trust, nil, "", ErrAdmissionResponse
	}
	row := rows[0]
	status := string(row[0])
	if status != expected {
		if (status == "unavailable" || status == "stale" || status == "busy") && row[1] == nil && row[2] == nil && row[3] == nil && row[4] == nil {
			return trust, nil, status, nil
		}
		return trust, nil, "", ErrAdmissionResponse
	}
	epoch, eok := treeNumber(row[1], 1, math.MaxInt64)
	seq, sok := treeNumber(row[2], 0, math.MaxInt64)
	if !eok || !sok || (row[4] == nil) != (name == "") || !utf8.Valid(row[3]) || !utf8.Valid(row[4]) {
		return trust, nil, "", ErrAdmissionResponse
	}
	request := AdmissionRequest{WorkspaceID: trust.WorkspaceID, UserID: trust.UserID, DeviceID: trust.DeviceID}
	wire, err := snapshotOptionalRow(row[3], 24)
	if err != nil {
		return trust, nil, "", err
	}
	slot, author, err := parseSelectionProjection([][][]byte{wire}, request, sharedcatalog.SelectionScope{Kind: "slot", Subject: id}, epoch, seq)
	if err != nil {
		return trust, nil, "", err
	}
	initialRevision := trust.Revision
	next, err := trust.AdvanceSelection(*slot, *author)
	if next.Revision != 0 {
		trust = next
	}
	if err != nil {
		return trust, nil, "", err
	}
	record := slot.Record.(sharedcatalog.SlotRecord)
	review := &SlotDefaultReview{workspace: trust.WorkspaceID, user: trust.UserID, slot: slot, Choice: SlotDefaultChoice{
		SlotID: record.ID, SlotName: record.Name, SlotRevision: strconv.FormatUint(slot.Seal.Revision, 10), Protocol: record.Protocol, HasDefault: record.DefaultCredentialID != "",
	}}
	if name != "" {
		wire, err = snapshotOptionalRow(row[4], 24)
		if err != nil || len(wire) < 2 {
			return trust, nil, "", ErrAdmissionResponse
		}
		credentialID, ok := treeID(wire[1])
		if !ok {
			return trust, nil, "", ErrAdmissionResponse
		}
		credential, signer, err := parseCredentialProjection([][][]byte{wire}, request, credentialID, epoch, seq)
		if err != nil {
			return trust, nil, "", err
		}
		// Both records belong to one database snapshot and one durable checkpoint.
		credentialTrust := trust
		credentialTrust.Revision = initialRevision
		next, err := credentialTrust.AdvanceCredential(*credential, *signer)
		if next.Revision != 0 {
			next.Revision = max(next.Revision, trust.Revision)
			trust = next
		}
		if err != nil {
			return trust, nil, "", err
		}
		if signer.State.UserID == author.State.UserID && signer.State.Sequence != author.State.Sequence {
			return trust, nil, "", ErrAdmissionResponse
		}
		meta := credential.Record.Metadata
		if meta.Name != name || meta.Protocol != record.Protocol || meta.Provider != "local" || meta.OwnerUserID != "" {
			return trust, nil, "", ErrAdmissionResponse
		}
		review.credential = credential
		review.Choice.CredentialName, review.Choice.CredentialID, review.Choice.CredentialRevision = meta.Name, meta.ID, strconv.FormatUint(credential.Seal.Revision, 10)
	}
	if expected == "review" && slot.Seal.Revision >= math.MaxInt64 {
		return trust, nil, "unavailable", nil
	}
	return trust, review, status, nil
}

func (r *SlotDefaultReview) Unchanged() bool {
	selected := ""
	if r.credential != nil {
		selected = r.credential.Record.Metadata.ID
	}
	return r.slot.Record.(sharedcatalog.SlotRecord).DefaultCredentialID == selected
}

func (s *Session) CommitSlotDefault(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, r *SlotDefaultReview, keys *vault.UserKeys) (TrustState, string, error) {
	if ctx == nil || r == nil || r.workspace != trust.WorkspaceID || r.user != trust.UserID || r.slot == nil || keys == nil || r.slot.Seal.Revision >= math.MaxInt64 {
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
	record := r.slot.Record.(sharedcatalog.SlotRecord)
	var credentialID, credentialSeal []byte
	name := ""
	record.DefaultCredentialID = ""
	if r.credential != nil {
		record.DefaultCredentialID = r.credential.Record.Metadata.ID
		name = r.credential.Record.Metadata.Name
		credentialID = []byte(record.DefaultCredentialID)
		credentialSeal = hex.AppendEncode(nil, r.credential.Seal.Signature)
	}
	if record == r.slot.Record {
		return trust, "unchanged", nil
	}
	private := ed25519.NewKeyFromSeed(keys.SigningSeed)
	defer vault.Wipe(private)
	seal, err := sharedcatalog.SignSelection(trust.WorkspaceID, r.slot.Boundary, record, r.slot.Seal.Revision+1, trust.Enrollment.Signing, private)
	if err != nil {
		return trust, "", err
	}
	args := [][]byte{[]byte(record.ID), []byte(name), strconv.AppendUint(nil, r.slot.Seal.Revision, 10), hex.AppendEncode(nil, r.slot.Seal.Signature), credentialID, credentialSeal, hex.AppendEncode(nil, seal.Signature)}
	var status string
	err = s.queryServerCA(ctx, trust, slotDefaultSQL, args, 2*adminSlotPageMaxBytes, 1, 5, func(rows [][][]byte) error {
		var receipt *SlotDefaultReview
		var err error
		trust, receipt, status, err = verifySlotDefault(rows, trust, uuid.MustParse(record.ID), name, "saved")
		if err == nil && receipt != nil && (receipt.slot.Record != record || receipt.slot.Boundary != r.slot.Boundary ||
			!bytes.Equal(receipt.slot.Seal.Signature, seal.Signature) || (r.credential != nil && (receipt.credential.Record.Metadata.ID != record.DefaultCredentialID ||
			!bytes.Equal(receipt.credential.Seal.Signature, r.credential.Seal.Signature)))) {
			return vault.ErrAuthentication
		}
		return err
	})
	if err != nil {
		return trust, "", err
	}
	return trust, status, nil
}
