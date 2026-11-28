package sharedpg

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const adminSlotsAvailableSQL = `SELECT (pg_catalog.to_regprocedure(
 'wormhole_api_v1.admin_credential_slots(bytea,uuid,bytea,bytea)') IS NOT NULL)::text`
const mySlotsAvailableSQL = `SELECT (pg_catalog.to_regprocedure(
 'wormhole_api_v1.my_credential_slots(bytea,uuid,bytea,bytea)') IS NOT NULL)::text`
const slotPageColumns = `SELECT status,epoch::text,change_seq::text,payload::text FROM wormhole_api_v1.`
const slotPageArguments = `(pg_catalog.decode($1,'hex'),$2::uuid,pg_catalog.decode($3,'hex'),pg_catalog.decode($4,'hex'))`
const adminSlotsSQL = slotPageColumns + "admin_credential_slots" + slotPageArguments
const mySlotsSQL = slotPageColumns + "my_credential_slots" + slotPageArguments

// One hex-encoded enrollment certificate must always fit, along with the
// record, author state and JSON escaping. Ordinary pages are bounded in SQL.
const adminSlotPageMaxBytes = 2*vault.MaxUserEnrollmentCertificateBytes + adminInventoryMaxBytes

type AdminCredentialSlot struct {
	ID               uuid.UUID `json:"id"`
	Name             string    `json:"name"`
	Protocol         string    `json:"protocol"`
	AllowSelfService bool      `json:"allowSelfService"`
}

type AdminSlotPage struct {
	Kind    string                `json:"kind"`
	Entries []AdminCredentialSlot `json:"entries"`
	Next    *AdminInventoryCursor `json:"next,omitempty"`
}

// AdminCredentialSlots returns the observations to commit even if a later slot
// is rejected. Only a successful, committed page may be sent to the desktop.
func (s *Session) AdminCredentialSlots(ctx context.Context, trust TrustState, after uuid.UUID) (TrustState, *AdminSlotPage, error) {
	return s.credentialSlotPage(ctx, trust, after, false)
}

func (s *Session) PersonalCredentialSlots(ctx context.Context, trust TrustState, after uuid.UUID) (TrustState, *AdminSlotPage, error) {
	return s.credentialSlotPage(ctx, trust, after, true)
}

func (s *Session) credentialSlotPage(ctx context.Context, trust TrustState, after uuid.UUID, personal bool) (TrustState, *AdminSlotPage, error) {
	var observed TrustState
	var page *AdminSlotPage
	var cursor []byte
	if after != uuid.Nil {
		cursor = []byte(after.String())
	}
	statement := adminSlotsSQL
	if personal {
		statement = mySlotsSQL
	}
	err := s.queryAdministration(ctx, trust, statement, [][]byte{cursor}, adminSlotPageMaxBytes, 4, func(row [][]byte) error {
		var err error
		observed, page, err = verifyAdminSlotPage(row, trust, after)
		if err == nil && personal && page != nil {
			page.Kind = "my-slots"
			for _, slot := range page.Entries {
				if !slot.AllowSelfService {
					return ErrAdmissionResponse
				}
			}
		}
		return err
	})
	if err != nil {
		return observed, nil, err
	}
	return observed, page, nil
}

func verifyAdminSlotPage(row [][]byte, trust TrustState, after uuid.UUID) (TrustState, *AdminSlotPage, error) {
	if len(row) != 4 {
		return trust, nil, ErrAdmissionResponse
	}
	if string(row[0]) == "unavailable" && row[1] == nil && row[2] == nil && row[3] == nil {
		return trust, nil, nil
	}
	epoch, epochOK := treeNumber(row[1], 1, math.MaxInt64)
	sequence, sequenceOK := treeNumber(row[2], 0, math.MaxInt64)
	more := string(row[0]) == "more"
	if (!more && string(row[0]) != "ready") || !epochOK || !sequenceOK || len(row[3]) > adminSlotPageMaxBytes || !utf8.Valid(row[3]) {
		return trust, nil, ErrAdmissionResponse
	}
	decoder := json.NewDecoder(bytes.NewReader(row[3]))
	if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
		return trust, nil, ErrAdmissionResponse
	}
	admission := AdmissionRequest{WorkspaceID: trust.WorkspaceID, DeviceID: trust.DeviceID, UserID: trust.UserID}
	page := &AdminSlotPage{Kind: "slots", Entries: []AdminCredentialSlot{}}
	for decoder.More() {
		if len(page.Entries) == adminInventoryLimit {
			return trust, nil, ErrAdmissionResponse
		}
		item, err := snapshotRow(decoder, 24)
		if err != nil {
			return trust, nil, err
		}
		id, ok := treeID(item[1])
		if !ok || bytes.Compare(id[:], after[:]) <= 0 {
			return trust, nil, ErrAdmissionResponse
		}
		value, author, err := parseSelectionProjection([][][]byte{item}, admission, sharedcatalog.SelectionScope{Kind: "slot", Subject: id}, epoch, sequence)
		if err != nil {
			return trust, nil, err
		}
		next, err := trust.AdvanceSelection(*value, *author)
		if next.Revision != 0 {
			trust = next
		}
		if err != nil {
			return trust, nil, err
		}
		slot := value.Record.(sharedcatalog.SlotRecord)
		page.Entries = append(page.Entries, AdminCredentialSlot{ID: id, Name: slot.Name, Protocol: slot.Protocol, AllowSelfService: slot.AllowSelfService})
		after = id
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim(']') || decoder.Decode(new(any)) != io.EOF {
		return trust, nil, ErrAdmissionResponse
	}
	if more {
		if len(page.Entries) == 0 {
			return trust, nil, ErrAdmissionResponse
		}
		page.Next = &AdminInventoryCursor{ID: after}
	}
	return trust, page, nil
}
