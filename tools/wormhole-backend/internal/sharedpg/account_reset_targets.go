package sharedpg

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const accountResetTargetsLimit = 50
const accountResetTargetsAvailableSQL = `SELECT
	(pg_catalog.to_regprocedure('wormhole_api_v1.account_reset_targets(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,integer)') IS NOT NULL
	  AND pg_catalog.to_regprocedure('wormhole_api_v1.mark_account_reset_handover(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,uuid)') IS NOT NULL)::text`
const accountResetTargetsSQL = `SELECT user_id::text,login_name,eligible::text,offer_id::text,status,expires_at::text
	FROM wormhole_api_v1.account_reset_targets(` + serverCAArguments + `,$10::uuid,$11::integer)`
const markAccountResetHandoverSQL = `SELECT wormhole_api_v1.mark_account_reset_handover(` + serverCAArguments + `,$10::uuid,$11::uuid)`

type AccountResetTarget struct {
	UserID    uuid.UUID  `json:"userId"`
	LoginName string     `json:"loginName"`
	Eligible  bool       `json:"eligible"`
	OfferID   *uuid.UUID `json:"offerId,omitempty"`
	Status    string     `json:"status"`
	ExpiresAt uint64     `json:"expiresAt,omitempty"`
}

type AccountResetTargets struct {
	Targets []AccountResetTarget `json:"targets"`
	Next    *uuid.UUID           `json:"next,omitempty"`
}

func (s *Session) AccountResetTargetsSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, accountResetTargetsAvailableSQL)
}

// ReadAccountResetTargets returns metadata only. Eligibility is a server hint
// for the queue; the issuing path verifies the actual signed recovery material.
func (s *Session) ReadAccountResetTargets(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, after uuid.UUID) (AccountResetTargets, error) {
	if ctx == nil {
		return AccountResetTargets{}, ErrConfiguration
	}
	if _, err := authenticatedServerCAContext(trust, tls); err != nil {
		return AccountResetTargets{}, err
	}
	var cursor []byte
	if after != uuid.Nil {
		cursor = []byte(after.String())
	}
	var page AccountResetTargets
	err := s.queryServerCA(ctx, trust, accountResetTargetsSQL, [][]byte{
		cursor, strconv.AppendInt(nil, accountResetTargetsLimit+1, 10),
	}, 24*1024, accountResetTargetsLimit+1, 6, func(rows [][][]byte) error {
		var err error
		page, err = parseAccountResetTargets(rows, trust.WorkspaceID, after)
		return err
	})
	return page, err
}

func parseAccountResetTargets(rows [][][]byte, workspace, after uuid.UUID) (AccountResetTargets, error) {
	if len(rows) > accountResetTargetsLimit+1 {
		return AccountResetTargets{}, ErrAdmissionResponse
	}
	result := AccountResetTargets{Targets: make([]AccountResetTarget, 0, min(len(rows), accountResetTargetsLimit))}
	for _, row := range rows {
		if len(row) != 6 {
			return AccountResetTargets{}, ErrAdmissionResponse
		}
		user, ok := treeID(row[0])
		if !ok || bytes.Compare(user[:], after[:]) <= 0 {
			return AccountResetTargets{}, ErrAdmissionResponse
		}
		after = user
		login := string(row[1])
		if _, err := vault.SharedSalt(workspace.String(), login); err != nil || strings.IndexFunc(login, unicode.IsControl) >= 0 {
			return AccountResetTargets{}, ErrAdmissionResponse
		}
		target := AccountResetTarget{UserID: user, LoginName: login, Status: string(row[4])}
		switch string(row[2]) {
		case "true":
			target.Eligible = true
		case "false":
		default:
			return AccountResetTargets{}, ErrAdmissionResponse
		}
		switch target.Status {
		case "not-issued":
			if row[3] != nil || row[5] != nil {
				return AccountResetTargets{}, ErrAdmissionResponse
			}
		case "awaiting-handover", "handed-over", "expired", "inactive", "redeemed":
			offer, offerOK := treeID(row[3])
			expiry, expiryOK := treeNumber(row[5], 1, 253402300799)
			if !offerOK || !expiryOK {
				return AccountResetTargets{}, ErrAdmissionResponse
			}
			target.OfferID, target.ExpiresAt = &offer, expiry
		default:
			return AccountResetTargets{}, ErrAdmissionResponse
		}
		if len(result.Targets) == accountResetTargetsLimit {
			result.Next = &result.Targets[accountResetTargetsLimit-1].UserID
		} else {
			result.Targets = append(result.Targets, target)
		}
	}
	return result, nil
}

func (s *Session) MarkAccountResetHandover(ctx context.Context, trust TrustState, tls *VerifiedTLSBundle, user, offer uuid.UUID) (string, error) {
	if ctx == nil || user == uuid.Nil || offer == uuid.Nil {
		return "", ErrConfiguration
	}
	if _, err := authenticatedServerCAContext(trust, tls); err != nil {
		return "", err
	}
	var status string
	err := s.queryServerCA(ctx, trust, markAccountResetHandoverSQL, [][]byte{[]byte(user.String()), []byte(offer.String())}, 16, 1, 1,
		func(rows [][][]byte) error {
			if len(rows) != 1 || len(rows[0]) != 1 {
				return ErrAdmissionResponse
			}
			switch string(rows[0][0]) {
			case "handed-over", "redeemed":
				status = string(rows[0][0])
				return nil
			default:
				return ErrAdmissionResponse
			}
		})
	return status, err
}
