package sharedpg

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

var ErrAccountResetSave = errors.New("account reset offer could not be saved")
var ErrAccountResetRecipient = errors.New("invalid account reset display recipient")

const accountResetSupportedSQL = `SELECT
	(pg_catalog.to_regprocedure('wormhole_api_v1.redeem_account_reset(uuid,bytea,bytea,uuid,text,text,text,bytea,bytea)') IS NOT NULL)::text`

// AccountResetSupported checks whether a reset can be redeemed on the current
// schema. Actual issuance still requires the authenticated custodian APIs.
func (s *Session) AccountResetSupported(ctx context.Context) (bool, error) {
	return s.serverCapability(ctx, accountResetSupportedSQL)
}

func (s *Session) serverCapability(ctx context.Context, statement string) (bool, error) {
	rows, err := s.Query(ctx, statement, nil)
	if err != nil {
		return false, err
	}
	if len(rows) != 1 || len(rows[0]) != 1 {
		return false, ErrAdmissionResponse
	}
	switch string(rows[0][0]) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, ErrAdmissionResponse
	}
}

type AccountResetHandover struct {
	WorkspaceID uuid.UUID          `json:"workspaceId"`
	RequestID   uuid.UUID          `json:"requestId"`
	OfferID     uuid.UUID          `json:"offerId"`
	Bundle      vault.SealedBundle `json:"bundle"`
}

// PublishAccountResetHandover saves the signed public offer before enabling
// its temporary login. The display bundle can leave Go only once the database
// confirms publication.
func (s *Session) PublishAccountResetHandover(ctx context.Context, trust TrustState, p *PreparedAccountReset, recipient []byte, request uuid.UUID, save func([]byte) error) (AccountResetHandover, error) {
	return p.publishHandover(ctx, recipient, request, save, func(stage func() error) error {
		return s.publishAccountReset(ctx, trust, p, stage)
	})
}

func (p *PreparedAccountReset) publishHandover(ctx context.Context, recipient []byte, request uuid.UUID, save func([]byte) error, publish func(func() error) error) (AccountResetHandover, error) {
	if ctx == nil || p == nil || p.factors == nil || p.published || p.delivered || save == nil || request == uuid.Nil ||
		p.offer.ExpiresAt <= time.Now().Unix() {
		return AccountResetHandover{}, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return AccountResetHandover{}, err
	}
	var bundle vault.SealedBundle
	err := p.factors.With(func(factors []byte) error {
		var err error
		bundle, err = vault.SealAccountResetDisplay(recipient, p.offer.WorkspaceID, request, p.offer.Subject.LoginName, factors)
		return err
	})
	if err != nil {
		return AccountResetHandover{}, errors.Join(ErrAccountResetRecipient, err)
	}
	staged := false
	if err := publish(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := save(bytes.Clone(p.document)); err != nil {
			return ErrAccountResetSave
		}
		staged = true
		return ctx.Err()
	}); err != nil {
		return AccountResetHandover{}, err
	}
	if !staged || !p.published {
		return AccountResetHandover{}, ErrAdmissionResponse
	}
	if err := ctx.Err(); err != nil {
		return AccountResetHandover{}, err
	}
	p.delivered = true
	return AccountResetHandover{WorkspaceID: p.offer.WorkspaceID, RequestID: request, OfferID: p.offer.ID, Bundle: bundle}, nil
}
