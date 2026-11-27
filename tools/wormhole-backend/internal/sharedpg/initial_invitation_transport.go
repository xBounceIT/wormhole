package sharedpg

import (
	"context"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// OpenInitialInvitation applies native OS/user floors before the first SCRAM
// connection. The authenticated workspace policy is checked during preparation;
// an unverified invitation cannot relax a local floor. Only the protected input
// flow may acknowledge the TLS-Off warning. Always Close this Session, including
// after an error. The borrowed code is never retained or sent to PostgreSQL.
func (s *Session) OpenInitialInvitation(ctx context.Context, i Invitation, code []byte, osFloor, userFloor vault.Profile, acknowledgeTLSOff bool) error {
	if s == nil || ctx == nil {
		return ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	settings, login, err := initialInvitationLogin(i, code, osFloor, userFloor, acknowledgeTLSOff)
	if err != nil {
		return err
	}
	defer vault.Wipe(login)
	return s.Open(ctx, settings, login, ChangePolicy{TransactionPooler: true})
}

func initialInvitationLogin(i Invitation, code []byte, osFloor, userFloor vault.Profile, acknowledgeTLSOff bool) (Settings, []byte, error) {
	profile := vault.EffectiveProfile(osFloor, vault.Default, userFloor)
	// Do not send any login proof for a profile the shared application cannot
	// activate yet. Unknown floors resolve to Paranoid and therefore also deny.
	if (profile != vault.Default && profile != vault.Standard) || (i.TLS == TLSOff && !acknowledgeTLSOff) {
		return Settings{}, nil, vault.ErrPolicy
	}
	settings, login, err := i.EnrollmentLogin(code, time.Now())
	if err != nil {
		return Settings{}, nil, err
	}
	settings.Profile = profile
	base, err := invitationTransportSettings(settings)
	if err == nil {
		_, err = validateTransportSettings(base)
	}
	if err != nil {
		vault.Wipe(login)
		return Settings{}, nil, err
	}
	return settings, login, nil
}
