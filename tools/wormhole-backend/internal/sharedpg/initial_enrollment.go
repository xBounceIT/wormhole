package sharedpg

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// PreparedInitialEnrollment owns all native preparation material. It never
// commits SQL or persists enrollment. Serialize Borrow/Close; a callback must
// not retain or close borrowed owners. Always Close a nonnil result, even when
// preparation returns an error because native cleanup could not be confirmed.
type PreparedInitialEnrollment struct {
	master     *AccountMaster
	root       *DeviceTrustRoot
	commit     *PreparedInvitationCommit
	storage    accountMasterMemory
	deviceFile []byte
	closed     bool
}

func (p *PreparedInitialEnrollment) Borrow(use func(*AccountMaster, *DeviceTrustRoot, *PreparedInvitationCommit) error) error {
	if p == nil || p.closed || use == nil || p.master == nil || p.root == nil || p.commit == nil {
		return ErrConfiguration
	}
	return use(p.master, p.root, p.commit)
}

func (p *PreparedInitialEnrollment) Close() error {
	if p == nil {
		return nil
	}
	p.closed = true
	p.commit.Wipe()
	p.commit = nil
	p.deviceFile = nil
	var err error
	if p.storage != nil {
		if e := p.storage.Close(); e != nil {
			err = errors.Join(err, ErrDeviceStorageCleanup)
		} else {
			p.storage = nil
		}
	}
	if p.root != nil {
		if e := p.root.Close(); e != nil {
			err = errors.Join(err, ErrDeviceTrustRootCleanup)
		} else {
			p.root = nil
		}
	}
	if p.master != nil {
		if e := p.master.Close(); e != nil {
			err = errors.Join(err, ErrAccountMasterCleanup)
		} else {
			p.master = nil
		}
	}
	return err
}

// PrepareInitialEnrollment runs on an already opened invitation session. Code,
// password and ASK are borrowed native inputs and must be wiped by their owner.
// The authenticated bootstrap/certification select derivation policy; caller
// settings cannot replace that policy. Native enrollment chooses fresh device
// and root-key identities. The returned binding must be persisted independently
// before dispatch through the initial-join coordinator.
func (s *Session) PrepareInitialEnrollment(ctx context.Context, i Invitation, code, password, ask []byte, name string, osFloor, userFloor vault.Profile) (*PreparedInitialEnrollment, error) {
	return prepareInitialEnrollment(ctx, i, code, password, ask, name, osFloor, userFloor, s.InvitationBootstrap, s.InvitationCertification, s.prepareInvitationCopies)
}

type initialBootstrapFetch func(context.Context, Invitation) (*UnverifiedInvitationBootstrap, error)
type initialCertificationFetch func(context.Context, Invitation, vault.InviteManifest) (*UnverifiedInvitationCertification, error)
type initialCopiesPrepare func(context.Context, Invitation, *UnverifiedInvitationBootstrap, *vault.InviteBootstrap, uint64) (*vault.InviteRewrapPlan, error)

func prepareInitialEnrollment(ctx context.Context, i Invitation, code, password, ask []byte, name string, osFloor, userFloor vault.Profile, fetch initialBootstrapFetch, certify initialCertificationFetch, copies initialCopiesPrepare) (result *PreparedInitialEnrollment, err error) {
	if ctx == nil || len(code) != vault.InviteCodeBytes || len(password) == 0 || len(password) > 1024 || (len(ask) != 0 && len(ask) != 32) || len(name) == 0 || len(name) > 4096 || !utf8.ValidString(name) || strings.ContainsRune(name, 0) {
		return nil, ErrConfiguration
	}
	if _, err := i.EnrollmentRole(time.Now()); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	bootstrap, err := fetch(ctx, i)
	if err != nil {
		return nil, err
	}
	opened, err := bootstrap.Authenticate(i, code, 1, time.Now())
	if err != nil {
		return nil, err
	}
	defer opened.Wipe()
	certification, err := certify(ctx, i, bootstrap.Manifest)
	if err != nil {
		return nil, err
	}
	policy, _, err := certification.Verify(i, opened.OrganisationPublic, bootstrap.Manifest, 1, 1, 1, time.Now())
	if err != nil {
		return nil, err
	}
	profile := vault.EffectiveProfile(osFloor, policy.Profile, userFloor)
	// Shared application runtime currently supports these two profiles only.
	// Do not allocate account keys for a join that the runtime cannot activate.
	if profile != vault.Default && profile != vault.Standard {
		return nil, vault.ErrPolicy
	}
	preset := policy.KDF
	if preset == vault.KDFLow && profile != vault.Default {
		preset = vault.KDFV1
	}
	d := AccountDerivation{WorkspaceID: i.WorkspaceID, LoginName: i.LoginName, Preset: preset, ASKRequired: policy.ASKRequired || len(ask) != 0, EffectiveProfile: profile}
	result = &PreparedInitialEnrollment{}
	defer func() {
		if err != nil {
			if cleanup := result.Close(); cleanup != nil {
				err = errors.Join(err, cleanup)
			} else {
				result = nil
			}
		}
	}()
	result.master, err = DeriveAccountMaster(ctx, d, policy, password, ask)
	if err != nil {
		return result, err
	}
	plan, err := copies(ctx, i, bootstrap, opened, 1)
	if err != nil {
		return result, err
	}
	defer plan.Wipe()
	b := TrustBinding{WorkspaceID: i.WorkspaceID, UserID: i.Enrollment.Context.UserID, DeviceID: uuid.New(), KeyID: uuid.New(), KeyVersion: 1}
	result.root, err = result.master.DeriveTrustRoot(ctx, b)
	if err != nil {
		return result, err
	}
	result.commit, err = PrepareInvitationCommit(i, certification, opened.OrganisationPublic, bootstrap.Manifest, plan, result.master, b.DeviceID, name, time.Now())
	if err != nil {
		return result, err
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if err = result.prepareDeviceStorage(ctx, password, ask, allocateDeviceStorage); err != nil {
		return result, err
	}
	return result, nil
}
