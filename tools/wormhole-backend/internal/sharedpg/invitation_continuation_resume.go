package sharedpg

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type invitationContinuationOpen func(context.Context, Settings, []byte, ChangePolicy) error
type invitationContinuationObserve func(PendingEnrollment) error

// Native-only inputs. Observed comes from authenticated durable staging and
// Request uses the actual application version; neither is renderer authority.
type InvitationContinuationOptions struct {
	Request           AdmissionRequest   `json:"-"`
	Observed          PendingEnrollment  `json:"-"`
	OSFloor           vault.Profile      `json:"-"`
	UserFloor         vault.Profile      `json:"-"`
	AcknowledgeTLSOff bool               `json:"-"`
	TLSBundle         *VerifiedTLSBundle `json:"-"`
}

// ResumeInvitationContinuation consumes the local continuation, even on failure.
// It opens a fresh temporary enrollment connection with the separately delivered
// code and checks the current bootstrap, manifest, certificates and policy.
// Observations MUST be durably saved by observe before they can be acted upon.
// The returned request still needs confirmed local staging before one submission;
// this method never commits SQL, establishes active trust or publishes admission.
// Always Close this Session and retain the independent encrypted checkpoint.
func (s *Session) ResumeInvitationContinuation(ctx context.Context, c *InvitationContinuation, code []byte, o InvitationContinuationOptions, observe func(PendingEnrollment) error) (*PreparedInvitationCommit, error) {
	if s == nil {
		c.Wipe()
		return nil, ErrConfiguration
	}
	return resumeInvitationContinuation(ctx, c, code, o, observe, s.Open, s.InvitationBootstrap, s.InvitationCertification)
}

func resumeInvitationContinuation(ctx context.Context, c *InvitationContinuation, code []byte, o InvitationContinuationOptions, observe invitationContinuationObserve, open invitationContinuationOpen, fetch initialBootstrapFetch, certify initialCertificationFetch) (result *PreparedInvitationCommit, err error) {
	defer c.Wipe()
	if ctx == nil || c == nil || len(code) != vault.InviteCodeBytes || o.Request.API != 1 || o.Request.Validate() != nil || observe == nil || open == nil || fetch == nil || certify == nil {
		return nil, ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	i, err := c.validate()
	if err != nil {
		return nil, err
	}
	if o.Request.WorkspaceID != c.binding.WorkspaceID || o.Request.UserID != c.binding.UserID || o.Request.DeviceID != c.binding.DeviceID {
		return nil, ErrConfiguration
	}
	observed := o.Observed
	if err := c.record.Pending.ValidateObservationSnapshot(c.binding, observed); err != nil {
		return nil, err
	}
	profile, err := continuationPolicy(c.master, observed, o.OSFloor, o.UserFloor)
	if err != nil {
		return nil, err
	}
	// Include the authenticated workspace floor BEFORE any fresh SCRAM proof.
	settings, login, err := continuationInvitationLogin(i, code, o, profile)
	if err != nil {
		return nil, err
	}
	err = open(ctx, settings, login, ChangePolicy{TransactionPooler: true})
	vault.Wipe(login)
	if err != nil {
		return nil, err
	}
	bootstrap, err := fetch(ctx, i)
	if err != nil {
		return nil, err
	}
	opened, err := bootstrap.Authenticate(i, code, c.record.Pending.Certificate.Manifest.Revision, time.Now())
	if err != nil {
		return nil, err
	}
	defer opened.Wipe()
	if !bytes.Equal(opened.OrganisationPublic, observed.Trust.PublicKey) || !reflect.DeepEqual(bootstrap.Manifest, c.record.Pending.Certificate.Manifest) {
		return nil, ErrTrustState
	}
	certification, err := certify(ctx, i, bootstrap.Manifest)
	if err != nil {
		return nil, err
	}
	if certification == nil {
		return nil, ErrAdmissionResponse
	}
	next, err := observed.ObservePolicy(c.binding, certification.SignedProfile)
	if err != nil {
		return nil, err
	}
	if err := observe(next); err != nil {
		return nil, err
	}
	observed = next
	next, err = observed.ObserveAccount(c.binding, certification.State, observed.ObservedTrust().WrappingRevision)
	if err != nil {
		return nil, err
	}
	if err := observe(next); err != nil {
		return nil, err
	}
	observed = next
	trust := observed.ObservedTrust()
	if _, _, err := certification.Verify(i, opened.OrganisationPublic, bootstrap.Manifest, trust.Account.Sequence, trust.PolicySequence, bootstrap.Manifest.Revision, time.Now()); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(certification.Encryption, c.record.Pending.Certificate.BootstrapEncryption) || !reflect.DeepEqual(certification.Signing, c.record.Pending.Certificate.BootstrapSigning) {
		return nil, ErrTrustState
	}
	if _, err := continuationPolicy(c.master, observed, o.OSFloor, o.UserFloor); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Recreate the device verifier from the freshly unlocked master. Nothing
	// sufficient for either enrollment or device login was saved in the record.
	var verifier []byte
	err = c.master.Use(func(secret []byte, _ vault.KDFPreset, _ bool) error {
		login, err := vault.DeriveKey(secret, nil, vault.PurposeLogin)
		if err != nil {
			return err
		}
		defer vault.Wipe(login)
		verifier, err = NewSCRAMVerifier(login)
		return err
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			vault.Wipe(verifier)
		}
	}()
	params, err := c.parameters(verifier)
	if err != nil {
		return nil, err
	}
	pending, err := json.Marshal(observed)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		vault.Wipe(pending)
		return nil, err
	}
	return &PreparedInvitationCommit{master: c.master, params: params, pending: pending, device: c.binding.DeviceID, role: "wh_" + observed.RoleTag + "_d_" + c.binding.DeviceID.String(), expires: i.ExpiresAt}, nil
}

func continuationInvitationLogin(i Invitation, code []byte, o InvitationContinuationOptions, profile vault.Profile) (Settings, []byte, error) {
	trust := o.Observed.ObservedTrust()
	if trust.TLSSequence != 0 && (o.TLSBundle == nil || i.TLS != TLSVerified) {
		return Settings{}, nil, ErrTrustRollback
	}
	if trust.TLSSequence == 0 && o.TLSBundle != nil {
		return Settings{}, nil, ErrTrustState
	}
	settings, login, err := initialInvitationLogin(i, code, o.OSFloor, profile, o.AcknowledgeTLSOff)
	if err != nil {
		return Settings{}, nil, err
	}
	if o.TLSBundle != nil {
		// Managed roots and revocations come exclusively from the current signed
		// bundle. Never reuse or append the original invitation's historical CA.
		settings.CAPEM, settings.TLSBundle = nil, o.TLSBundle
	}
	settings, err = trust.PrepareTransport(settings, o.OSFloor, profile, o.Request.API)
	if err != nil {
		vault.Wipe(login)
		return Settings{}, nil, err
	}
	return settings, login, nil
}

func continuationPolicy(master *AccountMaster, p PendingEnrollment, osFloor, userFloor vault.Profile) (vault.Profile, error) {
	trust := p.ObservedTrust()
	if trust.Account == nil || !trust.Account.Active {
		return "", vault.ErrPolicy
	}
	policy, err := trust.Policy()
	if err != nil {
		return "", err
	}
	if policy.MinAPI > 1 || policy.MaxAPI < 1 {
		return "", ErrAPIVersion
	}
	profile := vault.EffectiveProfile(osFloor, policy.Profile, userFloor)
	if profile != vault.Default && profile != vault.Standard {
		return "", vault.ErrPolicy
	}
	err = master.Use(func(_ []byte, preset vault.KDFPreset, ask bool) error {
		if preset != p.KDF || ask != p.ASKRequired {
			return ErrAccountRevision
		}
		actual := policy
		actual.Profile, actual.KDF, actual.ASKRequired = profile, preset, ask
		if err := actual.Validate(); err != nil {
			return err
		}
		floor, _ := vault.Parameters(policy.KDF)
		selected, err := vault.Parameters(preset)
		if err != nil || selected.MemoryKiB < floor.MemoryKiB || selected.Iterations < floor.Iterations || (policy.ASKRequired && !ask) {
			return vault.ErrPolicy
		}
		return nil
	})
	return profile, err
}
