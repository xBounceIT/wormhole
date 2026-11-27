package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

var (
	errSharedAdmissionCleanup   = errors.New("shared_workspace_cleanup_unconfirmed")
	errSharedRuntimeUnsupported = errors.New("shared_workspace_runtime_profile_not_available")
)

type sharedAdmissionSession interface {
	Open(context.Context, sharedpg.Settings, []byte, sharedpg.ChangePolicy) error
	AuthenticateSession(context.Context, sharedpg.AdmissionRequest, []byte) (*sharedpg.UnverifiedAdmission, error)
	TLSTrustBundle(context.Context) (*sharedpg.TLSTrustBundle, error)
	SubscribeChanges(context.Context) error
	NextChangeHint(context.Context) (string, error)
	AccountKeyState(context.Context) (*vault.UserKeyState, error)
	AccountUnlockMaterial(context.Context) (*sharedpg.UnverifiedAccountKeys, error)
	AccountEnrollmentMaterial(context.Context) (*sharedpg.UnverifiedAccountKeys, error)
	ChangePassword(context.Context, *sharedpg.PreparedPasswordChange, string) (*sharedpg.PasswordChangeReceipt, error)
	Close(context.Context) error
	Done() <-chan struct{}
}

type sharedAdmissionOptions struct {
	TrustPath         string
	Binding           sharedpg.TrustBinding
	MinimumRevision   uint64
	Request           sharedpg.AdmissionRequest
	Settings          sharedpg.Settings // authenticated enrollment metadata, never renderer supplied
	OSFloor           vault.Profile
	UserFloor         vault.Profile
	startupProtection *sharedStartupProtection // native initial selection, never serialized
}

// This owner separates transport admission from native account-key unlock. It
// does not grant tree/secret authorization or UI activation. Retain it and retry
// Close if cleanup is uncertain.
type sharedAdmissionController struct {
	lifetime          context.Context
	cancel            context.CancelFunc
	gate              chan struct{}
	session           sharedAdmissionSession
	root              *securemem.Buffer // protected by gate; retained on uncertain native release
	started           bool              // protected by gate
	admitted          atomic.Bool
	stopOwnerExit     func() bool // disarm the service-exit callback only for an acknowledged CA handoff
	memoryLockWarning atomic.Bool
	catalogDirty      atomic.Bool
	rotationPending   atomic.Bool
	rotationWake      chan struct{}
	rotationEpoch     int64 // fixed at verified administrator admission
	custodianMonitor  sync.Once
	rotationPin       vault.UserKeyTrust // set once under the gate from verified runtime trust
	catalogChanged    func()             // optional payload-free callback, configured before Open
	unlocked          atomic.Bool
	privateKeys       *securemem.Buffer    // encryption private key followed by signing seed; gate-owned
	vpnSSO            *sharedVPNSSOStorage // personal browser state; same admission/lifetime gate
	loginCommitment   [32]byte
	trustPath         string
	trustBinding      sharedpg.TrustBinding
	trustRevision     uint64
	runtimeOSFloor    vault.Profile
	runtimeUserFloor  vault.Profile
	runtimeKDF        vault.KDFPreset
	runtimeASK        bool
	runtimeProfile    vault.Profile
	runtimeTLS        sharedpg.TLSMode                                                                        // gate-owned; actual successfully opened transport
	tlsManaged        bool                                                                                    // gate-owned; transport was opened with a signed TLS bundle
	tlsTicks          func(time.Duration) (<-chan time.Time, func())                                          // native clock; configured before Open
	verifyEnrollment  sharedEnrollmentVerifier                                                                // native proof boundary; configured before use
	catalogAnchor     func(context.Context, string, []byte, sharedpg.TrustBinding, sharedpg.TrustState) error // native publication boundary; test seam
}

func newSharedAdmissionController() *sharedAdmissionController {
	return newSharedAdmissionControllerWithSession(sharedpg.NewSession())
}

func newSharedAdmissionControllerWithSession(session sharedAdmissionSession) *sharedAdmissionController {
	ctx, cancel := context.WithCancel(context.Background())
	c := &sharedAdmissionController{lifetime: ctx, cancel: cancel, gate: make(chan struct{}, 1), rotationWake: make(chan struct{}, 1), session: session, tlsTicks: newSharedTLSTicks, verifyEnrollment: nativeSharedEnrollmentVerifier}
	go func() {
		select {
		case <-session.Done():
			c.cancel()
			c.admitted.Store(false)
			_ = c.Close(context.Background())
		case <-ctx.Done():
		}
	}()
	return c
}

func (c *sharedAdmissionController) Admitted() bool {
	select {
	case <-c.session.Done():
		return false
	default:
	}
	return c.admitted.Load() && c.lifetime.Err() == nil
}

// MemoryLockWarning is safe status for the future shared-workspace UI. Default
// and Standard may continue with this warning; Hardened+ requires locked pages.
func (c *sharedAdmissionController) MemoryLockWarning() bool {
	return c.Admitted() && c.memoryLockWarning.Load()
}

func takeSharedAdmissionGate(ctx context.Context, gate chan struct{}) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-gate
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Open borrows both secrets for this call. It retains only a secure-memory copy
// of the trust root, never the derived PostgreSQL login material, and cannot be retried on
// this owner once an attempt begins. Enrollment/root derivation must have
// authenticated the binding.
func (c *sharedAdmissionController) Open(ctx context.Context, o sharedAdmissionOptions, root, loginMaterial []byte) (err error) {
	return c.openWithDerivation(ctx, o, root, loginMaterial, nil)
}

type sharedAccountDerivationFacts struct {
	preset  vault.KDFPreset
	askUsed bool
}

func (c *sharedAdmissionController) openWithDerivation(ctx context.Context, o sharedAdmissionOptions, root, loginMaterial []byte, facts *sharedAccountDerivationFacts) (err error) {
	return c.openWithDerivationSource(ctx, o, root, loginMaterial, facts, false)
}

func (c *sharedAdmissionController) openWithDerivationSource(ctx context.Context, o sharedAdmissionOptions, root, loginMaterial []byte, facts *sharedAccountDerivationFacts, fromSetup bool) (err error) {
	if ctx == nil || len(root) != 32 || len(loginMaterial) != 32 || !filepath.IsAbs(o.TrustPath) || o.MinimumRevision == 0 || o.Request.Validate() != nil ||
		o.Binding.WorkspaceID != o.Request.WorkspaceID || o.Binding.UserID != o.Request.UserID || o.Binding.DeviceID != o.Request.DeviceID {
		return sharedpg.ErrConfiguration
	}
	opCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	stop := context.AfterFunc(c.lifetime, cancel)
	defer stop()
	if err := takeSharedAdmissionGate(opCtx, c.gate); err != nil {
		return err
	}
	defer func() { <-c.gate }()
	if c.lifetime.Err() != nil {
		return sharedpg.ErrSessionClosed
	}
	if c.started {
		return sharedpg.ErrSessionStarted
	}
	c.started = true
	defer func() {
		if err != nil {
			c.cancel()
			c.admitted.Store(false)
			cleanupCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
			defer done()
			if c.closeLocked(cleanupCtx) != nil {
				err = errSharedAdmissionCleanup
			}
		}
	}()
	c.root, err = securemem.New(32, false)
	if err != nil {
		return err
	}
	if err = c.root.With(func(key []byte) error { copy(key, root); return nil }); err != nil {
		return err
	}
	var current sharedpg.TrustState
	err = c.root.With(func(key []byte) error {
		var e error
		current, e = readActiveSharedTrustFile(o.TrustPath, key, o.Binding, o.MinimumRevision)
		return e
	})
	if err != nil {
		return err
	}
	if fromSetup {
		o.Settings, err = readSharedTransportSetup(o, root, current)
		if err != nil {
			return err
		}
	}
	if err := loadSharedTLSCache(&o, current); err != nil {
		return err
	}
	if o.Settings.TLSBundle != nil {
		err = c.root.With(func(key []byte) error {
			var e error
			current, e = acceptSharedTLSBundle(o, key, current)
			return e
		})
		if err != nil {
			return err
		}
	}
	prepared, err := current.PrepareTransport(o.Settings, o.OSFloor, o.UserFloor, o.Request.API)
	if err != nil {
		return err
	}
	if err = sharedAdmissionRuntimeProfile(prepared.Profile); err != nil {
		return err
	}
	deviceChanges := func(trust sharedpg.TrustState, profile vault.Profile) (sharedpg.ChangePolicy, error) {
		policy, err := trust.Policy()
		if err != nil {
			return sharedpg.ChangePolicy{}, err
		}
		if facts != nil {
			if err := validateSharedAccountDerivation(policy, profile, facts.preset, facts.askUsed); err != nil {
				return sharedpg.ChangePolicy{}, err
			}
		}
		if devices := policy.DirectConnectionDevices; devices != nil {
			return sharedpg.ChangePolicy{ConcurrentDevices: *devices, TransactionPooler: *devices == 0}, nil
		}
		// Legacy profiles retain the transport metadata enrolled on this device.
		return o.Settings.Changes, nil
	}
	prepared.Changes, err = deviceChanges(current, prepared.Profile)
	if err != nil {
		return err
	}
	if err = opCtx.Err(); err != nil {
		return err
	}
	login, err := sharedpg.EncodeLoginSecret(loginMaterial)
	if err != nil {
		return err
	}
	defer vault.Wipe(login)
	if err = c.session.Open(opCtx, prepared, login, prepared.Changes); err != nil {
		return err
	}
	response, err := c.session.AuthenticateSession(opCtx, o.Request, loginMaterial)
	if err != nil {
		return err
	}
	next, err := current.Advance(response, o.Request)
	if err != nil {
		return err
	}
	c.memoryLockWarning.Store(!c.root.Locked() || response.MemoryLockWarning)
	if err = opCtx.Err(); err != nil {
		return err
	}
	// Persist a verified newer floor even if its stronger runtime policy cannot
	// currently be supported. Otherwise a subsequent login could accept rollback.
	err = c.root.With(func(key []byte) error {
		var e error
		if next.Revision == current.Revision {
			e = confirmSharedTrustFile(o.TrustPath, key, o.Binding, next)
		} else {
			e = writeSharedTrustFile(o.TrustPath, key, o.Binding, next, current.Revision)
		}
		if errors.Is(e, errSharedTrustCommitUncertain) {
			e = confirmSharedTrustFile(o.TrustPath, key, o.Binding, next)
		}
		return e
	})
	if err != nil {
		return err
	}
	updated, err := next.PrepareTransport(prepared, o.OSFloor, o.UserFloor, o.Request.API)
	if err != nil {
		return err
	}
	if err = sharedAdmissionRuntimeProfile(updated.Profile); err != nil {
		return err
	}
	if updated.Profile != prepared.Profile {
		// Reopen with the verified role settings and connection budget.
		return sharedpg.ErrProfileChanged
	}
	updated.Changes, err = deviceChanges(next, updated.Profile)
	if err != nil {
		return err
	}
	if updated.Changes.UseNotifications() != prepared.Changes.UseNotifications() {
		return sharedpg.ErrProfileChanged
	}
	if err = opCtx.Err(); err != nil {
		return err
	}
	if updated.Changes.UseNotifications() {
		if err = c.session.SubscribeChanges(opCtx); err != nil {
			return err
		}
	}
	if updated.TLSBundle != nil {
		if err = c.refreshTLSLocked(opCtx, o, next); err != nil {
			return err
		}
	}
	select {
	case <-c.session.Done():
		return sharedpg.ErrSessionClosed
	default:
	}
	c.admitted.Store(true)
	c.loginCommitment = sha256.Sum256(loginMaterial)
	c.trustPath = o.TrustPath
	c.trustBinding = o.Binding
	c.trustRevision = next.Revision
	c.runtimeProfile = updated.Profile
	c.runtimeOSFloor = o.OSFloor
	c.runtimeUserFloor = vault.EffectiveProfile(vault.Default, o.UserFloor, next.PersonalProfile())
	c.runtimeTLS = prepared.TLS
	c.tlsManaged = updated.TLSBundle != nil
	if response.IsAdmin && c.runtimeTLS == sharedpg.TLSVerified && c.tlsManaged {
		c.rotationEpoch = response.Epoch
	}
	c.rotationPending.Store(len(next.SuspensionRotations) != 0)
	go c.monitorWorkspaceAuthority(updated.Changes.UseNotifications())
	return nil
}

func sharedAdmissionRuntimeProfile(profile vault.Profile) error {
	switch profile {
	case vault.Default, vault.Standard:
		return nil
	default:
		return errSharedRuntimeUnsupported
	}
}

func (c *sharedAdmissionController) Close(ctx context.Context) error {
	if ctx == nil {
		return sharedpg.ErrConfiguration
	}
	c.admitted.Store(false)
	c.unlocked.Store(false)
	c.cancel()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := takeSharedAdmissionGate(ctx, c.gate); err != nil {
		return err
	}
	defer func() { <-c.gate }()
	return c.closeLocked(ctx)
}

func (c *sharedAdmissionController) closeLocked(ctx context.Context) error {
	failed := false
	c.unlocked.Store(false)
	clear(c.loginCommitment[:])
	if c.vpnSSO != nil {
		if c.vpnSSO.owner.Close() != nil {
			failed = true
		} else {
			c.vpnSSO = nil
		}
	}
	if c.privateKeys != nil {
		if c.privateKeys.Close() != nil {
			failed = true
		} else {
			c.privateKeys = nil
		}
	}
	if c.root != nil {
		if c.root.Close() != nil {
			failed = true
		} else {
			c.root = nil
		}
	}
	if c.session.Close(ctx) != nil {
		failed = true
	}
	if failed {
		return errSharedAdmissionCleanup
	}
	return ctx.Err()
}
