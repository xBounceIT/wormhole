package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type recoveryFixture struct {
	c                   *sharedAdmissionController
	probe               *sharedAdmissionProbe
	o                   sharedAdmissionOptions
	root                []byte
	pending             sharedpg.PendingEnrollment
	master              *sharedpg.AccountMaster
	account             *sharedpg.UnverifiedAccountKeys
	org                 ed25519.PrivateKey
	verified, confirmed int
}

func newRecoveryFixture(t *testing.T) *recoveryFixture {
	t.Helper()
	old, _, o, root, rawMaster, account, org := sharedEnrolledFixture(t)
	trust, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	at, err := trust.AccountTrust()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := vault.OpenEnrolledUserKeys(rawMaster, account.Binding, account.Envelope, *account.EnrollmentCertificate, *account.State, at, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Wipe()
	policy, err := trust.Policy()
	if err != nil {
		t.Fatal(err)
	}
	policy.Profile, policy.KDF, policy.LowKDFApproved = vault.Default, vault.KDFLow, true
	signed, err := vault.SignPolicy(policy, trust.SignerKeyID, trust.SignerKeyVersion, org)
	if err != nil {
		t.Fatal(err)
	}
	trust.SignedProfile, err = vault.EncodeSignedPolicy(signed)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(trust.SignedProfile)
	trust.PolicyDigest = digest[:]
	trust.FormatVersion, trust.Revision, trust.WrappingRevision, trust.Enrollment = 3, 1, 1, nil
	master, err := sharedpg.DeriveAccountMaster(context.Background(), sharedpg.AccountDerivation{WorkspaceID: o.Binding.WorkspaceID, LoginName: "alice", Preset: vault.KDFLow, EffectiveProfile: vault.Default}, policy, []byte("recovery-test-password"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := master.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	probe := &sharedAdmissionProbe{ctx: ctx, cancel: cancel, response: &sharedpg.UnverifiedAdmission{SessionID: uuid.New(), WorkspaceID: o.Binding.WorkspaceID, UserID: o.Binding.UserID, DeviceID: o.Binding.DeviceID, MinAPI: 1, MaxAPI: 1, Epoch: 1, SignedProfile: bytes.Clone(trust.SignedProfile)}}
	account.Binding.Revision, account.KDF = 1, vault.KDFLow
	err = master.Use(func(secret []byte, _ vault.KDFPreset, _ bool) error {
		var e error
		account.Envelope, e = vault.SealUserKeys(secret, account.Binding, keys)
		if e != nil {
			return e
		}
		probe.loginMaterial, e = vault.DeriveKey(secret, nil, vault.PurposeLogin)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vault.Wipe(probe.loginMaterial) })
	h := sha256.New()
	h.Write([]byte("wormhole/v1/pending-enrollment-capsule"))
	h.Write(account.Envelope.Nonce)
	h.Write(account.Envelope.Ciphertext)
	pending := sharedpg.PendingEnrollment{FormatVersion: 1, Trust: trust, Certificate: *account.EnrollmentCertificate, CapsuleDigest: h.Sum(nil), RoleTag: "testscope", KDF: vault.KDFLow}
	o.TrustPath = filepath.Join(t.TempDir(), "recover.trust")
	o.OSFloor, o.UserFloor = vault.Default, vault.Default
	o.Settings.DeviceRole = "wh_testscope_d_" + o.Binding.DeviceID.String()
	if err := stageSharedTransportSetup(o, root, pending.Trust); err != nil {
		t.Fatal(err)
	}
	if err := stageSharedPendingEnrollment(o.TrustPath, root, o.Binding, pending); err != nil {
		t.Fatal(err)
	}
	c := newSharedAdmissionControllerWithSession(probe)
	t.Cleanup(func() {
		probe.closeFailure.Store(false)
		if err := c.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	f := &recoveryFixture{c: c, probe: probe, o: o, root: root, pending: pending, master: master, account: account, org: org}
	probe.accountState = func(context.Context) (*vault.UserKeyState, error) { return account.State, nil }
	probe.enrollmentMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) { return account, nil }
	probe.accountMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) {
		t.Fatal("direct certificate fallback")
		return nil, nil
	}
	// This explicitly substitutes only the session-bound proof boundary. Native
	// VerifyPendingEnrollment/ConfirmVerifiedEnrollment have real PostgreSQL tests.
	c.verifyEnrollment = func(_ context.Context, _ sharedAdmissionSession, b sharedpg.TrustBinding, p sharedpg.PendingEnrollment, m *sharedpg.AccountMaster, a *sharedpg.UnverifiedAccountKeys) (sharedEnrollmentConfirmation, error) {
		f.verified++
		disk, e := readSharedPendingEnrollment(f.o.TrustPath, f.root, b)
		if e != nil || !reflect.DeepEqual(disk, p) {
			t.Fatal("proof preceded observation persistence", e)
		}
		trust, e := p.ObservedTrust().AccountTrust()
		if e != nil {
			return nil, e
		}
		e = m.Use(func(secret []byte, _ vault.KDFPreset, _ bool) error {
			opened, e := vault.OpenEnrolledUserKeys(secret, a.Binding, a.Envelope, *a.EnrollmentCertificate, *a.State, trust, 1)
			if e == nil {
				opened.Wipe()
			}
			return e
		})
		if e != nil {
			return nil, e
		}
		proof := enrollmentPublicationProof(t, b, p)
		return func(context.Context) (sharedConfirmedEnrollment, error) { f.confirmed++; return proof, nil }, nil
	}
	return f
}

func TestSharedEnrollmentRecoverySuccess(t *testing.T) {
	f := newRecoveryFixture(t)
	result, err := f.c.RecoverEnrollment(context.Background(), f.o, f.root, f.master)
	if err != nil || result == nil || !result.Confirmed || f.verified != 1 || f.confirmed != 1 {
		t.Fatal("recovery", result, err)
	}
	state, err := readActiveSharedTrustFile(f.o.TrustPath, f.root, f.o.Binding, result.TrustRevision)
	if err != nil || state.Enrollment == nil {
		t.Fatal("activation", err)
	}
	if _, err := os.Lstat(sharedPendingEnrollmentPath(f.o.TrustPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pending retained", err)
	}
	if f.c.Admitted() || f.c.Unlocked() || f.probe.closes.Load() == 0 {
		t.Fatal("recovery retained live authorization")
	}
	if _, err := f.c.RecoverEnrollment(context.Background(), f.o, f.root, f.master); err == nil {
		t.Fatal("reused owner")
	}
}

func TestSharedEnrollmentRecoveryObservations(t *testing.T) {
	for _, stage := range []string{"cached", "state", "material"} {
		for _, kind := range []string{"revoked", "reset"} {
			t.Run(stage+"/"+kind, func(t *testing.T) {
				f := newRecoveryFixture(t)
				state := *f.account.State
				state.Sequence++
				want := vault.ErrPolicy
				if kind == "revoked" {
					state.Active = false
				} else {
					state.Encryption.ID = uuid.New()
					want = sharedpg.ErrAccountRevision
				}
				state, err := vault.SignUserKeyState(state, f.org)
				if err != nil {
					t.Fatal(err)
				}
				switch stage {
				case "cached":
					next, e := f.pending.ObserveAccount(f.o.Binding, state, 1)
					if e != nil {
						t.Fatal(e)
					}
					if e = writeSharedPendingObservation(f.o.TrustPath, f.root, f.o.Binding, f.pending, next); e != nil {
						t.Fatal(e)
					}
				case "state":
					f.probe.accountState = func(context.Context) (*vault.UserKeyState, error) { return &state, nil }
				case "material":
					f.account.State = &state
					f.probe.accountState = func(context.Context) (*vault.UserKeyState, error) { return f.pending.Trust.Account, nil }
				}
				result, err := f.c.RecoverEnrollment(context.Background(), f.o, f.root, f.master)
				if !errors.Is(err, want) || result != nil || f.verified != 0 || f.confirmed != 0 {
					t.Fatal("unsafe recovery", result, err)
				}
				disk, e := readSharedPendingEnrollment(f.o.TrustPath, f.root, f.o.Binding)
				if e != nil || disk.ObservedTrust().Account.Sequence != state.Sequence {
					t.Fatal("observation lost", e)
				}
				if stage == "cached" && f.probe.opens.Load() != 0 {
					t.Fatal("contacted SQL after known denial")
				}
			})
		}
	}
}

func TestSharedEnrollmentRecoveryFailures(t *testing.T) {
	for _, mode := range []string{"nil-context", "root", "master", "workspace", "path", "minimum", "request", "role", "rollback", "missing", "closed-master", "open", "auth", "nil-admission", "state", "nil-state", "material", "nil-material", "nil-material-state", "verify", "nil-confirm", "confirm", "nil-proof", "wrong-proof", "publish", "cleanup", "closed", "started", "canceled", "profile-forged", "profile-write"} {
		t.Run(mode, func(t *testing.T) {
			f := newRecoveryFixture(t)
			ctx := context.Background()
			root := f.root
			master := f.master
			sentinel := errors.New("injected")
			syncDirectory := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = syncDirectory })
			switch mode {
			case "nil-context":
				ctx = nil
			case "root":
				root = nil
			case "master":
				master = nil
			case "workspace":
				f.o.Binding.WorkspaceID = uuid.New()
			case "path":
				f.o.TrustPath = "relative"
			case "minimum":
				f.o.MinimumRevision = 0
			case "request":
				f.o.Request.API = 0
			case "role":
				f.o.Settings.DeviceRole = "other"
			case "rollback":
				f.o.MinimumRevision = 99
			case "missing":
				if err := os.Remove(sharedPendingEnrollmentPath(f.o.TrustPath)); err != nil {
					t.Fatal(err)
				}
			case "closed-master":
				if err := master.Close(); err != nil {
					t.Fatal(err)
				}
			case "open":
				f.probe.open = func(context.Context, sharedpg.Settings) error { return sentinel }
			case "auth":
				f.probe.start = func(context.Context) error { return sentinel }
			case "nil-admission":
				f.probe.response = nil
			case "state":
				f.probe.accountState = func(context.Context) (*vault.UserKeyState, error) { return nil, sentinel }
			case "nil-state":
				f.probe.accountState = func(context.Context) (*vault.UserKeyState, error) { return nil, nil }
			case "material":
				f.probe.enrollmentMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) { return nil, sentinel }
			case "nil-material":
				f.probe.enrollmentMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) { return nil, nil }
			case "nil-material-state":
				f.probe.enrollmentMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) {
					a := *f.account
					a.State = nil
					return &a, nil
				}
			case "verify":
				f.c.verifyEnrollment = func(context.Context, sharedAdmissionSession, sharedpg.TrustBinding, sharedpg.PendingEnrollment, *sharedpg.AccountMaster, *sharedpg.UnverifiedAccountKeys) (sharedEnrollmentConfirmation, error) {
					return nil, sentinel
				}
			case "nil-confirm", "confirm", "nil-proof", "wrong-proof", "publish":
				original := f.c.verifyEnrollment
				f.c.verifyEnrollment = func(ctx context.Context, s sharedAdmissionSession, b sharedpg.TrustBinding, p sharedpg.PendingEnrollment, m *sharedpg.AccountMaster, a *sharedpg.UnverifiedAccountKeys) (sharedEnrollmentConfirmation, error) {
					next, err := original(ctx, s, b, p, m, a)
					if err != nil {
						return nil, err
					}
					if mode == "nil-confirm" {
						return nil, nil
					}
					return func(ctx context.Context) (sharedConfirmedEnrollment, error) {
						switch mode {
						case "confirm":
							return nil, sentinel
						case "nil-proof":
							return nil, nil
						case "wrong-proof":
							return confirmedEnrollmentProbe{}, nil
						case "publish":
							privateFileDirectorySync = func(string) error { return sentinel }
						}
						return next(ctx)
					}, nil
				}
			case "cleanup":
				f.probe.closeFailure.Store(true)
			case "closed":
				if err := f.c.Close(ctx); err != nil {
					t.Fatal(err)
				}
			case "started":
				f.c.started = true
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "profile-forged":
				f.probe.response.SignedProfile = []byte("{}")
			case "profile-write":
				privateFileDirectorySync = func(string) error { return sentinel }
			}
			result, err := f.c.RecoverEnrollment(ctx, f.o, root, master)
			if err == nil {
				t.Fatal("accepted failure", mode)
			}
			if mode == "publish" || mode == "cleanup" {
				if result == nil || !result.Confirmed {
					t.Fatal("lost confirmed remote outcome", err)
				}
			} else if result != nil {
				t.Fatal("invented confirmation", result)
			}
			if f.c.Admitted() || f.c.Unlocked() {
				t.Fatal("failure admitted")
			}
			if mode == "publish" {
				if _, e := readActiveSharedTrustFile(f.o.TrustPath, f.root, f.o.Binding, 1); e != errSharedEnrollmentPending {
					t.Fatal("uncertain publication activated", e)
				}
			}
		})
	}
}

func TestSharedEnrollmentRecoveryTLS(t *testing.T) {
	for _, mode := range []string{"stable", "changed", "read", "initial-write", "refresh-write", "cache-missing"} {
		t.Run(mode, func(t *testing.T) {
			f := newRecoveryFixture(t)
			sharedTLSFixture(t, &f.o, f.pending.Trust, f.org, 3)
			syncDirectory := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = syncDirectory })
			sentinel := errors.New("TLS fault")
			switch mode {
			case "changed":
				updated := f.o
				bundle := sharedTLSFixture(t, &updated, f.pending.Trust, f.org, 4)
				f.probe.tlsRead = func(context.Context) (*sharedpg.TLSTrustBundle, error) {
					raw, e := sharedpg.DecodeTLSTrustBundle(bundle.Encode())
					return &raw, e
				}
			case "read":
				f.probe.tlsRead = func(context.Context) (*sharedpg.TLSTrustBundle, error) { return nil, sentinel }
			case "initial-write":
				privateFileDirectorySync = func(string) error { return sentinel }
			case "refresh-write":
				f.probe.tlsRead = func(context.Context) (*sharedpg.TLSTrustBundle, error) {
					privateFileDirectorySync = func(string) error { return sentinel }
					raw, e := sharedpg.DecodeTLSTrustBundle(f.o.Settings.TLSBundle.Encode())
					return &raw, e
				}
			case "cache-missing":
				next, e := f.pending.ObserveTLS(f.o.Binding, f.o.Settings.TLSBundle)
				if e != nil {
					t.Fatal(e)
				}
				if e = writeSharedPendingObservation(f.o.TrustPath, f.root, f.o.Binding, f.pending, next); e != nil {
					t.Fatal(e)
				}
				f.o.Settings.TLSBundle = nil
			}
			result, err := f.c.RecoverEnrollment(context.Background(), f.o, f.root, f.master)
			if mode == "stable" {
				if err != nil || result == nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || result != nil || f.verified != 0 {
				t.Fatal("TLS failure admitted", err)
			}
			if mode == "changed" {
				disk, e := readSharedPendingEnrollment(f.o.TrustPath, f.root, f.o.Binding)
				if err != errSharedTLSChanged || e != nil || disk.ObservedTrust().TLSSequence != 4 {
					t.Fatal("rotation not durable", err, e)
				}
			}
		})
	}
}

func TestSharedEnrollmentRecoveryPersistenceAndPolicy(t *testing.T) {
	for _, mode := range []string{"one-sync-failure", "state-write", "material-write", "state-forged", "material-forged", "policy-upgrade", "initial-floor", "initial-kdf"} {
		t.Run(mode, func(t *testing.T) {
			f := newRecoveryFixture(t)
			syncDirectory := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = syncDirectory })
			fail := func(string) error { return os.ErrPermission }
			switch mode {
			case "one-sync-failure":
				calls := 0
				privateFileDirectorySync = func(path string) error {
					calls++
					if calls == 1 {
						return os.ErrPermission
					}
					return syncDirectory(path)
				}
			case "state-write":
				f.probe.accountState = func(context.Context) (*vault.UserKeyState, error) {
					privateFileDirectorySync = fail
					return f.account.State, nil
				}
			case "material-write":
				f.probe.enrollmentMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) {
					privateFileDirectorySync = fail
					return f.account, nil
				}
			case "state-forged":
				s := *f.account.State
				s.Signature = bytes.Repeat([]byte{0}, 64)
				f.probe.accountState = func(context.Context) (*vault.UserKeyState, error) { return &s, nil }
			case "material-forged":
				s := *f.account.State
				s.Signature = bytes.Repeat([]byte{0}, 64)
				f.probe.enrollmentMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) {
					a := *f.account
					a.State = &s
					return &a, nil
				}
			case "policy-upgrade":
				policy, e := f.pending.Trust.Policy()
				if e != nil {
					t.Fatal(e)
				}
				policy.Sequence++
				policy.KDF = vault.KDFV1
				signed, e := vault.SignPolicy(policy, f.pending.Trust.SignerKeyID, 1, f.org)
				if e != nil {
					t.Fatal(e)
				}
				f.probe.response.SignedProfile, e = vault.EncodeSignedPolicy(signed)
				if e != nil {
					t.Fatal(e)
				}
			case "initial-floor":
				f.o.OSFloor = vault.Standard
			case "initial-kdf":
				next := f.pending
				next.KDF = vault.KDFV1
				sealed, e := sharedpg.SealPendingEnrollment(f.root, f.o.Binding, next)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(sharedPendingEnrollmentPath(f.o.TrustPath), sealed, 0600); e != nil {
					t.Fatal(e)
				}
			}
			result, err := f.c.RecoverEnrollment(context.Background(), f.o, f.root, f.master)
			if mode == "one-sync-failure" {
				if err != nil || result == nil {
					t.Fatal("exact durability retry failed", err)
				}
				return
			}
			if err == nil || result != nil || f.verified != 0 {
				t.Fatal("unsafe continuation", err)
			}
			if mode == "policy-upgrade" {
				disk, e := readSharedPendingEnrollment(f.o.TrustPath, f.root, f.o.Binding)
				if e != nil || disk.ObservedTrust().PolicySequence != f.pending.Trust.PolicySequence+1 {
					t.Fatal("policy floor lost", e)
				}
			}
		})
	}
}

func TestSharedEnrollmentRecoveryCancellation(t *testing.T) {
	f := newRecoveryFixture(t)
	entered := make(chan struct{})
	f.probe.accountState = func(ctx context.Context) (*vault.UserKeyState, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	done := make(chan error, 1)
	go func() { _, err := f.c.RecoverEnrollment(context.Background(), f.o, f.root, f.master); done <- err }()
	<-entered
	if err := f.c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if f.verified != 0 {
		t.Fatal("confirmed canceled operation")
	}
	if _, err := readSharedPendingEnrollment(f.o.TrustPath, f.root, f.o.Binding); err != nil {
		t.Fatal("pending lost", err)
	}
}

func TestSharedNativeEnrollmentVerifierBoundary(t *testing.T) {
	f := newRecoveryFixture(t)
	if _, err := nativeSharedEnrollmentVerifier(context.Background(), f.probe, f.o.Binding, f.pending, f.master, f.account); err != sharedpg.ErrConfiguration {
		t.Fatal("mock accepted as native proof", err)
	}
	s := sharedpg.NewSession()
	defer s.Close(context.Background())
	if _, err := nativeSharedEnrollmentVerifier(context.Background(), s, f.o.Binding, f.pending, f.master, f.account); err != sharedpg.ErrSessionClosed {
		t.Fatal("unadmitted native proof", err)
	}
	if err := validateSharedEnrollmentState(sharedpg.PendingEnrollment{}); err != vault.ErrPolicy {
		t.Fatal(err)
	}
}

func TestSharedEnrollmentRecoveryConfirmationCancellation(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "after"}[after], func(t *testing.T) {
			f := newRecoveryFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			original := f.c.verifyEnrollment
			f.c.verifyEnrollment = func(ctx context.Context, s sharedAdmissionSession, b sharedpg.TrustBinding, p sharedpg.PendingEnrollment, m *sharedpg.AccountMaster, a *sharedpg.UnverifiedAccountKeys) (sharedEnrollmentConfirmation, error) {
				confirmation, err := original(ctx, s, b, p, m, a)
				if err != nil {
					return nil, err
				}
				if !after {
					cancel()
					return confirmation, nil
				}
				return func(ctx context.Context) (sharedConfirmedEnrollment, error) {
					result, err := confirmation(ctx)
					cancel()
					return result, err
				}, nil
			}
			result, err := f.c.RecoverEnrollment(ctx, f.o, f.root, f.master)
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if after {
				if result == nil || !result.Confirmed || f.confirmed != 1 {
					t.Fatal("confirmed outcome lost")
				}
			} else if result != nil || f.confirmed != 0 {
				t.Fatal("confirmed after cancellation")
			}
			if _, err := readSharedPendingEnrollment(f.o.TrustPath, f.root, f.o.Binding); err != nil {
				t.Fatal("pending removed", err)
			}
			if _, err := os.Lstat(f.o.TrustPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("published despite cancellation", err)
			}
		})
	}
}

func TestSharedEnrollmentRecoveryProtectedSetup(t *testing.T) {
	for _, mode := range []string{"success", "missing", "missing-journal", "corrupt", "nil-context", "relative", "canceled", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			f := newRecoveryFixture(t)
			ctx := context.Background()
			expected := f.o.Settings
			// A caller cannot redirect recovery, change the role, or disable TLS.
			f.o.Settings = sharedpg.Settings{Endpoints: []sharedpg.Endpoint{{Host: "attacker.example.test", Port: 5432}}, DeviceRole: "attacker", TLS: sharedpg.TLSOff}
			f.probe.open = func(_ context.Context, s sharedpg.Settings) error {
				if !reflect.DeepEqual(s.Endpoints, expected.Endpoints) || s.DeviceRole != expected.DeviceRole || s.TLS != expected.TLS {
					t.Fatal("used caller settings")
				}
				return nil
			}
			switch mode {
			case "missing-journal":
				if err := os.Remove(sharedPendingEnrollmentPath(f.o.TrustPath)); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(sharedTransportSetupPath(f.o.TrustPath)); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(sharedTransportSetupPath(f.o.TrustPath), []byte("broken"), 0600); err != nil {
					t.Fatal(err)
				}
			case "nil-context":
				ctx = nil
			case "relative":
				f.o.TrustPath = "relative"
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "revoked":
				state := *f.account.State
				state.Sequence++
				state.Active = false
				state, err := vault.SignUserKeyState(state, f.org)
				if err != nil {
					t.Fatal(err)
				}
				next, err := f.pending.ObserveAccount(f.o.Binding, state, 1)
				if err != nil {
					t.Fatal(err)
				}
				if err = writeSharedPendingObservation(f.o.TrustPath, f.root, f.o.Binding, f.pending, next); err != nil {
					t.Fatal(err)
				}
			}
			result, err := f.c.RecoverEnrollmentFromSetup(ctx, f.o, f.root, f.master)
			if mode == "success" {
				if err != nil || result == nil || !result.Confirmed {
					t.Fatal(err)
				}
				return
			}
			if err == nil || result != nil || f.probe.opens.Load() != 0 {
				t.Fatal("unsafe setup recovery", err)
			}
		})
	}
}

func TestSharedEnrollmentRecoveryRotatedSetup(t *testing.T) {
	for _, mode := range []string{"success", "missing-cache", "corrupt-cache"} {
		t.Run(mode, func(t *testing.T) {
			f := newRecoveryFixture(t)
			sharedTLSFixture(t, &f.o, f.pending.Trust, f.org, 3)
			old, err := f.pending.ObserveTLS(f.o.Binding, f.o.Settings.TLSBundle)
			if err != nil {
				t.Fatal(err)
			}
			// Build the historical protected setup and accepted floor as initial staging
			// would; later publications leave this original setup ciphertext unchanged.
			sealed, err := sharedpg.SealTransportSetup(f.root, f.o.Binding, f.o.Settings, old.ObservedTrust(), f.o.OSFloor, f.o.UserFloor, f.o.Request.API)
			if err != nil {
				t.Fatal(err)
			}
			if err := persistSharedTransitionBytes(sharedTransportSetupPath(f.o.TrustPath), sealed); err != nil {
				t.Fatal(err)
			}
			if err := publishSharedTLSCache(f.o.TrustPath, f.o.Settings.TLSBundle, nil, func() error { return writeSharedPendingObservation(f.o.TrustPath, f.root, f.o.Binding, f.pending, old) }); err != nil {
				t.Fatal(err)
			}
			updated := f.o
			latest := sharedTLSFixture(t, &updated, old.ObservedTrust(), f.org, 4)
			next, err := old.ObserveTLS(f.o.Binding, latest)
			if err != nil {
				t.Fatal(err)
			}
			if err := publishSharedTLSCache(f.o.TrustPath, latest, nil, func() error { return writeSharedPendingObservation(f.o.TrustPath, f.root, f.o.Binding, old, next) }); err != nil {
				t.Fatal(err)
			}
			path, err := sharedTLSCachePath(f.o.TrustPath, next.ObservedTrust().TLSDigest)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "missing-cache":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "corrupt-cache":
				if err := os.WriteFile(path, []byte("bad"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			f.probe.open = func(_ context.Context, s sharedpg.Settings) error {
				if s.TLSBundle == nil || s.TLSBundle.Pin().MinimumSequence != 4 {
					t.Fatal("connected with obsolete TLS")
				}
				return nil
			}
			f.probe.tlsRead = func(context.Context) (*sharedpg.TLSTrustBundle, error) {
				bundle, e := sharedpg.DecodeTLSTrustBundle(latest.Encode())
				return &bundle, e
			}
			f.o.Settings = sharedpg.Settings{}
			result, err := f.c.RecoverEnrollmentFromSetup(context.Background(), f.o, f.root, f.master)
			if mode == "success" {
				if err != nil || result == nil || !result.Confirmed {
					t.Fatal("rotation recovery", err)
				}
			} else if err == nil || result != nil || f.probe.opens.Load() != 0 {
				t.Fatal("connected without authenticated cache", err)
			}
			actual, e := os.ReadFile(sharedTransportSetupPath(f.o.TrustPath))
			if e != nil || !bytes.Equal(actual, sealed) {
				t.Fatal("modified immutable setup", e)
			}
		})
	}
}
