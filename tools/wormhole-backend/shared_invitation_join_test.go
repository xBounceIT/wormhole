package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type invitationJoinProbe struct {
	commit        func(context.Context, *sharedpg.PreparedInvitationCommit) error
	calls, closes int
	closeFailure  bool
}

func (p *invitationJoinProbe) CommitInvitation(ctx context.Context, request *sharedpg.PreparedInvitationCommit) error {
	p.calls++
	return p.commit(ctx, request)
}
func (p *invitationJoinProbe) Close(context.Context) error {
	p.closes++
	if p.closeFailure {
		return sharedpg.ErrSessionCleanup
	}
	return nil
}

type joinRecoveryProbe struct {
	run          func(context.Context, sharedAdmissionOptions, []byte, *sharedpg.AccountMaster) (*sharedEnrollmentRecoveryResult, error)
	closeFailure bool
}

func (p *joinRecoveryProbe) RecoverEnrollmentFromSetup(ctx context.Context, o sharedAdmissionOptions, root []byte, master *sharedpg.AccountMaster) (*sharedEnrollmentRecoveryResult, error) {
	return p.run(ctx, o, root, master)
}
func (p *joinRecoveryProbe) Close(context.Context) error {
	if p.closeFailure {
		return sharedpg.ErrSessionCleanup
	}
	return nil
}

func preparedJoinFixture(t *testing.T) (*recoveryFixture, *sharedpg.PreparedInvitationCommit) {
	t.Helper()
	f := newRecoveryFixture(t)
	accountTrust, err := f.pending.Trust.AccountTrust()
	if err != nil {
		t.Fatal(err)
	}
	var keys *vault.UserKeys
	err = f.master.Use(func(secret []byte, _ vault.KDFPreset, _ bool) error {
		var e error
		keys, e = vault.OpenEnrolledUserKeys(secret, f.account.Binding, f.account.Envelope, f.pending.Certificate, *f.account.State, accountTrust, 1)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Wipe()
	certificate := f.pending.Certificate
	manifestRaw, err := vault.EncodeInviteManifest(certificate.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(manifestRaw)
	fingerprint := sha256.Sum256(f.org.Public().(ed25519.PublicKey))
	invitation := sharedpg.Invitation{FormatVersion: 2, WorkspaceID: f.o.Binding.WorkspaceID, LoginName: "alice", Endpoints: f.o.Settings.Endpoints, Database: f.o.Settings.Database, TLS: f.o.Settings.TLS, CAPEM: f.o.Settings.CAPEM, OrganisationFingerprint: fingerprint[:], ExpiresAt: certificate.Manifest.ExpiresAt, Enrollment: &sharedpg.InvitationEnrollment{RoleTag: f.pending.RoleTag, Context: certificate.Manifest.Context}}
	certification := &sharedpg.UnverifiedInvitationCertification{State: *f.account.State, Encryption: certificate.BootstrapEncryption, Signing: certificate.BootstrapSigning, SignedProfile: f.pending.Trust.SignedProfile}
	plan := &vault.InviteRewrapPlan{Keys: keys, Proof: certificate.Rekey, SourceManifestRevision: certificate.Manifest.Revision, SourceManifestDigest: digest[:], Copies: []vault.RewrappedKeyCopy{}}
	prepared, err := sharedpg.PrepareInvitationCommit(invitation, certification, f.org.Public().(ed25519.PublicKey), certificate.Manifest, plan, f.master, f.o.Binding.DeviceID, "test device", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(prepared.Wipe)
	f.o.TrustPath = filepath.Join(t.TempDir(), "nested", "device.trust")
	return f, prepared
}

func TestSharedInvitationJoinEndToEndCoordinator(t *testing.T) {
	for _, mode := range []string{"receipt", "uncertain", "managed-tls"} {
		t.Run(mode, func(t *testing.T) {
			f, request := preparedJoinFixture(t)
			if mode == "managed-tls" {
				sharedTLSFixture(t, &f.o, f.pending.Trust, f.org, 3)
				f.probe.tlsRead = func(context.Context) (*sharedpg.TLSTrustBundle, error) {
					raw, e := sharedpg.DecodeTLSTrustBundle(f.o.Settings.TLSBundle.Encode())
					return &raw, e
				}
			}
			source := &invitationJoinProbe{}
			source.commit = func(ctx context.Context, p *sharedpg.PreparedInvitationCommit) error {
				if ctx.Err() != nil || p.ValidateAccountMaster(f.master) != nil {
					t.Fatal("invalid dispatch ownership")
				}
				pending, e := readSharedPendingEnrollment(f.o.TrustPath, f.root, f.o.Binding)
				if e != nil {
					t.Fatal("SQL before durable intent", e)
				}
				expected, e := p.PendingEnrollment(f.o.Binding)
				if e != nil {
					t.Fatal(e)
				}
				pending.Observed = nil
				if !reflect.DeepEqual(pending, expected) {
					t.Fatal("wrong intent submitted")
				}
				disk, e := readSharedPendingEnrollment(f.o.TrustPath, f.root, f.o.Binding)
				if e != nil {
					t.Fatal(e)
				}
				settings, e := readSharedTransportSetup(f.o, f.root, disk.ObservedTrust())
				if e != nil || settings.DeviceRole != "wh_testscope_d_"+f.o.Binding.DeviceID.String() {
					t.Fatal("SQL before setup", e)
				}
				if mode == "uncertain" {
					return sharedpg.ErrInvitationCommitUncertain
				}
				return nil
			}
			factories := 0
			join := newSharedInvitationJoinWithSession(source, func() sharedJoinRecovery {
				factories++
				if source.closes != 1 {
					t.Fatal("device login preceded invitation cleanup")
				}
				if request.ValidateAccountMaster(f.master) != sharedpg.ErrConfiguration {
					t.Fatal("verifier retained during recovery")
				}
				return f.c
			})
			t.Cleanup(func() {
				if err := join.Close(context.Background()); err != nil {
					t.Error(err)
				}
			})
			result, err := join.Join(context.Background(), f.o, f.root, f.master, request)
			if err != nil || result == nil || !result.Submitted || !result.Committed || !result.Confirmed || source.calls != 1 || factories != 1 {
				t.Fatal("join", result, err)
			}
			if _, err := readActiveSharedTrustFile(f.o.TrustPath, f.root, f.o.Binding, result.TrustRevision); err != nil {
				t.Fatal("not activated", err)
			}
			if _, err := join.Join(context.Background(), f.o, f.root, f.master, request); err == nil || source.calls != 1 {
				t.Fatal("repeated SQL", err)
			}
		})
	}
}

func TestSharedInvitationJoinStagingFailures(t *testing.T) {
	for _, mode := range []string{"nil-context", "relative", "root", "minimum", "request", "nil-master", "nil-prepared", "closed-master", "configuration", "binding", "floor", "runtime", "foreign-tls", "tls-cache", "setup-sync", "intent-sync", "setup-confirm", "intent-confirm", "existing-setup", "existing-intent"} {
		t.Run(mode, func(t *testing.T) {
			f, request := preparedJoinFixture(t)
			ctx := context.Background()
			root := f.root
			master := f.master
			prepared := request
			syncDirectory := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = syncDirectory })
			source := &invitationJoinProbe{commit: func(context.Context, *sharedpg.PreparedInvitationCommit) error {
				t.Fatal("SQL after staging failure")
				return nil
			}}
			join := newSharedInvitationJoinWithSession(source, func() sharedJoinRecovery { t.Fatal("recovered undispatched intent"); return nil })
			t.Cleanup(func() {
				if err := join.Close(context.Background()); err != nil {
					t.Error(err)
				}
			})
			switch mode {
			case "nil-context":
				ctx = nil
			case "relative":
				f.o.TrustPath = "relative"
			case "root":
				root = nil
			case "minimum":
				f.o.MinimumRevision = 0
			case "request":
				f.o.Request.API = 0
			case "nil-master":
				master = nil
			case "nil-prepared":
				prepared = nil
			case "closed-master":
				if err := master.Close(); err != nil {
					t.Fatal(err)
				}
			case "configuration":
				f.o.Settings.Endpoints = nil
			case "binding":
				f.o.Binding.DeviceID[0] ^= 1
				f.o.Request.DeviceID = f.o.Binding.DeviceID
			case "floor":
				f.o.OSFloor = vault.Standard
			case "runtime":
				f.o.UserFloor = vault.Hardened
			case "foreign-tls":
				other := newRecoveryFixture(t)
				sharedTLSFixture(t, &f.o, other.pending.Trust, other.org, 3)
			case "tls-cache":
				sharedTLSFixture(t, &f.o, f.pending.Trust, f.org, 3)
				if err := os.MkdirAll(filepath.Dir(f.o.TrustPath), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(f.o.TrustPath+".tls", []byte("not a directory"), 0600); err != nil {
					t.Fatal(err)
				}
			case "existing-setup":
				if err := stageSharedTransportSetup(f.o, root, f.pending.Trust); err != nil {
					t.Fatal(err)
				}
			case "existing-intent":
				if err := stageSharedPendingEnrollment(f.o.TrustPath, root, f.o.Binding, f.pending); err != nil {
					t.Fatal(err)
				}
			default:
				calls := 0
				privateFileDirectorySync = func(path string) error {
					calls++
					switch mode {
					case "setup-sync":
						return os.ErrPermission
					case "intent-sync":
						if calls >= 2 {
							return os.ErrPermission
						}
					case "setup-confirm":
						if calls == 3 {
							return os.ErrPermission
						}
					case "intent-confirm":
						if calls == 4 {
							return os.ErrPermission
						}
					}
					return syncDirectory(path)
				}
			}
			result, err := join.Join(ctx, f.o, root, master, prepared)
			if err == nil || result != nil || source.calls != 0 {
				t.Fatal("unsafe staging", result, err)
			}
			if join.started && prepared == request && request.ValidateAccountMaster(f.master) != sharedpg.ErrConfiguration {
				t.Fatal("failed attempt retained prepared verifier")
			}
		})
	}
}

func TestSharedInvitationJoinRemoteOutcomes(t *testing.T) {
	for _, mode := range []string{"rejected", "unknown-unrecoverable", "close-failure", "nil-factory-result", "nil-recovery-result", "confirmed-local-failure", "recovery-cleanup"} {
		t.Run(mode, func(t *testing.T) {
			f, request := preparedJoinFixture(t)
			source := &invitationJoinProbe{closeFailure: mode == "close-failure"}
			source.commit = func(context.Context, *sharedpg.PreparedInvitationCommit) error {
				if mode == "rejected" {
					return sharedpg.ErrAuditUnavailable
				}
				if mode == "unknown-unrecoverable" {
					return sharedpg.ErrInvitationCommitUncertain
				}
				return nil
			}
			recovery := &joinRecoveryProbe{closeFailure: mode == "recovery-cleanup", run: func(context.Context, sharedAdmissionOptions, []byte, *sharedpg.AccountMaster) (*sharedEnrollmentRecoveryResult, error) {
				switch mode {
				case "unknown-unrecoverable":
					return nil, sharedpg.ErrAuthentication
				case "nil-recovery-result":
					return nil, nil
				case "confirmed-local-failure":
					return &sharedEnrollmentRecoveryResult{Confirmed: true, TrustRevision: 9}, errSharedTrustCommitUncertain
				}
				return &sharedEnrollmentRecoveryResult{Confirmed: true, TrustRevision: 9}, nil
			}}
			factories := 0
			join := newSharedInvitationJoinWithSession(source, func() sharedJoinRecovery {
				factories++
				if mode == "nil-factory-result" {
					return nil
				}
				return recovery
			})
			t.Cleanup(func() {
				source.closeFailure = false
				recovery.closeFailure = false
				if err := join.Close(context.Background()); err != nil {
					t.Error(err)
				}
			})
			result, err := join.Join(context.Background(), f.o, f.root, f.master, request)
			if err == nil || result == nil || !result.Submitted || source.calls != 1 {
				t.Fatal("lost remote outcome", result, err)
			}
			if mode == "rejected" || mode == "close-failure" {
				if factories != 0 {
					t.Fatal("unsafe recovery")
				}
			}
			if mode == "unknown-unrecoverable" {
				if result.Committed || !errors.Is(err, sharedpg.ErrInvitationCommitUncertain) || !errors.Is(err, sharedpg.ErrAuthentication) {
					t.Fatal("lost uncertainty", err)
				}
			}
			if mode == "confirmed-local-failure" || mode == "recovery-cleanup" {
				if !result.Confirmed || !result.Committed || result.TrustRevision != 9 {
					t.Fatal("lost confirmation")
				}
			}
			if _, err := readSharedPendingEnrollment(f.o.TrustPath, f.root, f.o.Binding); err != nil {
				t.Fatal("discarded pending outcome", err)
			}
		})
	}
}

func TestSharedInvitationJoinLifetime(t *testing.T) {
	for _, mode := range []string{"close-during-commit", "caller-cancel", "cancel-after-receipt", "closed", "started", "nil-session", "nil-factory"} {
		t.Run(mode, func(t *testing.T) {
			f, request := preparedJoinFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered := make(chan struct{})
			source := &invitationJoinProbe{commit: func(ctx context.Context, _ *sharedpg.PreparedInvitationCommit) error {
				if mode == "cancel-after-receipt" {
					cancel()
					return nil
				}
				close(entered)
				<-ctx.Done()
				return sharedpg.ErrInvitationCommitUncertain
			}}
			join := newSharedInvitationJoinWithSession(source, func() sharedJoinRecovery { t.Fatal("recovery after cancellation"); return nil })
			t.Cleanup(func() {
				if err := join.Close(context.Background()); err != nil {
					t.Error(err)
				}
			})
			switch mode {
			case "closed":
				if err := join.Close(ctx); err != nil {
					t.Fatal(err)
				}
			case "started":
				join.started = true
			case "nil-session":
				join.invitation = nil
			case "nil-factory":
				join.newRecovery = nil
			}
			type outcome struct {
				result *sharedInvitationJoinResult
				err    error
			}
			done := make(chan outcome, 1)
			go func() { result, err := join.Join(ctx, f.o, f.root, f.master, request); done <- outcome{result, err} }()
			if mode == "close-during-commit" || mode == "caller-cancel" {
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("commit not reached")
				}
				// A repeated caller with a canceled context must not wipe the live request.
				repeated, stop := context.WithCancel(context.Background())
				stop()
				if _, err := join.Join(repeated, f.o, f.root, f.master, request); !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				if err := request.ValidateAccountMaster(f.master); err != nil {
					t.Fatal("concurrent caller wiped active request", err)
				}
				if mode == "close-during-commit" {
					if err := join.Close(context.Background()); err != nil {
						t.Fatal(err)
					}
				} else {
					cancel()
				}
			}
			var result outcome
			select {
			case result = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("join stuck")
			}
			if result.err == nil {
				t.Fatal("accepted terminal lifetime")
			}
			if mode == "cancel-after-receipt" {
				if result.result == nil || !result.result.Committed || result.result.Confirmed {
					t.Fatal("receipt lost", result.result)
				}
			}
			if mode == "close-during-commit" || mode == "caller-cancel" {
				if result.result == nil || result.result.Committed || source.calls != 1 || !errors.Is(result.err, sharedpg.ErrInvitationCommitUncertain) {
					t.Fatal("uncertainty lost", result.err)
				}
			}
		})
	}
}

func TestSharedInvitationJoinExactDurabilityRetry(t *testing.T) {
	for _, phase := range []int{1, 2} {
		t.Run(map[int]string{1: "setup", 2: "intent"}[phase], func(t *testing.T) {
			f, request := preparedJoinFixture(t)
			syncDirectory := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = syncDirectory })
			calls := 0
			privateFileDirectorySync = func(path string) error {
				calls++
				if calls == phase {
					return os.ErrPermission
				}
				return syncDirectory(path)
			}
			source := &invitationJoinProbe{commit: func(context.Context, *sharedpg.PreparedInvitationCommit) error { return nil }}
			join := newSharedInvitationJoinWithSession(source, func() sharedJoinRecovery { return f.c })
			t.Cleanup(func() {
				if err := join.Close(context.Background()); err != nil {
					t.Error(err)
				}
			})
			result, err := join.Join(context.Background(), f.o, f.root, f.master, request)
			if err != nil || result == nil || !result.Confirmed || source.calls != 1 {
				t.Fatal("durable local retry", result, err)
			}
		})
	}
}

func TestSharedInvitationJoinConstructorsAndCleanup(t *testing.T) {
	if _, err := newSharedInvitationJoin(nil); err != sharedpg.ErrConfiguration {
		t.Fatal(err)
	}
	session := sharedpg.NewSession()
	join, err := newSharedInvitationJoin(session)
	if err != nil {
		t.Fatal(err)
	}
	join.recovery = join.newRecovery()
	if _, ok := join.recovery.(*sharedAdmissionController); !ok {
		t.Fatal("default recovery registration is not native")
	}
	if err := join.Close(nil); err != sharedpg.ErrConfiguration {
		t.Fatal(err)
	}
	if err := join.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := join.Close(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	f, request := preparedJoinFixture(t)
	other := newRecoveryFixture(t)
	source := &invitationJoinProbe{commit: func(context.Context, *sharedpg.PreparedInvitationCommit) error {
		t.Fatal("mismatched master submitted")
		return nil
	}}
	join = newSharedInvitationJoinWithSession(source, func() sharedJoinRecovery { return f.c })
	t.Cleanup(func() {
		if err := join.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	if _, err := join.Join(context.Background(), f.o, f.root, other.master, request); err != sharedpg.ErrConfiguration || source.calls != 0 {
		t.Fatal(err)
	}
}
