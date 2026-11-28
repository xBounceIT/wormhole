package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type initialAccountPreparationProbe struct {
	*preparedDeviceProbe
	closed, taken         bool
	closeError, takeError error
}

func (p *initialAccountPreparationProbe) Close() error {
	if p.closeError != nil {
		return p.closeError
	}
	p.closed = true
	p.commit.Wipe()
	return errors.Join(p.master.Close(), p.root.Close())
}

func (p *initialAccountPreparationProbe) TakeDeviceAccount(ctx context.Context) (*sharedpg.UnlockedDeviceAccount, error) {
	if p.takeError != nil {
		return nil, p.takeError
	}
	raw, err := sharedpg.EncodeDeviceEnrollmentFile(p.key, p.slots, p.envelope)
	if err != nil {
		return nil, err
	}
	account, err := sharedpg.OpenDeviceAccount(ctx, raw, sharedpg.DeviceUnlockSelection{VaultID: p.slots.VaultID, FileID: p.slots.FileID, SlotID: p.slots.Slots[0].ID, MinimumSequence: 1}, []byte("recovery-test-password"), nil, vault.Default, vault.Default)
	p.taken = err == nil
	return account, err
}

type initialInvitationSessionProbe struct {
	*invitationJoinProbe
	prepared                sharedInitialAccountPreparation
	openError, prepareError error
	prepareHook             func()
	borrowed                [][]byte
	opens, preparations     int
}

func (s *initialInvitationSessionProbe) OpenInitialInvitation(_ context.Context, _ sharedpg.Invitation, code []byte, osFloor, userFloor vault.Profile, acknowledged bool) error {
	s.opens++
	s.borrowed = append(s.borrowed, code)
	if osFloor != vault.Default || userFloor != vault.Default || !acknowledged {
		return vault.ErrPolicy
	}
	return s.openError
}

func (s *initialInvitationSessionProbe) prepareInitial(_ context.Context, _ sharedpg.Invitation, code, password, ask []byte, _ string, _, _ vault.Profile) (sharedInitialAccountPreparation, error) {
	s.preparations++
	s.borrowed = append(s.borrowed, code, password, ask)
	if s.prepareHook != nil {
		s.prepareHook()
	}
	return s.prepared, s.prepareError
}

func initialJoinFixture(t *testing.T) (*vaultFoundationHandler, *recoveryFixture, *initialAccountPreparationProbe, *initialInvitationSessionProbe, map[string]any, *int) {
	t.Helper()
	_, f, p, source := sharedJoinPasswordPreparationFixture(t)
	f.o.TrustPath = sharedWorkspaceTrustPath(filepath.Join(t.TempDir(), "workspace.db"))
	fingerprint := sha256.Sum256(f.org.Public().(ed25519.PublicKey))
	pending, err := p.commit.PendingEnrollment(f.o.Binding)
	if err != nil {
		t.Fatal(err)
	}
	i := sharedpg.Invitation{FormatVersion: 2, WorkspaceID: f.o.Binding.WorkspaceID, LoginName: "alice", Endpoints: f.o.Settings.Endpoints, Database: f.o.Settings.Database, TLS: f.o.Settings.TLS, CAPEM: f.o.Settings.CAPEM, OrganisationFingerprint: fingerprint[:], ExpiresAt: pending.Certificate.Manifest.ExpiresAt, Enrollment: &sharedpg.InvitationEnrollment{RoleTag: pending.RoleTag, Context: pending.Certificate.Manifest.Context}}
	token, err := sharedpg.EncodeInvitation(i, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	prepared := &initialAccountPreparationProbe{preparedDeviceProbe: p}
	session := &initialInvitationSessionProbe{invitationJoinProbe: source, prepared: prepared}
	protection := startupTestProtection()
	factories := 0
	h := &vaultFoundationHandler{databasePath: filepath.Dir(f.o.TrustPath)}
	h.databasePath = strings.TrimSuffix(h.databasePath, ".shared")
	h.sharedProtection = &protection
	h.sharedInvitationFactory = func() sharedInitialInvitationSession { return session }
	h.sharedFactory = func() *sharedAdmissionController {
		factories++
		if factories == 1 {
			return f.c
		}
		c, _ := selectedDeviceController(t, f)
		return c
	}
	t.Cleanup(func() {
		source.closeFailure = false
		prepared.closeError = nil
		if err := h.Close(); err != nil {
			t.Error(err)
		}
	})
	input := map[string]any{"invitation": token, "code": bytes.Repeat([]byte{31}, 16), "password": []byte("recovery-test-password"), "deviceName": "native device", "appVersion": "1.0.0", "acknowledgeTLSOff": true}
	return h, f, prepared, session, input, &factories
}

func TestVaultSharedInitialJoinAdmitsOnlyAfterNativeConfirmation(t *testing.T) {
	h, f, p, session, input, factories := initialJoinFixture(t)
	raw, err := h.Handle(context.Background(), "shared-join-initial", vaultInput(t, input))
	var result map[string]bool
	if err != nil || json.Unmarshal(raw, &result) != nil || len(result) != 3 || !result["admitted"] || !result["orgEscrow"] {
		t.Fatal("native initial admission", string(raw), err, "commits", session.calls, "preparations", session.preparations, "controllers", *factories, "taken", p.taken)
	}
	if session.calls != 1 || session.opens != 1 || session.preparations != 1 || *factories != 2 || !p.closed || !p.taken {
		t.Fatal("wrong native preparation, dispatch or owner lifetime")
	}
	for _, factor := range session.borrowed {
		if !bytes.Equal(factor, make([]byte, len(factor))) {
			t.Fatal("initial factors survived the native operation")
		}
	}
	if h.owner != nil || h.shared == nil || h.shared.initial != nil || h.shared.vaultID != p.slots.VaultID || !h.shared.controller.Unlocked() {
		t.Fatal("wrong application owner")
	}
	anchor, err := readSharedStartupAnchor(f.o.TrustPath, h.startupProtection())
	if err != nil || anchor.Binding != f.o.Binding || anchor.VaultID != p.slots.VaultID || requireNoSharedJoinStartup(f.o.TrustPath) != nil {
		t.Fatal("confirmed initial selection was not promoted", err)
	}
	settings, err := readSharedTransportSetup(h.shared.selected.options, f.root, anchor.Trust)
	if err != nil || settings.Changes.UseNotifications() {
		t.Fatal("initial enrollment did not preserve conservative pooler support", err)
	}
	runtime := verifySharedRuntimeAfterAdmission(t, h)
	if runtime.WorkspaceID != f.o.Binding.WorkspaceID.String() || runtime.VaultID != p.slots.VaultID {
		t.Fatal("wrong admitted runtime")
	}
	if err := h.shared.selected.account.Borrow(func(*sharedpg.AccountMaster, *sharedpg.DeviceTrustRoot) error { return nil }); err == nil {
		t.Fatal("account derivation roots remained available")
	}
	if _, err := acquireWorkspaceOwnership(h.databasePath, false); !errors.Is(err, errWorkspaceInUse) {
		t.Fatal("initial admission lost its workspace lease", err)
	}
	if !h.ExitOnCancel("shared-join-initial") {
		t.Fatal("initial join cancellation did not retire the owner")
	}
	if _, err := h.Handle(context.Background(), "shared-join-initial", vaultInput(t, input)); err == nil || session.calls != 1 {
		t.Fatal("admitted invitation was submitted twice")
	}
}

func TestVaultSharedInitialJoinFailurePreservesOnlyRequiredRecovery(t *testing.T) {
	for _, mode := range []string{"factory", "open", "prepare", "nil-prepared", "binding", "competing-directory", "protect", "commit", "recovery", "take", "recovery-factory", "second-factory", "admit", "publish", "transport-cleanup", "preparation-cleanup", "sync"} {
		t.Run(mode, func(t *testing.T) {
			h, f, p, session, input, _ := initialJoinFixture(t)
			syncOriginal := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = syncOriginal })
			switch mode {
			case "factory":
				h.sharedInvitationFactory = func() sharedInitialInvitationSession { return nil }
			case "open", "transport-cleanup":
				session.openError = sharedpg.ErrConnection
				session.closeFailure = mode == "transport-cleanup"
			case "prepare", "preparation-cleanup":
				session.prepareError = sharedpg.ErrInvitation
				if mode == "preparation-cleanup" {
					p.closeError = sharedpg.ErrAccountMasterCleanup
				}
			case "nil-prepared":
				session.prepared = nil
			case "binding":
				i, err := sharedpg.DecodeInvitation(input["invitation"].(string), time.Now())
				if err != nil {
					t.Fatal(err)
				}
				i.WorkspaceID = uuid.New()
				i.Enrollment.Context.WorkspaceID = i.WorkspaceID
				input["invitation"], err = sharedpg.EncodeInvitation(i, time.Now())
				if err != nil {
					t.Fatal(err)
				}
			case "competing-directory":
				session.prepareHook = func() {
					if err := os.Mkdir(sharedWorkspaceDirectory(h.databasePath), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(sharedWorkspaceDirectory(h.databasePath), "foreign"), []byte("preserve"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "protect":
				h.sharedProtection.protect = func(string, []byte) ([]byte, error) { return nil, errors.New("keystore unavailable") }
			case "commit":
				session.commit = func(context.Context, *sharedpg.PreparedInvitationCommit) error {
					return sharedpg.ErrInvitationCommitUncertain
				}
				f.probe.start = func(context.Context) error { return sharedpg.ErrConnection }
			case "recovery":
				f.probe.start = func(context.Context) error { return sharedpg.ErrConnection }
			case "take":
				p.takeError = sharedpg.ErrDeviceStorageCleanup
			case "recovery-factory":
				h.sharedFactory = func() *sharedAdmissionController { return nil }
			case "second-factory", "admit":
				calls := 0
				h.sharedFactory = func() *sharedAdmissionController {
					calls++
					if calls == 1 {
						return f.c
					}
					if mode == "second-factory" {
						return nil
					}
					c, probe := selectedDeviceController(t, f)
					probe.open = func(context.Context, sharedpg.Settings) error { return sharedpg.ErrConnection }
					return c
				}
			case "publish":
				protect := h.sharedProtection.protect
				h.sharedProtection.protect = func(path string, raw []byte) ([]byte, error) {
					if strings.HasSuffix(path, ".startup") {
						return nil, errors.New("keystore unavailable")
					}
					return protect(path, raw)
				}
			case "sync":
				session.prepareHook = func() { privateFileDirectorySync = func(string) error { return errors.New("sync unavailable") } }
			}
			raw, err := h.Handle(context.Background(), "shared-join-initial", vaultInput(t, input))
			if err == nil || len(raw) != 0 {
				t.Fatal("failed join admitted", string(raw), err)
			}
			expectedCommit := mode == "commit" || mode == "recovery" || mode == "take" || mode == "recovery-factory" || mode == "second-factory" || mode == "admit" || mode == "publish"
			if expectedCommit != (session.calls == 1) {
				t.Fatal("failure did not reach its intended dispatch boundary", mode, session.calls, err)
			}
			for _, factor := range session.borrowed {
				if !bytes.Equal(factor, make([]byte, len(factor))) {
					t.Fatal("failed join retained input factors")
				}
			}
			if mode == "transport-cleanup" || mode == "preparation-cleanup" || mode == "sync" {
				if !h.closed || h.shared == nil || h.shared.release == nil {
					t.Fatal("unconfirmed cleanup released native exclusion")
				}
				session.closeFailure, p.closeError, privateFileDirectorySync = false, nil, syncOriginal
				if err := h.Close(); err != nil {
					t.Fatal("native cleanup retry", err)
				}
			} else if h.shared != nil {
				t.Fatal("positively cleaned failed owner remained attached")
			}
			if session.calls != 0 {
				if session.calls != 1 {
					t.Fatal("remote invocation was replayed")
				}
				if _, err := readSharedJoinStartup(f.o.TrustPath, h.startupProtection()); err != nil {
					t.Fatal("uncertain or unpromoted outcome lost its recovery selection", err)
				}
			} else if mode != "competing-directory" {
				if _, err := os.Lstat(sharedWorkspaceDirectory(h.databasePath)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("never-submitted clean failure left an unusable startup directory", err)
				}
			}
		})
	}
}

func TestSharedInitialJoinInputAndWorkspaceGuards(t *testing.T) {
	h, _, _, session, valid, _ := initialJoinFixture(t)
	for _, mode := range []string{"unknown", "null", "missing", "array-code", "empty-password", "large-password", "bad-code", "bad-ask", "empty-ask", "bad-name", "large-name", "version", "invite", "duplicate", "large-payload", "utf8"} {
		t.Run(mode, func(t *testing.T) {
			input := make(map[string]any)
			for key, value := range valid {
				input[key] = value
			}
			switch mode {
			case "unknown":
				input["settings"] = map[string]any{"role": "administrator"}
			case "null":
				input["acknowledgeTLSOff"] = nil
			case "missing":
				delete(input, "code")
			case "array-code":
				input["code"] = []int{1, 2, 3}
			case "empty-password":
				input["password"] = []byte{}
			case "large-password":
				input["password"] = make([]byte, 1025)
			case "bad-code":
				input["code"] = []byte{1}
			case "bad-ask":
				input["ask"] = []byte{1}
			case "empty-ask":
				input["ask"] = []byte{}
			case "bad-name":
				input["deviceName"] = "bad\nname"
			case "large-name":
				input["deviceName"] = strings.Repeat("a", 4097)
			case "version":
				input["appVersion"] = "untrusted version"
			case "invite":
				input["invitation"] = "WHINV2-invalid"
			}
			payload := vaultInput(t, input)
			if mode == "duplicate" {
				payload = append([]byte(`{"deviceName":"first",`), payload[1:]...)
			}
			if mode == "large-payload" {
				payload = bytes.Repeat([]byte{' '}, 2*sharedpg.MaxInvitationBytes+16385)
			}
			if mode == "utf8" {
				payload = []byte{'{', 255, '}'}
			}
			decoded, err := decodeSharedInitialJoin(payload)
			if err == nil {
				t.Fatal("malformed initial join accepted")
			}
			for _, factor := range [][]byte{decoded.code, decoded.password, decoded.ask} {
				if !bytes.Equal(factor, make([]byte, len(factor))) {
					t.Fatal("partial input decode retained factors")
				}
			}
			if _, err := h.Handle(context.Background(), "shared-join-initial", payload); err == nil || session.opens != 0 {
				t.Fatal("invalid input contacted an invitation server")
			}
		})
	}
	for _, mode := range []string{"nil-context", "cancelled", "local", "slots", "shared-directory", "lease"} {
		t.Run(mode, func(t *testing.T) {
			h, _, _, session, input, _ := initialJoinFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "nil-context":
				ctx = nil
			case "cancelled":
				cancel()
			case "local", "slots":
				path := h.databasePath
				if mode == "slots" {
					path = vaultSlotPath(path)
				}
				if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			case "shared-directory":
				if err := os.Mkdir(sharedWorkspaceDirectory(h.databasePath), 0700); err != nil {
					t.Fatal(err)
				}
			case "lease":
				release, err := acquireWorkspaceOwnership(h.databasePath, false)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			}
			if _, err := h.joinSharedInitial(ctx, vaultInput(t, input)); err == nil || session.opens != 0 {
				t.Fatal("workspace guard contacted the invitation server")
			}
		})
	}
}

func TestInitialJoinEmptyDirectoryCleanupDoesNotEraseCompetingState(t *testing.T) {
	for _, mode := range []string{"empty", "lock", "nonempty-lock", "lock-directory", "unknown", "many", "replaced", "missing", "sync"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "workspace.shared")
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			info, err := captureInitialJoinDirectory(path)
			if err != nil {
				t.Fatal(err)
			}
			p := &vaultSharedInitialJoin{path: path, directory: info}
			write := func(name, content string) {
				if err := os.WriteFile(filepath.Join(path, name), []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			syncOriginal := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = syncOriginal })
			switch mode {
			case "lock":
				write("device.trust.lock", "")
			case "nonempty-lock":
				write("device.trust.lock", "preserve")
			case "lock-directory":
				if err := os.Mkdir(filepath.Join(path, "device.trust.lock"), 0700); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				write("foreign", "preserve")
			case "many":
				write("one", "preserve")
				write("two", "preserve")
			case "replaced":
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "sync":
				privateFileDirectorySync = func(string) error { return errors.New("uncertain directory sync") }
			}
			err = p.close()
			allowed := mode == "empty" || mode == "lock" || mode == "missing"
			if allowed {
				if err != nil || p.directory != nil {
					t.Fatal("empty owned preparation not retired", err)
				}
			} else {
				if err == nil || p.directory == nil {
					t.Fatal("unconfirmed or competing directory was discarded")
				}
				if mode == "sync" {
					privateFileDirectorySync = syncOriginal
					if err := p.close(); err != nil || p.directory != nil {
						t.Fatal("directory sync retry", err)
					}
				} else if _, err := os.Lstat(path); err != nil {
					t.Fatal("competing directory was erased", err)
				}
			}
		})
	}
}

func TestInitialJoinNativeAdapterAndDirectoryCaptureGuards(t *testing.T) {
	session := nativeSharedInitialInvitation{sharedpg.NewSession()}
	defer session.Close(context.Background())
	if p, err := session.prepareInitial(nil, sharedpg.Invitation{}, nil, nil, nil, "", vault.Default, vault.Default); err == nil || p != nil {
		t.Fatal("native adapter returned a typed nil preparation owner")
	}
	path := filepath.Join(t.TempDir(), "capture")
	if _, err := captureInitialJoinDirectory(path); err == nil {
		t.Fatal("captured nonexistent directory")
	}
	if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := captureInitialJoinDirectory(path); err == nil {
		t.Fatal("captured a file as a preparation directory")
	}
	h, _, _, probe, input, _ := initialJoinFixture(t)
	i, err := sharedpg.DecodeInvitation(input["invitation"].(string), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"legacy-invite", "login-control"} {
		invitation := i
		if mode == "legacy-invite" {
			invitation.FormatVersion, invitation.Enrollment = 1, nil
		} else {
			enrollment := *i.Enrollment
			invitation.Enrollment = &enrollment
			invitation.LoginName = "alice\n"
			invitation.Enrollment.Context.LoginName = invitation.LoginName
		}
		input["invitation"], err = sharedpg.EncodeInvitation(invitation, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.Handle(context.Background(), "shared-join-initial", vaultInput(t, input)); err == nil || probe.opens != 0 {
			t.Fatal("invalid enrollment invitation reached transport", mode)
		}
	}
	input["invitation"], err = sharedpg.EncodeInvitation(i, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	input["ask"] = bytes.Repeat([]byte{11}, 32)
	decoded, err := decodeSharedInitialJoin(vaultInput(t, input))
	if err != nil || !bytes.Equal(decoded.ask, input["ask"].([]byte)) {
		t.Fatal("valid optional account secret key was rejected", err)
	}
	decoded.wipe()
	if !bytes.Equal(decoded.ask, make([]byte, 32)) {
		t.Fatal("account secret key was not retired")
	}
}
