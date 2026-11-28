package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestSharedSetupDestinationRetryAfterSelectionWriteFailure(t *testing.T) {
	h := vaultCredentialFixture(t)
	initial, remote, _, session, request, _ := initialJoinFixture(t)
	target := localSharedWorkspaceDatabase(h.databasePath)
	remote.o.TrustPath = sharedWorkspaceTrustPath(target)
	h.sharedFactory, h.sharedInvitationFactory = initial.sharedFactory, initial.sharedInvitationFactory
	protection := *initial.sharedProtection
	protect := protection.protect
	failSelection := true
	protection.protect = func(path string, raw []byte) ([]byte, error) {
		if failSelection && path == sharedWorkspaceSelectionPath(h.databasePath) {
			return nil, errSharedTrustStorage
		}
		return protect(path, raw)
	}
	h.sharedProtection = &protection
	input, err := decodeSharedInitialJoin(vaultInput(t, request))
	if err != nil {
		t.Fatal(err)
	}
	defer input.wipe()
	ctx := context.Background()
	if result, err := h.selectLocalSharedDestination(ctx, input); !errors.Is(err, errSharedTrustStorage) || len(result) != 0 {
		t.Fatal("selection write failure reported success", err)
	}
	if session.calls != 1 || h.closed || h.sharedDestination != nil || h.owner == nil {
		t.Fatal("failed selection lost the local owner or retained the destination owner")
	}
	if path, selection, err := resolveVaultWorkspace(h.databasePath, protection); path != h.databasePath || selection != nil || err != nil {
		t.Fatal("unpublished selection changed the configured workspace", err)
	}
	if _, err := readSharedStartupAnchor(sharedWorkspaceTrustPath(target), protection); err != nil {
		t.Fatal("lost confirmed admission", err)
	}
	failSelection = false
	other, err := decodeSharedInitialJoin(vaultInput(t, request))
	if err != nil {
		t.Fatal(err)
	}
	defer other.wipe()
	other.invitation.Enrollment.Context.UserID = uuid.New()
	if _, err := h.selectLocalSharedDestination(ctx, other); !errors.Is(err, sharedpg.ErrTrustState) {
		t.Fatal("an unrelated account selected the existing device", err)
	}
	if result, err := h.selectLocalSharedDestination(ctx, input); err != nil || string(result) != `{"switchOnRestart":true}` || session.calls != 1 {
		t.Fatal("retry should select the admitted device without replaying the invitation", err)
	}
}

func TestSharedSetupDestinationRefusesOccupiedOrInvalidStorage(t *testing.T) {
	h := vaultCredentialFixture(t)
	initial, _, _, session, request, _ := initialJoinFixture(t)
	h.sharedFactory, h.sharedInvitationFactory, h.sharedProtection = initial.sharedFactory, initial.sharedInvitationFactory, initial.sharedProtection
	input, err := decodeSharedInitialJoin(vaultInput(t, request))
	if err != nil {
		t.Fatal(err)
	}
	defer input.wipe()
	target := localSharedWorkspaceDatabase(h.databasePath)
	dir := filepath.Dir(target)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.selectLocalSharedDestination(ctx, input); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled setup touched the destination", err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("canceled setup created a directory", err)
	}
	if err := os.WriteFile(dir, []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx = context.Background()
	if _, err := h.selectLocalSharedDestination(ctx, input); !errors.Is(err, errSharedTrustStorage) {
		t.Fatal("non-directory was accepted", err)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	release, err := tryAcquireExclusiveFileLock(target + ".vault.lock")
	if err != nil {
		t.Fatal(err)
	}
	_, occupied := h.selectLocalSharedDestination(ctx, input)
	release()
	if !errors.Is(occupied, errWorkspaceInUse) {
		t.Fatal("setup acquired an occupied destination", occupied)
	}

	if err := os.Mkdir(sharedWorkspaceDirectory(target), 0700); err != nil {
		t.Fatal(err)
	}
	checkpoint := sharedJoinStartupPath(sharedWorkspaceTrustPath(target))
	if err := os.WriteFile(checkpoint, []byte("invalid checkpoint"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.selectLocalSharedDestination(ctx, input); !errors.Is(err, errSharedTrustStorage) {
		t.Fatal("invalid enrollment checkpoint was accepted", err)
	}
	if session.calls != 0 || h.sharedDestination != nil || h.owner == nil {
		t.Fatal("refused destination changed local owner state or submitted a Join")
	}
	if data, err := os.ReadFile(checkpoint); err != nil || string(data) != "invalid checkpoint" {
		t.Fatal("setup overwrote the refused checkpoint", err)
	}
}

func TestSharedSetupDestinationReconcilesSubmittedEnrollment(t *testing.T) {
	h := vaultCredentialFixture(t)
	join, remote, prepared, session := sharedJoinPasswordPreparationFixture(t)
	target := localSharedWorkspaceDatabase(h.databasePath)
	remote.o.TrustPath = sharedWorkspaceTrustPath(target)
	protection := startupTestProtection()
	h.sharedProtection = &protection
	ctx := context.Background()
	pending, err := prepared.commit.PendingEnrollment(remote.o.Binding)
	if err != nil {
		t.Fatal(err)
	}
	join.newRecovery = func() sharedJoinRecovery {
		return &joinRecoveryProbe{run: func(context.Context, sharedAdmissionOptions, []byte, *sharedpg.AccountMaster) (*sharedEnrollmentRecoveryResult, error) {
			return nil, sharedpg.ErrConnection
		}}
	}
	result, err := join.joinPreparedWithStartup(ctx, remote.o, prepared, &protection)
	if result == nil || !result.Submitted || err == nil {
		t.Fatal("fixture failed to stage a submitted enrollment", err)
	}
	input := sharedInitialJoinInput{
		invitation: sharedpg.Invitation{
			WorkspaceID: remote.o.Binding.WorkspaceID,
			Enrollment:  &sharedpg.InvitationEnrollment{Context: pending.Certificate.Manifest.Context},
		},
		password: []byte("recovery-test-password"), code: make([]byte, vault.InviteCodeBytes),
		appVersion: "1.0.0", deviceName: "fixture device",
	}
	defer input.wipe()
	factories := 0
	h.sharedFactory = func() *sharedAdmissionController {
		factories++
		if factories == 1 {
			return remote.c
		}
		controller, _ := selectedDeviceController(t, remote)
		return controller
	}
	h.sharedInvitationFactory = func() sharedInitialInvitationSession {
		t.Fatal("submitted invitation reached the initial Join path")
		return nil
	}
	receipt, err := h.selectLocalSharedDestination(ctx, input)
	if err != nil || string(receipt) != `{"switchOnRestart":true}` || session.calls != 1 || factories != 2 {
		t.Fatal("failed to recover submitted enrollment", err, session.calls, factories)
	}
}
