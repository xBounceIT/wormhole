package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

type continuationSessionProbe struct {
	invitationJoinProbe
	resumes int
	resume  func(context.Context, *sharedpg.InvitationContinuation, []byte, sharedpg.InvitationContinuationOptions, func(sharedpg.PendingEnrollment) error) (*sharedpg.PreparedInvitationCommit, error)
}

func (s *continuationSessionProbe) ResumeInvitationContinuation(ctx context.Context, c *sharedpg.InvitationContinuation, code []byte, o sharedpg.InvitationContinuationOptions, observe func(sharedpg.PendingEnrollment) error) (*sharedpg.PreparedInvitationCommit, error) {
	s.resumes++
	defer c.Wipe()
	if s.resume != nil {
		return s.resume(ctx, c, code, o, observe)
	}
	return nil, errors.New("fresh code proof refused")
}

func TestSharedInitialContinuationConfirmsExistingStagingBeforeOneSubmission(t *testing.T) {
	o, initial, protection, f, d := initialPublicationAccountFixture(t, false)
	o.startupProtection = &protection
	if _, err := publishSharedInitialBundle(context.Background(), o, initial, protection); err != nil {
		t.Fatal(err)
	}
	source := &invitationJoinProbe{commit: func(context.Context, *sharedpg.PreparedInvitationCommit) error { return nil }}
	j := newSharedInvitationJoinWithSession(source, func() sharedJoinRecovery { return f.c })
	defer func() {
		if err := j.Close(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	result, err := j.commitStagedInitial(context.Background(), o, f.root, d.key, initial.DeviceFile, d.master, d.commit, initial, protection)
	if err != nil || result == nil || !result.Confirmed || source.calls != 1 {
		t.Fatal(result, err, source.calls)
	}
	if j.preparation != nil {
		t.Fatal("continuation acquired discard authority")
	}
	if _, err := j.commitStagedInitial(context.Background(), o, f.root, d.key, initial.DeviceFile, d.master, d.commit, initial, protection); err == nil || source.calls != 1 {
		t.Fatal("owner replayed submission")
	}
}

func TestSharedInitialContinuationCloseRetainsLeaseUntilTemporarySessionCloses(t *testing.T) {
	probe := &continuationSessionProbe{}
	probe.closeFailure = true
	j := newSharedInvitationJoinWithSession(probe, func() sharedJoinRecovery { return nil })
	releases := 0
	s := &vaultSharedSession{joining: j, release: func() { releases++ }}
	if err := s.close(); err == nil || releases != 0 {
		t.Fatal("uncertain close released the workspace", err, releases)
	}
	probe.closeFailure = false
	if err := s.close(); err != nil || releases != 1 {
		t.Fatal("close retry did not release", err, releases)
	}
	if err := s.close(); err != nil || releases != 1 {
		t.Fatal("close released twice", err, releases)
	}
}

func TestSharedInitialContinuationRejectsChangedStagingWithoutDiscard(t *testing.T) {
	for _, mode := range []string{"format", "device-copy", "role", "config", "pending", "device", "snapshot", "active", "transition", "anchor", "cancel", "master", "binding", "late-cancel"} {
		t.Run(mode, func(t *testing.T) {
			o, initial, protection, f, d := initialPublicationAccountFixture(t, false)
			if _, err := publishSharedInitialBundle(context.Background(), o, initial, protection); err != nil {
				t.Fatal(err)
			}
			source := &invitationJoinProbe{}
			j := newSharedInvitationJoinWithSession(source, func() sharedJoinRecovery { return f.c })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			device := initial.DeviceFile
			master := d.master
			switch mode {
			case "format":
				initial.FormatVersion = 2
			case "device-copy":
				device = bytes.Clone(device)
				device[len(device)-1] ^= 1
			case "role":
				o.Settings.DeviceRole = "wrong"
			case "config":
				if err := os.WriteFile(sharedTransportSetupPath(o.TrustPath), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "pending":
				if err := os.WriteFile(sharedPendingEnrollmentPath(o.TrustPath), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "device":
				if err := os.WriteFile(sharedDeviceEnrollmentPath(o.TrustPath), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "snapshot":
				if err := os.WriteFile(sharedJoinStartupPath(o.TrustPath), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "active":
				if err := os.WriteFile(o.TrustPath, []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "transition":
				if err := os.WriteFile(sharedTrustTransitionPath(o.TrustPath), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "anchor":
				if err := os.WriteFile(sharedStartupAnchorPath(o.TrustPath), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancel()
			case "master":
				master = nil
			case "binding":
				o.Binding.KeyVersion++
			case "late-cancel":
				original := privateFileDirectorySync
				t.Cleanup(func() { privateFileDirectorySync = original })
				calls := 0
				privateFileDirectorySync = func(path string) error {
					calls++
					if calls == 4 {
						cancel()
					}
					return original(path)
				}
			}
			result, err := j.commitStagedInitial(ctx, o, f.root, d.key, device, master, d.commit, initial, protection)
			if err == nil || result != nil || source.calls != 0 {
				t.Fatal("changed staging reached SQL", result, err, source.calls)
			}
			if mode == "late-cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("test missed final cancellation boundary", err)
			}
			if err := j.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(sharedJoinStartupPath(o.TrustPath)); err != nil {
				t.Fatal("continuation discarded preexisting state", err)
			}
		})
	}
}

func TestSharedInitialContinuationRereadsProtectedSelectionAfterFreshProof(t *testing.T) {
	for _, mode := range []string{"corrupt-snapshot", "different-selection", "different-pending", "different-transport"} {
		t.Run(mode, func(t *testing.T) {
			o, initial, protection, _, d := initialPublicationAccountFixture(t, false)
			if _, err := publishSharedInitialBundle(context.Background(), o, initial, protection); err != nil {
				t.Fatal(err)
			}
			probe := &continuationSessionProbe{}
			probe.resume = func(_ context.Context, _ *sharedpg.InvitationContinuation, _ []byte, _ sharedpg.InvitationContinuationOptions, _ func(sharedpg.PendingEnrollment) error) (*sharedpg.PreparedInvitationCommit, error) {
				path := sharedJoinStartupPath(o.TrustPath)
				raw := []byte("changed")
				if mode == "different-transport" {
					path = sharedTransportSetupPath(o.TrustPath)
				}
				if mode == "different-selection" || mode == "different-pending" {
					next := initial
					if mode == "different-selection" {
						next.LoginName = "mallory"
					} else {
						next.Pending = bytes.Clone(next.Pending)
						next.Pending[len(next.Pending)-1] ^= 1
					}
					var err error
					raw, err = sealSharedJoinStartupValue(o.TrustPath, next, protection)
					if err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				// An intentionally foreign native owner can reach only these local
				// reread checks. The real PostgreSQL test covers matching-master success.
				return d.commit, nil
			}
			h := &vaultFoundationHandler{databasePath: strings.TrimSuffix(filepath.Dir(o.TrustPath), ".shared"), sharedProtection: &protection, sharedContinuationFactory: func() sharedInitialContinuationSession { return probe }}
			defer func() {
				if err := h.Close(); err != nil {
					t.Error(err)
				}
			}()
			input := map[string]any{"appVersion": "1.0.0", "factors": map[string]any{"vaultId": d.slots.VaultID, "slotId": d.slots.Slots[0].ID, "password": []byte("recovery-test-password")}, "code": bytes.Repeat([]byte{31}, 16), "acknowledgeTLSOff": true}
			_, err := h.Handle(context.Background(), "shared-continue-enrollment", vaultInput(t, input))
			if err == nil || probe.resumes != 1 || probe.calls != 0 {
				t.Fatal("changed selection reached SQL", err, probe.resumes, probe.calls)
			}
			if (mode == "different-selection" || mode == "different-pending") && !errors.Is(err, errSharedTrustConflict) {
				t.Fatal("test failed after the required local reread", err)
			}
			if mode == "corrupt-snapshot" && !errors.Is(err, errSharedTrustStorage) {
				t.Fatal("test missed snapshot authentication", err)
			}
			if mode == "different-transport" && !errors.Is(err, sharedpg.ErrTrustState) {
				t.Fatal("test missed protected transport reread", err)
			}
		})
	}
	var absent *sharedSelectedDevice
	if err := absent.continueInitialEnrollment(context.Background(), nil, nil, nil, false); !errors.Is(err, sharedpg.ErrConfiguration) {
		t.Fatal(err)
	}
}

func TestVaultSharedContinuationAuthenticatesAndRejectsMalformedRequestsBeforeNetwork(t *testing.T) {
	for _, mode := range []string{"proof", "nil-session", "nil-prepared", "legacy", "wrong-password", "wrong-vault", "code-short", "code-array", "ack-string", "extra", "missing-ack", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			o, initial, protection := initialPublicationFixture(t, false)
			if _, err := publishSharedInitialBundle(context.Background(), o, initial, protection); err != nil {
				t.Fatal(err)
			}
			slots, _, err := sharedpg.DecodeDeviceEnrollmentFile(initial.DeviceFile)
			if err != nil {
				t.Fatal(err)
			}
			probe := &continuationSessionProbe{}
			factories := 0
			h := &vaultFoundationHandler{databasePath: strings.TrimSuffix(filepath.Dir(o.TrustPath), ".shared"), sharedProtection: &protection, sharedContinuationFactory: func() sharedInitialContinuationSession {
				factories++
				if mode == "nil-session" {
					return nil
				}
				return probe
			}}
			defer func() {
				if err := h.Close(); err != nil {
					t.Error(err)
				}
			}()
			input := map[string]any{"appVersion": "1.0.0", "factors": map[string]any{"vaultId": slots.VaultID, "slotId": slots.Slots[0].ID, "password": []byte("recovery-test-password")}, "code": bytes.Repeat([]byte{31}, 16), "acknowledgeTLSOff": true}
			factors := input["factors"].(map[string]any)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "nil-prepared":
				probe.resume = func(context.Context, *sharedpg.InvitationContinuation, []byte, sharedpg.InvitationContinuationOptions, func(sharedpg.PendingEnrollment) error) (*sharedpg.PreparedInvitationCommit, error) {
					return nil, nil
				}
			case "legacy":
				initial.FormatVersion, initial.Purpose, initial.Continuation = 2, "wormhole/shared-join-startup/v2", nil
				sealed, err := sealSharedJoinStartupValue(o.TrustPath, initial, protection)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(sharedJoinStartupPath(o.TrustPath), sealed, 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-password":
				factors["password"] = []byte("wrong password")
			case "wrong-vault":
				factors["vaultId"] = slots.Slots[0].ID
			case "code-short":
				input["code"] = bytes.Repeat([]byte{31}, 15)
			case "code-array":
				input["code"] = []int{1, 2, 3}
			case "ack-string":
				input["acknowledgeTLSOff"] = "true"
			case "extra":
				input["endpoint"] = "untrusted"
			case "missing-ack":
				delete(input, "acknowledgeTLSOff")
			case "cancel":
				cancel()
			}
			if raw, err := h.Handle(ctx, "shared-continue-enrollment", vaultInput(t, input)); err == nil || len(raw) != 0 {
				t.Fatal("invalid continuation admitted", err)
			}
			expected := 0
			if mode == "proof" || mode == "nil-prepared" {
				expected = 1
			}
			if probe.resumes != expected || probe.calls != 0 {
				t.Fatal("unexpected network or SQL", probe.resumes, probe.calls)
			}
			if factories > 0 && expected == 0 && mode != "nil-session" {
				t.Fatal("invalid local state opened continuation")
			}
			if _, err := os.Stat(sharedJoinStartupPath(o.TrustPath)); err != nil {
				t.Fatal("failed continuation deleted snapshot", err)
			}
		})
	}
}
