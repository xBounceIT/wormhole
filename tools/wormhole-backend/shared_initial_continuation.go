package main

import (
	"context"
	"errors"
	"os"
	"reflect"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type sharedInitialContinuationSession interface {
	sharedInvitationCommitSession
	ResumeInvitationContinuation(context.Context, *sharedpg.InvitationContinuation, []byte, sharedpg.InvitationContinuationOptions, func(sharedpg.PendingEnrollment) error) (*sharedpg.PreparedInvitationCommit, error)
}

func requirePendingInitialJoin(path string) error {
	if err := requireMissingSharedTrust(path); err != nil {
		return err
	}
	if err := requireNoSharedTrustTransition(path); err != nil {
		return err
	}
	if _, err := os.Lstat(sharedStartupAnchorPath(path)); !errors.Is(err, os.ErrNotExist) {
		return errSharedTrustConflict
	}
	return nil
}

// Explicit PW/code continuation never owns pre-existing staging for discard.
// Fresh code proof and the server's single-use transaction authorize one attempt;
// a failed device login or a missing local record is never evidence of noncommit.
func (s *sharedSelectedDevice) continueInitialEnrollment(ctx context.Context, j *sharedInvitationJoin, session sharedInitialContinuationSession, code []byte, acknowledgeTLSOff bool) error {
	if ctx == nil || s == nil || s.initial == nil || s.initial.FormatVersion != 3 || len(s.initial.Continuation) == 0 || len(code) != vault.InviteCodeBytes || j == nil || session == nil {
		return sharedpg.ErrConfiguration
	}
	return s.account.Borrow(func(master *sharedpg.AccountMaster, root *sharedpg.DeviceTrustRoot) error {
		return root.Use(func(key []byte) error {
			o := s.options
			if err := requirePendingInitialJoin(o.TrustPath); err != nil {
				return err
			}
			if err := restoreSharedJoinStaging(ctx, s, key, master); err != nil {
				return err
			}
			pending, err := readSharedPendingEnrollment(o.TrustPath, key, o.Binding)
			if err != nil {
				return err
			}
			if err := validateSharedEnrollmentState(pending); err != nil {
				return err
			}
			o.Settings, err = readSharedTransportSetup(o, key, pending.ObservedTrust())
			if err != nil {
				return err
			}
			if err := loadSharedTLSCache(&o, pending.ObservedTrust()); err != nil {
				return err
			}
			continuation, err := sharedpg.OpenInvitationContinuation(key, o.Binding, master, s.initial.Continuation)
			if err != nil {
				return err
			}
			prepared, err := session.ResumeInvitationContinuation(ctx, continuation, code, sharedpg.InvitationContinuationOptions{
				Request: o.Request, Observed: pending, OSFloor: o.OSFloor, UserFloor: o.UserFloor, AcknowledgeTLSOff: acknowledgeTLSOff, TLSBundle: o.Settings.TLSBundle,
			}, func(next sharedpg.PendingEnrollment) error {
				return persistSharedEnrollmentObservation(o, key, &pending, next)
			})
			if prepared != nil {
				defer prepared.Wipe()
			}
			if err != nil {
				return err
			}
			if prepared == nil {
				return sharedpg.ErrAdmissionResponse
			}
			current, err := readSharedJoinStartup(o.TrustPath, *o.startupProtection)
			if err != nil {
				return err
			}
			a, b := *s.initial, current
			a.Transport, a.Pending = nil, nil
			b.Transport, b.Pending = nil, nil
			if !reflect.DeepEqual(a, b) {
				return errSharedTrustConflict
			}
			observed, err := sharedpg.OpenPendingEnrollment(key, o.Binding, current.Pending)
			if err != nil || !reflect.DeepEqual(observed, pending) {
				return errSharedTrustConflict
			}
			*s.initial = current
			o.Settings, err = readSharedTransportSetup(o, key, pending.ObservedTrust())
			if err != nil {
				return err
			}
			return s.account.BorrowDeviceStorage(func(storage, deviceFile []byte) error {
				result, err := j.commitStagedInitial(ctx, o, key, storage, deviceFile, master, prepared, current, *o.startupProtection)
				if err != nil {
					return err
				}
				if result == nil || !result.Confirmed {
					return sharedpg.ErrAdmissionResponse
				}
				return nil
			})
		})
	})
}

func (j *sharedInvitationJoin) commitStagedInitial(ctx context.Context, o sharedAdmissionOptions, root, storage, deviceFile []byte, master *sharedpg.AccountMaster, prepared *sharedpg.PreparedInvitationCommit, initial sharedJoinStartup, protection sharedStartupProtection) (*sharedInvitationJoinResult, error) {
	return j.runJoin(ctx, func(ctx context.Context) (*sharedInvitationJoinResult, error) {
		defer prepared.Wipe()
		if initial.FormatVersion != 3 || !initial.valid(o.TrustPath) || !reflect.DeepEqual(deviceFile, initial.DeviceFile) || j.invitation == nil || j.newRecovery == nil {
			return nil, sharedpg.ErrConfiguration
		}
		if err := prepared.ValidateAccountMaster(master); err != nil {
			return nil, err
		}
		if err := requirePendingInitialJoin(o.TrustPath); err != nil {
			return nil, err
		}
		pending, err := prepared.PendingEnrollment(o.Binding)
		if err != nil {
			return nil, err
		}
		if err := validateSharedEnrollmentState(pending); err != nil {
			return nil, err
		}
		if o.Settings.DeviceRole != "wh_"+pending.RoleTag+"_d_"+o.Binding.DeviceID.String() {
			return nil, sharedpg.ErrTrustState
		}
		if err := confirmSharedTransportSetup(o, root, pending.ObservedTrust()); err != nil {
			return nil, err
		}
		if err := confirmSharedPendingEnrollment(o.TrustPath, root, o.Binding, pending); err != nil {
			return nil, err
		}
		slots, _, err := sharedpg.DecodeDeviceEnrollmentFile(deviceFile)
		if err != nil {
			return nil, err
		}
		if err := confirmSharedDeviceEnrollmentState(o.TrustPath, storage, slots.VaultID, slots.FileID, slots.Sequence, deviceFile, func() error {
			actual, err := readSharedPendingEnrollment(o.TrustPath, root, o.Binding)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(actual, pending) {
				return errSharedTrustConflict
			}
			return nil
		}); err != nil {
			return nil, err
		}
		if err := writeSharedJoinStartup(ctx, o.TrustPath, initial, protection, true); err != nil {
			return nil, err
		}
		if err := requirePendingInitialJoin(o.TrustPath); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return j.commitAndRecover(ctx, o, root, master, prepared)
	})
}
