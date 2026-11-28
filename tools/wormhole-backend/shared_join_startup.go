package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const maxSharedJoinStartupBytes = 2*(sharedpg.MaxDeviceEnrollmentFileBytes+2*sharedpg.MaxTransportSnapshotBytes+sharedpg.MaxPendingEnrollmentBytes+2*sharedpg.MaxInvitationContinuationBytes) + 4096

// Independently OS-protected native selection for an INITIAL join. DeviceFile is
// ciphertext plus public slots, never an account/storage root or a factor. This
// record pins code-authenticated preparation; it proves no SQL commit/admission.
type sharedJoinStartup struct {
	FormatVersion uint16                `json:"formatVersion"`
	Purpose       string                `json:"purpose"`
	PathDigest    []byte                `json:"pathDigest"`
	Binding       sharedpg.TrustBinding `json:"binding"`
	LoginName     string                `json:"loginName"`
	DeviceFile    []byte                `json:"deviceFile"`
	Transport     []byte                `json:"transport,omitempty"`
	Pending       []byte                `json:"pending,omitempty"`
	Continuation  []byte                `json:"continuation,omitempty"`
}

func sharedJoinStartupPath(path string) string { return path + ".join-startup" }

func requireNoSharedJoinStartup(path string) error {
	_, err := os.Lstat(sharedJoinStartupPath(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errSharedTrustStorage
	}
	return errSharedTrustConflict
}

func (p sharedJoinStartup) valid(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	switch p.FormatVersion {
	case 1:
		if p.Purpose != "wormhole/shared-join-startup/v1" || len(p.Transport) != 0 || len(p.Pending) != 0 || len(p.Continuation) != 0 {
			return false
		}
	case 2:
		if p.Purpose != "wormhole/shared-join-startup/v2" || len(p.Continuation) != 0 {
			return false
		}
	case 3:
		if p.Purpose != "wormhole/shared-join-startup/v3" || len(p.Continuation) == 0 || len(p.Continuation) > 2*sharedpg.MaxInvitationContinuationBytes {
			return false
		}
	case 4:
		if p.Purpose != "wormhole/shared-account-reset/v1" || len(p.Continuation) != 0 ||
			len(p.Pending) == 0 || len(p.Pending) > sharedpg.MaxResetDeviceCheckpointBytes {
			return false
		}
	default:
		return false
	}
	if p.FormatVersion >= 2 && (len(p.Transport) == 0 || len(p.Transport) > 2*sharedpg.MaxTransportSnapshotBytes ||
		len(p.Pending) == 0 || (p.FormatVersion != 4 && len(p.Pending) > sharedpg.MaxPendingEnrollmentBytes)) {
		return false
	}
	digest := sha256.Sum256([]byte(path))
	if !bytes.Equal(p.PathDigest, digest[:]) {
		return false
	}
	b := p.Binding
	if b.WorkspaceID == uuid.Nil || b.UserID == uuid.Nil || b.DeviceID == uuid.Nil || b.KeyID == uuid.Nil || b.KeyVersion == 0 {
		return false
	}
	if _, err := vault.SharedSalt(b.WorkspaceID.String(), p.LoginName); err != nil {
		return false
	}
	if strings.IndexFunc(p.LoginName, unicode.IsControl) >= 0 {
		return false
	}
	slots, _, err := sharedpg.DecodeDeviceEnrollmentFile(p.DeviceFile)
	if err != nil || slots.Encrypted || slots.Initializing || slots.Migration != nil || slots.Rotation != nil {
		return false
	}
	password := false
	for _, slot := range slots.Slots {
		switch slot.Kind {
		case vault.SlotPassword:
			parameters, err := vault.Parameters(slot.Preset)
			floor, _ := vault.Parameters(vault.KDFV1)
			if err != nil || parameters.MemoryKiB < floor.MemoryKiB || parameters.Iterations < floor.Iterations {
				return false
			}
			password = true
		case vault.SlotRecovery:
		default:
			return false
		}
	}
	return password
}

func makeSharedJoinStartup(o sharedAdmissionOptions, d *sharedJoinDeviceStorage) (sharedJoinStartup, error) {
	if d == nil {
		return sharedJoinStartup{}, sharedpg.ErrConfiguration
	}
	metadata, err := sharedpg.OpenDeviceEnrollment(d.root, d.slots, d.slots.VaultID, d.slots.FileID, d.slots.Sequence, d.envelope)
	if err != nil {
		return sharedJoinStartup{}, err
	}
	if metadata.Binding() != o.Binding {
		return sharedJoinStartup{}, sharedpg.ErrConfiguration
	}
	derivation, policy, err := metadata.Derivation(o.OSFloor, o.UserFloor)
	if err != nil {
		return sharedJoinStartup{}, err
	}
	if err := validateSharedAccountDerivation(policy, derivation.EffectiveProfile, derivation.Preset, derivation.ASKRequired); err != nil {
		return sharedJoinStartup{}, err
	}
	raw, err := sharedpg.EncodeDeviceEnrollmentFile(d.root, d.slots, d.envelope)
	if err != nil {
		return sharedJoinStartup{}, err
	}
	digest := sha256.Sum256([]byte(o.TrustPath))
	p := sharedJoinStartup{FormatVersion: 1, Purpose: "wormhole/shared-join-startup/v1", PathDigest: digest[:], Binding: o.Binding, LoginName: derivation.LoginName, DeviceFile: raw}
	if !p.valid(o.TrustPath) {
		return sharedJoinStartup{}, sharedpg.ErrConfiguration
	}
	return p, nil
}

func readSharedJoinStartup(path string, protection sharedStartupProtection) (sharedJoinStartup, error) {
	if !filepath.IsAbs(path) || protection.unprotect == nil {
		return sharedJoinStartup{}, sharedpg.ErrConfiguration
	}
	sealed, err := readSharedTrustBytes(sharedJoinStartupPath(path), 2*maxSharedJoinStartupBytes)
	if err != nil {
		return sharedJoinStartup{}, err
	}
	if len(sealed) == 0 || len(sealed) > 2*maxSharedJoinStartupBytes {
		return sharedJoinStartup{}, errSharedTrustStorage
	}
	raw, err := protection.unprotect(sharedJoinStartupPath(path), sealed)
	defer vault.Wipe(raw)
	if err != nil || len(raw) == 0 || len(raw) > maxSharedJoinStartupBytes {
		return sharedJoinStartup{}, errSharedTrustStorage
	}
	var p sharedJoinStartup
	if json.Unmarshal(raw, &p) != nil || !p.valid(path) {
		return sharedJoinStartup{}, errSharedTrustStorage
	}
	canonical, err := json.Marshal(p)
	if err != nil || !bytes.Equal(canonical, raw) {
		return sharedJoinStartup{}, errSharedTrustStorage
	}
	return p, nil
}

// Creation and exact confirmation share one durable writer. Matching readback
// never acknowledges an uncertain directory sync. Confirmation cannot adopt a
// missing or competing record, even after local intent has been staged.
func writeSharedJoinStartup(ctx context.Context, path string, p sharedJoinStartup, protection sharedStartupProtection, confirm bool) error {
	if ctx == nil || !p.valid(path) || protection.protect == nil || protection.unprotect == nil {
		return sharedpg.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return errSharedTrustStorage
	}
	release, err := tryAcquireExclusiveFileLock(path + ".lock")
	if err != nil {
		return errSharedTrustConflict
	}
	defer release()
	if err := requireMissingSharedTrust(path); err != nil {
		return err
	}
	if err := requireNoSharedTrustTransition(path); err != nil {
		return err
	}
	if confirm {
		actual, err := readSharedJoinStartup(path, protection)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(actual, p) {
			return errSharedTrustConflict
		}
	} else {
		for _, destination := range []string{sharedJoinStartupPath(path), sharedStartupAnchorPath(path), sharedDeviceEnrollmentPath(path), sharedTransportSetupPath(path), sharedPendingEnrollmentPath(path)} {
			if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
				if err != nil {
					return errSharedTrustStorage
				}
				return errSharedTrustConflict
			}
		}
	}
	return persistSharedJoinStartupValue(ctx, path, p, protection)
}

// Callers establish the exact identity/state under the trust lock first.
func persistSharedJoinStartupValue(ctx context.Context, path string, p sharedJoinStartup, protection sharedStartupProtection) error {
	if ctx == nil {
		return sharedpg.ErrConfiguration
	}
	sealed, err := sealSharedJoinStartupValue(path, p, protection)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return persistSharedTransitionBytes(sharedJoinStartupPath(path), sealed)
}

// Bind protection to the final name even while constructing an unpublished bundle.
func sealSharedJoinStartupValue(path string, p sharedJoinStartup, protection sharedStartupProtection) ([]byte, error) {
	if !p.valid(path) || protection.protect == nil {
		return nil, sharedpg.ErrConfiguration
	}
	raw, err := json.Marshal(p)
	defer vault.Wipe(raw)
	if err != nil || len(raw) > maxSharedJoinStartupBytes {
		return nil, errSharedTrustStorage
	}
	sealed, err := protection.protect(sharedJoinStartupPath(path), raw)
	if err != nil || len(sealed) == 0 || len(sealed) > 2*maxSharedJoinStartupBytes {
		return nil, errSharedTrustStorage
	}
	return sealed, nil
}

// The caller holds the trust-file lock and has durably published a normal
// startup anchor from independently confirmed active trust. Never erase a
// replaced initial selection, including after an uncertain earlier publication.
func removeSharedJoinStartupLocked(path string, expected sharedJoinStartup, protection sharedStartupProtection) error {
	actual, err := readSharedJoinStartup(path, protection)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, expected) {
		return errSharedTrustConflict
	}
	if err := os.Remove(sharedJoinStartupPath(path)); err != nil {
		return errSharedTrustStorage
	}
	if err := privateFileDirectorySync(filepath.Dir(path)); err != nil {
		return errSharedTrustCommitUncertain
	}
	return nil
}
