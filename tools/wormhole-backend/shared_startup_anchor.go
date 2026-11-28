package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const maxSharedStartupAnchorBytes = sharedpg.MaxTransportSnapshotBytes + sharedpg.MaxTrustStateBytes + 128*1024

// Only public enrollment/transport facts. OS protection authenticates their
// provenance independently of the password slot; it never stores account keys.
type sharedStartupAnchor struct {
	FormatVersion   uint16                `json:"formatVersion"`
	Purpose         string                `json:"purpose"`
	PathDigest      []byte                `json:"pathDigest"`
	Revision        uint64                `json:"revision"`
	VaultID         string                `json:"vaultId"`
	FileID          string                `json:"fileId"`
	MinimumSequence uint64                `json:"minimumSequence"`
	Binding         sharedpg.TrustBinding `json:"binding"`
	LoginName       string                `json:"loginName"`
	DisplayName     string                `json:"displayName"`
	KDF             vault.KDFPreset       `json:"kdf"`
	ASKRequired     bool                  `json:"askRequired"`
	Trust           sharedpg.TrustState   `json:"trust"`
	Transport       json.RawMessage       `json:"transport"`
}

type sharedStartupProtection struct {
	protect   func(string, []byte) ([]byte, error)
	unprotect func(string, []byte) ([]byte, error)
}

func nativeSharedStartupProtection() sharedStartupProtection {
	return sharedStartupProtection{protectFileContents, unprotectFileContents}
}

func sharedStartupAnchorPath(path string) string { return path + ".startup" }

func (a sharedStartupAnchor) valid(path string) bool {
	if !filepath.IsAbs(path) || a.FormatVersion != 1 || a.Purpose != "wormhole/shared-startup/v1" || a.Revision == 0 || a.Revision > math.MaxInt64 || a.MinimumSequence == 0 {
		return false
	}
	digest := sha256.Sum256([]byte(filepath.Clean(path)))
	if !bytes.Equal(a.PathDigest, digest[:]) {
		return false
	}
	for _, id := range []string{a.VaultID, a.FileID} {
		u, err := uuid.Parse(id)
		if err != nil || u == uuid.Nil || u.String() != id {
			return false
		}
	}
	b := a.Binding
	if b.WorkspaceID == uuid.Nil || b.UserID == uuid.Nil || b.DeviceID == uuid.Nil || b.KeyID == uuid.Nil || b.KeyVersion == 0 || a.Trust.WorkspaceID != b.WorkspaceID || a.Trust.UserID != b.UserID || a.Trust.DeviceID != b.DeviceID {
		return false
	}
	if len(a.DisplayName) == 0 || len(a.DisplayName) > 256 || !utf8.ValidString(a.DisplayName) || strings.IndexFunc(a.DisplayName, unicode.IsControl) >= 0 {
		return false
	}
	if _, err := vault.SharedSalt(b.WorkspaceID.String(), a.LoginName); err != nil {
		return false
	}
	policy, err := a.Trust.Policy()
	if err != nil || a.Trust.Account == nil || a.Trust.Enrollment == nil || policy.MinAPI > math.MaxInt32 {
		return false
	}
	if validateSharedAccountDerivation(policy, vault.EffectiveProfile(vault.Default, policy.Profile, a.Trust.PersonalProfile()), a.KDF, a.ASKRequired) != nil {
		return false
	}
	_, err = sharedpg.DecodeTransportSnapshot(a.Transport, a.Trust, vault.Default, vault.Default, int32(policy.MinAPI))
	return err == nil
}

func readSharedStartupAnchor(path string, protection sharedStartupProtection) (sharedStartupAnchor, error) {
	if !filepath.IsAbs(path) || protection.unprotect == nil {
		return sharedStartupAnchor{}, sharedpg.ErrConfiguration
	}
	protected, err := readSharedTrustBytes(sharedStartupAnchorPath(path), int64(maxSharedStartupAnchorBytes*2))
	if err != nil {
		return sharedStartupAnchor{}, err
	}
	if len(protected) > maxSharedStartupAnchorBytes*2 {
		return sharedStartupAnchor{}, errSharedTrustStorage
	}
	raw, err := protection.unprotect(sharedStartupAnchorPath(path), protected)
	if err != nil {
		return sharedStartupAnchor{}, errSharedTrustStorage
	}
	defer vault.Wipe(raw)
	if len(raw) == 0 || len(raw) > maxSharedStartupAnchorBytes {
		return sharedStartupAnchor{}, errSharedTrustStorage
	}
	var anchor sharedStartupAnchor
	if json.Unmarshal(raw, &anchor) != nil || !anchor.valid(path) {
		return sharedStartupAnchor{}, errSharedTrustStorage
	}
	canonical, err := json.Marshal(anchor)
	if err != nil || !bytes.Equal(canonical, raw) {
		return sharedStartupAnchor{}, errSharedTrustStorage
	}
	return anchor, nil
}

func startupAnchorAdvances(previous, next sharedStartupAnchor) bool {
	if previous.Revision == math.MaxInt64 || next.Revision != previous.Revision+1 || previous.Binding != next.Binding || previous.VaultID != next.VaultID || previous.FileID != next.FileID || next.MinimumSequence < previous.MinimumSequence || previous.LoginName != next.LoginName || previous.KDF != next.KDF || previous.ASKRequired != next.ASKRequired || next.Trust.Revision < previous.Trust.Revision {
		return false
	}
	if next.Trust.Revision == previous.Trust.Revision {
		return reflect.DeepEqual(previous.Trust, next.Trust)
	}
	// Multiple authenticated observations may have occurred since the last
	// startup snapshot. Normalize only the local CAS counter for floor validation.
	state := next.Trust
	state.Revision = previous.Trust.Revision + 1
	return previous.Trust.ValidateAdvance(state) == nil
}

// Update only from an unlocked native owner and the active protected files.
// Never accept a serialized anchor or transport settings from the renderer.
// expected=0 registers; exact replay confirms an uncertain directory sync.
func writeSharedStartupAnchor(ctx context.Context, o sharedAdmissionOptions, account *sharedpg.UnlockedDeviceAccount, displayName string, expected uint64, protection sharedStartupProtection) (sharedStartupAnchor, error) {
	if ctx == nil || !filepath.IsAbs(o.TrustPath) || account == nil || expected >= math.MaxInt64 || protection.protect == nil || protection.unprotect == nil {
		return sharedStartupAnchor{}, sharedpg.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return sharedStartupAnchor{}, err
	}
	release, err := tryAcquireExclusiveFileLock(o.TrustPath + ".lock")
	if err != nil {
		return sharedStartupAnchor{}, errSharedTrustConflict
	}
	defer release()
	if err := requireNoSharedPendingEnrollment(o.TrustPath); err != nil {
		return sharedStartupAnchor{}, err
	}
	if err := requireNoSharedTrustTransition(o.TrustPath); err != nil {
		return sharedStartupAnchor{}, err
	}
	var anchor sharedStartupAnchor
	var initial *sharedJoinStartup
	err = account.BorrowDeviceStorage(func(key, file []byte) error {
		actual, e := readSharedTrustBytes(sharedDeviceEnrollmentPath(o.TrustPath), sharedpg.MaxDeviceEnrollmentFileBytes)
		if e != nil {
			return e
		}
		if !bytes.Equal(file, actual) {
			return errSharedTrustConflict
		}
		slots, envelope, e := sharedpg.DecodeDeviceEnrollmentFile(file)
		if e != nil {
			return e
		}
		metadata, e := sharedpg.OpenDeviceEnrollment(key, slots, slots.VaultID, slots.FileID, slots.Sequence, envelope)
		if e != nil {
			return e
		}
		return account.Borrow(func(master *sharedpg.AccountMaster, root *sharedpg.DeviceTrustRoot) error {
			if root.Binding() != o.Binding || metadata.Binding() != o.Binding {
				return sharedpg.ErrConfiguration
			}
			candidate, e := readSharedJoinStartup(o.TrustPath, protection)
			if !errors.Is(e, errSharedTrustMissing) {
				if e != nil {
					return e
				}
				if candidate.Binding != o.Binding || candidate.LoginName != master.LoginName() || !bytes.Equal(candidate.DeviceFile, file) {
					return errSharedTrustConflict
				}
				initial = &candidate
			}
			return root.Use(func(rootKey []byte) error {
				trust, e := readSharedTrustFile(o.TrustPath, rootKey, o.Binding, o.MinimumRevision)
				if e != nil {
					return e
				}
				settings, e := readSharedTransportSetup(o, rootKey, trust)
				if e != nil {
					return e
				}
				transport, e := sharedpg.EncodeTransportSnapshot(settings, trust, o.OSFloor, o.UserFloor, o.Request.API)
				if e != nil {
					return e
				}
				digest := sha256.Sum256([]byte(filepath.Clean(o.TrustPath)))
				anchor = sharedStartupAnchor{FormatVersion: 1, Purpose: "wormhole/shared-startup/v1", PathDigest: digest[:], Revision: expected + 1, VaultID: slots.VaultID, FileID: slots.FileID, MinimumSequence: slots.Sequence, Binding: o.Binding, LoginName: master.LoginName(), DisplayName: displayName, Trust: trust, Transport: transport}
				return master.Use(func(_ []byte, preset vault.KDFPreset, ask bool) error {
					anchor.KDF, anchor.ASKRequired = preset, ask
					return nil
				})
			})
		})
	})
	if err != nil {
		return sharedStartupAnchor{}, err
	}
	if !anchor.valid(o.TrustPath) {
		return sharedStartupAnchor{}, sharedpg.ErrConfiguration
	}
	previous, err := readSharedStartupAnchor(o.TrustPath, protection)
	if errors.Is(err, errSharedTrustMissing) {
		if expected != 0 {
			return sharedStartupAnchor{}, errSharedTrustConflict
		}
	} else if err != nil {
		return sharedStartupAnchor{}, err
	} else if !reflect.DeepEqual(previous, anchor) && (expected == 0 || previous.Revision != expected || !startupAnchorAdvances(previous, anchor)) {
		return sharedStartupAnchor{}, errSharedTrustConflict
	}
	raw, err := json.Marshal(anchor)
	if err != nil || len(raw) > maxSharedStartupAnchorBytes {
		return sharedStartupAnchor{}, errSharedTrustStorage
	}
	defer vault.Wipe(raw)
	protected, err := protection.protect(sharedStartupAnchorPath(o.TrustPath), raw)
	if err != nil || len(protected) == 0 || len(protected) > maxSharedStartupAnchorBytes*2 {
		return sharedStartupAnchor{}, errSharedTrustStorage
	}
	if err := ctx.Err(); err != nil {
		return sharedStartupAnchor{}, err
	}
	if err := persistSharedTransitionBytes(sharedStartupAnchorPath(o.TrustPath), protected); err != nil {
		return anchor, err
	}
	if initial != nil {
		if err := removeSharedJoinStartupLocked(o.TrustPath, *initial, protection); err != nil {
			return anchor, err
		}
	}
	return anchor, nil
}
