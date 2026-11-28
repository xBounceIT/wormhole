package sharedpg

import (
	"bytes"
	"encoding/json"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const MaxDeviceEnrollmentBytes = 128 * 1024

// This payload is encrypted under a separate device slot root. It establishes
// the account binding/derivation only after the slot file and envelope have
// authenticated. It contains no password, ASK, master or account root.
type deviceEnrollmentRecord struct {
	FormatVersion uint16          `json:"formatVersion"`
	SlotSequence  uint64          `json:"slotSequence"`
	Binding       TrustBinding    `json:"binding"`
	LoginName     string          `json:"loginName"`
	KDF           vault.KDFPreset `json:"kdf"`
	ASKRequired   bool            `json:"askRequired"`
	Trust         TrustState      `json:"trust"`
}

// DeviceEnrollment is authenticated native metadata, not an active session or
// current server authorization. Current protected trust must still be checked
// during admission. It deliberately has no JSON representation of its fields.
type DeviceEnrollment struct{ record deviceEnrollmentRecord }

func (e *DeviceEnrollment) Binding() TrustBinding {
	if e == nil {
		return TrustBinding{}
	}
	return e.record.Binding
}

func (e *DeviceEnrollment) Derivation(osFloor, userFloor vault.Profile) (AccountDerivation, vault.Policy, error) {
	if e == nil {
		return AccountDerivation{}, vault.Policy{}, ErrConfiguration
	}
	p, err := e.record.Trust.Policy()
	if err != nil {
		return AccountDerivation{}, vault.Policy{}, err
	}
	profile := vault.EffectiveProfile(osFloor, p.Profile, userFloor)
	d := AccountDerivation{WorkspaceID: e.record.Binding.WorkspaceID, LoginName: e.record.LoginName, Preset: e.record.KDF, ASKRequired: e.record.ASKRequired, EffectiveProfile: profile}
	// Preserve the original account derivation. Silently upgrading its KDF here
	// would produce a different root and lose access to protected trust.
	actual := p
	actual.Profile, actual.KDF, actual.ASKRequired = profile, d.Preset, d.ASKRequired
	if err := actual.Validate(); err != nil {
		return AccountDerivation{}, vault.Policy{}, err
	}
	return d, p, nil
}

func (r deviceEnrollmentRecord) valid(sequence uint64) bool {
	if r.FormatVersion != 1 || r.SlotSequence != sequence || sequence == 0 || !r.Trust.matches(r.Binding) {
		return false
	}
	if _, err := r.Binding.binding(); err != nil {
		return false
	}
	if _, err := vault.SharedSalt(r.Binding.WorkspaceID.String(), r.LoginName); err != nil {
		return false
	}
	p, err := r.Trust.Policy()
	if err != nil {
		return false
	}
	actual := p
	actual.KDF, actual.ASKRequired = r.KDF, r.ASKRequired
	if actual.Validate() != nil || (p.ASKRequired && !r.ASKRequired) {
		return false
	}
	floor, _ := vault.Parameters(p.KDF)
	selected, err := vault.Parameters(r.KDF)
	return err == nil && selected.MemoryKiB >= floor.MemoryKiB && selected.Iterations >= floor.Iterations
}

func deviceEnrollmentBinding(slots vault.SlotFile) vault.Binding {
	return vault.Binding{WorkspaceID: slots.VaultID, Table: "SharedDeviceEnrollment", OwnerID: slots.FileID, Field: "account", KeyID: slots.RootKeyID, KeyVersion: slots.RootKeyVersion}
}

func deviceSlotsMeetDerivation(slots vault.SlotFile, preset vault.KDFPreset) bool {
	floor, err := vault.Parameters(preset)
	if err != nil {
		return false
	}
	for _, slot := range slots.Slots {
		if slot.Kind == vault.SlotRecovery {
			continue
		}
		if slot.Kind != vault.SlotPassword {
			return false
		}
		actual, err := vault.Parameters(slot.Preset)
		if err != nil || actual.MemoryKiB < floor.MemoryKiB || actual.Iterations < floor.Iterations {
			return false
		}
	}
	return len(slots.Slots) != 0
}

// SealDeviceEnrollment snapshots only facts from this live preparation. The
// independent storage root and already authenticated slots belong to native
// device storage, not to the account. Persist slots+this ciphertext atomically.
func (p *PreparedInitialEnrollment) SealDeviceEnrollment(storageRoot []byte, slots vault.SlotFile) (raw []byte, err error) {
	err = p.Borrow(func(master *AccountMaster, root *DeviceTrustRoot, commit *PreparedInvitationCommit) error {
		if err := commit.ValidateAccountMaster(master); err != nil {
			return err
		}
		raw, err = commit.SealDeviceEnrollment(storageRoot, slots, root.Binding())
		return err
	})
	return raw, err
}

// SealDeviceEnrollment accepts the independently selected native device binding.
// It uses the same derivation owner that produced this prepared commit.
func (p *PreparedInvitationCommit) SealDeviceEnrollment(storageRoot []byte, slots vault.SlotFile, b TrustBinding) (raw []byte, err error) {
	if err := vault.VerifySlotFile(storageRoot, slots, slots.VaultID, slots.FileID, slots.Sequence); err != nil {
		return nil, err
	}
	if p == nil {
		return nil, ErrConfiguration
	}
	if err := p.ValidateAccountMaster(p.master); err != nil {
		return nil, err
	}
	pending, err := p.PendingEnrollment(b)
	if err != nil {
		return nil, err
	}
	record := deviceEnrollmentRecord{FormatVersion: 1, SlotSequence: slots.Sequence, Binding: b, LoginName: p.master.LoginName(), KDF: pending.KDF, ASKRequired: pending.ASKRequired, Trust: pending.Trust}
	return sealDeviceEnrollmentRecord(storageRoot, slots, record)
}

func sealDeviceEnrollmentRecord(storageRoot []byte, slots vault.SlotFile, record deviceEnrollmentRecord) ([]byte, error) {
	if !record.valid(slots.Sequence) {
		return nil, ErrTrustState
	}
	if !deviceSlotsMeetDerivation(slots, record.KDF) {
		return nil, vault.ErrPolicy
	}
	plain, err := json.Marshal(record)
	if err != nil || len(plain) > MaxDeviceEnrollmentBytes/2 {
		return nil, ErrTrustState
	}
	defer vault.Wipe(plain)
	key, err := vault.DeriveKey(storageRoot, []byte(slots.FileID), vault.PurposeSharedDeviceSetup)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(key)
	envelope, err := vault.Seal(key, deviceEnrollmentBinding(slots), plain)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope)
}

// OpenDeviceEnrollment verifies the slot file against independent selection and
// its rollback floor before decrypting any account facts. Opening a password or
// recovery slot alone does not authenticate those facts. ASK is supplied through
// a separate protected native input; it is never placed in this record.
func OpenDeviceEnrollment(storageRoot []byte, slots vault.SlotFile, vaultID, fileID string, minimumSequence uint64, raw []byte) (*DeviceEnrollment, error) {
	if minimumSequence == 0 || len(raw) == 0 || len(raw) > MaxDeviceEnrollmentBytes {
		return nil, ErrConfiguration
	}
	if err := vault.VerifySlotFile(storageRoot, slots, vaultID, fileID, minimumSequence); err != nil {
		return nil, err
	}
	var envelope vault.Envelope
	if json.Unmarshal(raw, &envelope) != nil {
		return nil, ErrTrustState
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, ErrTrustState
	}
	key, err := vault.DeriveKey(storageRoot, []byte(slots.FileID), vault.PurposeSharedDeviceSetup)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(key)
	plain, err := vault.Open(key, deviceEnrollmentBinding(slots), envelope)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(plain)
	if len(plain) > MaxDeviceEnrollmentBytes/2 {
		return nil, ErrTrustState
	}
	var record deviceEnrollmentRecord
	if json.Unmarshal(plain, &record) != nil || !record.valid(slots.Sequence) {
		return nil, ErrTrustState
	}
	if !deviceSlotsMeetDerivation(slots, record.KDF) {
		return nil, vault.ErrPolicy
	}
	canonical, err = json.Marshal(record)
	defer vault.Wipe(canonical)
	if err != nil || !bytes.Equal(canonical, plain) {
		return nil, ErrTrustState
	}
	return &DeviceEnrollment{record: record}, nil
}
