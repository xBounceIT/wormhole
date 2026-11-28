package sharedpg

import (
	"bytes"
	"encoding/json"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const MaxDeviceEnrollmentFileBytes = vault.MaxSlotFileBytes + 2*MaxDeviceEnrollmentBytes

type deviceEnrollmentFile struct {
	FormatVersion uint16          `json:"formatVersion"`
	Slots         json.RawMessage `json:"slots"`
	Enrollment    json.RawMessage `json:"enrollment"`
}

// EncodeDeviceEnrollmentFile authenticates the complete pair before producing
// bytes for one atomic publication. The root is borrowed, never serialized.
func EncodeDeviceEnrollmentFile(storageRoot []byte, slots vault.SlotFile, enrollment []byte) ([]byte, error) {
	if _, err := OpenDeviceEnrollment(storageRoot, slots, slots.VaultID, slots.FileID, slots.Sequence, enrollment); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(slots)
	if err != nil || len(raw) > vault.MaxSlotFileBytes {
		return nil, ErrConfiguration
	}
	return json.Marshal(deviceEnrollmentFile{FormatVersion: 1, Slots: raw, Enrollment: enrollment})
}

// DecodeDeviceEnrollmentFile returns UNTRUSTED slots for native factor entry.
// No returned field may select account policy before OpenDeviceEnrollment has
// authenticated both the unlocked root and independently selected identity.
func DecodeDeviceEnrollmentFile(raw []byte) (vault.SlotFile, []byte, error) {
	fail := func() (vault.SlotFile, []byte, error) { return vault.SlotFile{}, nil, ErrConfiguration }
	if len(raw) == 0 || len(raw) > MaxDeviceEnrollmentFileBytes {
		return fail()
	}
	var file deviceEnrollmentFile
	if json.Unmarshal(raw, &file) != nil || file.FormatVersion != 1 || len(file.Enrollment) < 2 || len(file.Enrollment) > MaxDeviceEnrollmentBytes || file.Enrollment[0] != '{' {
		return fail()
	}
	canonical, err := json.Marshal(file)
	if err != nil || !bytes.Equal(raw, canonical) {
		return fail()
	}
	slots, err := vault.DecodeSlotFile(file.Slots)
	if err != nil {
		return vault.SlotFile{}, nil, err
	}
	return slots, bytes.Clone(file.Enrollment), nil
}
