package vault

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/google/uuid"
)

const MaxSlotFileBytes = 2 * 1024 * 1024

// Slot container v3 adds an authenticated local root-rotation barrier. Secret envelopes
// remain format v1. Older readers identify a newer container before parsing it.
const SlotFileFormatVersion = 3

// v4 is transient and limited to OS-custody legacy migration. Completed
// documents use v3 again; ordinary opening still rejects migration markers.
const SlotFileUnprotectedMigrationVersion = 4

// v5 authenticates an optional Windows Hello key fingerprint and the observed
// attestation availability. An older reader refuses the container before unlock.
const SlotFileHelloVersion = 5

// v6 adds a device-only Keychain factor for Touch ID.
const SlotFileTouchIDVersion = 6

// v7 distinguishes verified TPM evidence from an availability-only result.
const SlotFileTPMAttestationVersion = 7

func MigrationSlotFile(document SlotFile, state *LocalMigration) SlotFile {
	document.Migration = state
	if len(document.Slots) == 1 && document.Slots[0].Kind == SlotUnprotected {
		if state != nil && document.FormatVersion == SlotFileFormatVersion {
			document.FormatVersion = SlotFileUnprotectedMigrationVersion
		} else if state == nil && document.FormatVersion == SlotFileUnprotectedMigrationVersion {
			document.FormatVersion = SlotFileFormatVersion
		}
	}
	return document
}

var ErrKeyCheck = errors.New("vault_key_check_mismatch")

type NodeHighWater struct {
	NodeID   string `json:"nodeId"`
	Revision uint64 `json:"revision"`
}
type TunnelHighWater struct {
	TunnelID string `json:"tunnelId"`
	Revision uint64 `json:"revision"`
}

// SlotFile contains ciphertext and authenticated metadata only. It is outside
// SQLite so authentication can finish before SQLite is allowed to open a file.
// The MAC also covers the slot set and high-water marks, preventing an attacker
// from removing protection or loosening a floor independently of the database.
type SlotFile struct {
	FormatVersion   uint16             `json:"formatVersion"`
	VaultID         string             `json:"vaultId"`
	FileID          string             `json:"fileId"`
	RootKeyID       string             `json:"rootKeyId"`
	RootKeyVersion  uint32             `json:"rootKeyVersion"`
	Initializing    bool               `json:"initializing"`
	Migration       *LocalMigration    `json:"migration,omitempty"`
	Rotation        *LocalRootRotation `json:"rotation,omitempty"`
	Sequence        uint64             `json:"sequence"`
	Encrypted       bool               `json:"encrypted"`
	Slots           []Slot             `json:"slots"`
	KeyCheck        []byte             `json:"keyCheck"`
	ProfileSequence uint64             `json:"profileSequence"`
	FileEpoch       uint64             `json:"fileEpoch"`
	Nodes           []NodeHighWater    `json:"nodes"`
	VPNSSO          []VPNSSOHighWater  `json:"vpnSso,omitempty"`
	Tunnels         []TunnelHighWater  `json:"tunnels,omitempty"`
	Authentication  []byte             `json:"authentication"`
}

type SlotDescriptor struct {
	ID     string    `json:"id"`
	Kind   SlotKind  `json:"kind"`
	Preset KDFPreset `json:"preset,omitempty"`
}

// This pre-unlock projection is untrusted until VerifySlotFile succeeds. It
// must never select policy or claim protection; it contains no key material.
type SlotFileDescriptor struct {
	FormatVersion uint16           `json:"formatVersion"`
	VaultID       string           `json:"vaultId"`
	Encrypted     bool             `json:"encrypted"`
	Slots         []SlotDescriptor `json:"slots"`
}

func canonicalID(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed != uuid.Nil && parsed.String() == id
}

func (f SlotFile) validate() error {
	if f.FormatVersion > SlotFileTPMAttestationVersion {
		return ErrNewerFormat
	}
	if f.FormatVersion < 1 || (f.FormatVersion == 1 && (len(f.VPNSSO) != 0 || len(f.Tunnels) != 0)) || !canonicalID(f.VaultID) || !canonicalID(f.FileID) || !canonicalID(f.RootKeyID) || f.RootKeyVersion == 0 || f.Sequence == 0 || f.FileEpoch == 0 || len(f.KeyCheck) != 32 || len(f.Slots) == 0 || len(f.Slots) > 16 || len(f.Nodes) > 10000 || len(f.VPNSSO) > 1024 || len(f.Tunnels) > 10000 {
		return ErrFormat
	}
	if f.Migration != nil && (f.Initializing || f.Encrypted || !f.Migration.valid()) {
		return ErrFormat
	}
	if f.FormatVersion == SlotFileUnprotectedMigrationVersion && (f.Migration == nil || len(f.Slots) != 1 || f.Slots[0].Kind != SlotUnprotected) {
		return ErrFormat
	}
	if f.Rotation != nil && (f.FormatVersion < 3 || f.Initializing || f.Migration != nil || !f.Rotation.valid(f.RootKeyVersion)) {
		return ErrFormat
	}
	if f.Rotation != nil && f.Rotation.Pending != nil {
		pending := f
		pending.RootKeyVersion = f.Rotation.TargetRootVersion
		pending.Encrypted = true
		pending.Slots = f.Rotation.Pending.Slots
		pending.KeyCheck = f.Rotation.Pending.KeyCheck
		pending.Rotation = nil
		if err := pending.validate(); err != nil {
			return err
		}
		for _, slot := range pending.Slots {
			if slot.WrappedKey.KeyVersion != pending.RootKeyVersion {
				return ErrFormat
			}
		}
	}
	seen := make(map[string]bool, len(f.Slots))
	var recovery, password, hello, touchID bool
	for _, slot := range f.Slots {
		if !canonicalID(slot.ID) || seen[slot.ID] || len(slot.FactorIDs) != 0 || (slot.Kind != SlotHello && slot.Hello != nil) {
			return ErrFormat
		}
		seen[slot.ID] = true
		switch slot.Kind {
		case SlotPassword:
			password = password || slot.WrappedKey.KeyVersion == f.RootKeyVersion
			if _, err := Parameters(slot.Preset); err != nil || len(slot.Salt) != 32 {
				return ErrFormat
			}
		case SlotRecovery:
			recovery = recovery || slot.WrappedKey.KeyVersion == f.RootKeyVersion
			if slot.Preset != "" || len(slot.Salt) != 0 || slot.ASKRequired {
				return ErrFormat
			}
		case SlotUnprotected:
			// v3 can authenticate a single OS-custody source for forward root
			// rotation. Decoding grants neither OS access nor ordinary unlock.
			if f.FormatVersion < 3 || f.Encrypted || (f.Migration != nil && f.FormatVersion != SlotFileUnprotectedMigrationVersion) || len(f.Slots) != 1 || slot.Preset != "" || len(slot.Salt) != 0 || slot.ASKRequired {
				return ErrFormat
			}
		case SlotHello:
			if hello || f.FormatVersion < SlotFileHelloVersion || f.Initializing || f.Migration != nil ||
				slot.WrappedKey.KeyVersion != f.RootKeyVersion || !slot.validHello() ||
				(slot.Hello.Attestation == HelloAttestationTPMVerified && f.FormatVersion < SlotFileTPMAttestationVersion) {
				return ErrFormat
			}
			hello = true
		case SlotTouchID:
			if touchID || f.FormatVersion < SlotFileTouchIDVersion || f.Initializing || f.Migration != nil ||
				slot.WrappedKey.KeyVersion != f.RootKeyVersion || !slot.validTouchID() {
				return ErrFormat
			}
			touchID = true
		default:
			// Reserved platform/AND slots must not silently become password slots.
			return ErrFormat
		}
		binding := slotBinding(f.VaultID, slot)
		if _, err := binding.aad(); err != nil {
			return err
		}
		if err := validateEnvelope(binding, slot.WrappedKey); err != nil {
			return err
		}
		if len(slot.WrappedKey.Ciphertext) != 48 {
			return ErrFormat
		}
	}
	if (f.Encrypted && !recovery) || ((hello || touchID) && !password && !recovery) {
		return ErrPolicy
	}
	previous := ""
	for _, mark := range f.Nodes {
		if !canonicalID(mark.NodeID) || mark.NodeID <= previous || mark.Revision == 0 {
			return ErrFormat
		}
		previous = mark.NodeID
	}
	previous = ""
	for _, mark := range f.VPNSSO {
		if !mark.Valid() || mark.ScopeID <= previous {
			return ErrFormat
		}
		previous = mark.ScopeID
	}
	previous = ""
	for _, mark := range f.Tunnels {
		if !canonicalID(mark.TunnelID) || mark.TunnelID <= previous || mark.Revision == 0 {
			return ErrFormat
		}
		previous = mark.TunnelID
	}
	return nil
}

func slotFileMAC(key []byte, document SlotFile) ([]byte, error) {
	if err := document.validate(); err != nil {
		return nil, err
	}
	subkey, err := DeriveKey(key, []byte(document.VaultID), PurposeLocalSeal)
	if err != nil {
		return nil, err
	}
	defer Wipe(subkey)
	document.Authentication = nil
	body, err := json.Marshal(document)
	if err != nil || len(body) > MaxSlotFileBytes-128 {
		return nil, ErrFormat
	}
	mac := hmac.New(sha256.New, subkey)
	mac.Write(canonical("wormhole/v1/slot-file", body))
	return mac.Sum(nil), nil
}

func EncodeSlotFile(key []byte, document SlotFile) ([]byte, error) {
	check, err := KeyCheck(key, document.VaultID, document.FileID)
	if err != nil {
		return nil, err
	}
	document.KeyCheck = check
	document.Authentication, err = slotFileMAC(key, document)
	if err != nil {
		return nil, err
	}
	return json.Marshal(document)
}

// DecodeSlotFile rejects alternate structural interpretations before either a
// descriptor or a costly KDF is exposed. Payload values remain unauthenticated.
func DecodeSlotFile(raw []byte) (SlotFile, error) {
	if len(raw) > MaxSlotFileBytes || !utf8.Valid(raw) {
		return SlotFile{}, ErrFormat
	}
	version, unique := uniqueJSONFields(raw)
	if !unique {
		return SlotFile{}, ErrFormat
	}
	if version > SlotFileTPMAttestationVersion {
		return SlotFile{}, ErrNewerFormat
	}
	var document SlotFile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil || decoder.Decode(new(any)) != io.EOF || len(document.Authentication) != 32 {
		return SlotFile{}, ErrFormat
	}
	if err := document.validate(); err != nil {
		return SlotFile{}, err
	}
	// Go's decoder accepts case-insensitive field aliases. Check against a
	// canonical re-encoding's field names as well as duplicates, at every depth.
	canonicalBody, _ := json.Marshal(document)
	var supplied, expected any
	json.Unmarshal(raw, &supplied)
	json.Unmarshal(canonicalBody, &expected)
	if !sameJSONFields(supplied, expected) {
		return SlotFile{}, ErrFormat
	}
	return document, nil
}

func uniqueJSONFields(raw []byte) (uint64, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var version uint64
	var walk func(int) bool
	walk = func(depth int) bool {
		if depth > 16 {
			return false
		}
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for decoder.More() {
				name, err := decoder.Token()
				field, ok := name.(string)
				if err != nil || !ok || seen[field] {
					return false
				}
				seen[field] = true
				if depth == 0 && field == "formatVersion" {
					if decoder.Decode(&version) != nil {
						return false
					}
					continue
				}
				if !walk(depth + 1) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim('}')
		case json.Delim('['):
			for decoder.More() {
				if !walk(depth + 1) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim(']')
		default:
			_, delimiter := token.(json.Delim)
			return !delimiter
		}
	}
	valid := walk(0) && decoder.Decode(new(any)) == io.EOF
	return version, valid
}

func sameJSONFields(supplied, expected any) bool {
	switch value := supplied.(type) {
	case map[string]any:
		other, ok := expected.(map[string]any)
		if !ok {
			return false
		}
		for key, child := range value {
			corresponding, found := other[key]
			if !found || !sameJSONFields(child, corresponding) {
				return false
			}
		}
	case []any:
		other, ok := expected.([]any)
		if !ok || len(value) != len(other) {
			return false
		}
		for i, child := range value {
			if !sameJSONFields(child, other[i]) {
				return false
			}
		}
	}
	return true
}

func VerifySlotFile(key []byte, document SlotFile, vaultID, fileID string, minimumSequence uint64) error {
	if err := document.validate(); err != nil {
		return err
	}
	if document.VaultID != vaultID || document.FileID != fileID || VerifyKeyCheck(key, vaultID, fileID, document.KeyCheck) != nil {
		return ErrKeyCheck
	}
	mac, err := slotFileMAC(key, document)
	if err != nil {
		return err
	}
	if !hmac.Equal(mac, document.Authentication) {
		return ErrAuthentication
	}
	if document.Sequence < minimumSequence {
		return ErrRollback
	}
	return nil
}

func (f SlotFile) Descriptor() SlotFileDescriptor {
	descriptor := SlotFileDescriptor{FormatVersion: f.FormatVersion, VaultID: f.VaultID, Encrypted: f.Encrypted, Slots: make([]SlotDescriptor, len(f.Slots))}
	for i, slot := range f.Slots {
		descriptor.Slots[i] = SlotDescriptor{slot.ID, slot.Kind, slot.Preset}
	}
	return descriptor
}
