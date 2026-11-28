package localvault

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const bitwardenInstallationKind = "bitwarden-installation"

// BitwardenInstallation is native-only admission metadata, not proof that the
// installed files are intact or the Chromium profile is protected. InstallationID
// selects a native-owned directory; untrusted settings paths are never stored here.
type BitwardenInstallation struct {
	Enabled        bool   `json:"enabled"`
	InstallationID string `json:"installationId"`
	ExtensionID    string `json:"extensionId"`
	ContentSHA256  string `json:"contentSha256"`
	Layout         int    `json:"layout,omitempty"`
}

type bitwardenInstallationRecord struct {
	Version      int                   `json:"version"`
	Installation BitwardenInstallation `json:"installation"`
	Retired      []string              `json:"retired,omitempty"`
}

// Layout 0 is the legacy shared root; layout 1 is the database-scoped root.
func (v BitwardenInstallation) valid() bool {
	if v.Layout < 0 || v.Layout > 1 {
		return false
	}
	if v.InstallationID == "" {
		return !v.Enabled && v.ExtensionID == "" && v.ContentSHA256 == "" && v.Layout == 0
	}
	id, err := uuid.Parse(v.InstallationID)
	if err != nil || id == uuid.Nil || id.String() != v.InstallationID || len(v.ExtensionID) != 32 || len(v.ContentSHA256) != 64 {
		return false
	}
	for _, c := range v.ExtensionID {
		if c < 'a' || c > 'p' {
			return false
		}
	}
	digest, err := hex.DecodeString(v.ContentSHA256)
	return err == nil && hex.EncodeToString(digest) == v.ContentSHA256
}

// ReadBitwardenInstallation reauthenticates policy and the encrypted record. A
// missing initial record disables the extension; deletion after observation is
// rollback, never permission to import legacy settings or choose another path.
func (o *Owner) ReadBitwardenInstallation(ctx context.Context, minimum uint64) (BitwardenInstallation, uint64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.readBitwardenInstallation(ctx, minimum)
}

func (o *Owner) readBitwardenInstallation(ctx context.Context, minimum uint64) (BitwardenInstallation, uint64, error) {
	record, revision, err := o.readBitwardenInstallationRecord(ctx, minimum)
	return record.Installation, revision, err
}

func (o *Owner) readBitwardenInstallationRecord(ctx context.Context, minimum uint64) (bitwardenInstallationRecord, uint64, error) {
	var result bitwardenInstallationRecord
	if _, err := o.readSecurityProfile(ctx); err != nil {
		return result, 0, err
	}
	minimum = max(minimum, o.bitwardenInstallationFloor)
	scope := o.store.Identity().WorkspaceID
	state, err := o.readLocalState(ctx, bitwardenInstallationKind, scope)
	if errors.Is(err, vaultstore.ErrMissing) {
		if minimum != 0 {
			return result, 0, vault.ErrRollback
		}
		return result, 0, nil
	}
	if err != nil {
		return result, 0, err
	}
	if state.RowVersion < minimum {
		return result, 0, vault.ErrRollback
	}
	if state.Deleted {
		return result, 0, vault.ErrPolicy
	}
	if state.Size > 4096 {
		return result, 0, vault.ErrFormat
	}
	err = o.withLocalState(ctx, bitwardenInstallationKind, scope, state.RowVersion, func(raw []byte) error {
		var record bitwardenInstallationRecord
		if json.Unmarshal(raw, &record) != nil || !record.valid() {
			return vault.ErrFormat
		}
		canonical, e := json.Marshal(record)
		if e != nil || !bytes.Equal(raw, canonical) {
			return vault.ErrFormat
		}
		result = record
		return nil
	})
	if err != nil {
		return bitwardenInstallationRecord{}, 0, err
	}
	o.bitwardenInstallationFloor = state.RowVersion
	return result, state.RowVersion, nil
}

// SaveBitwardenInstallation must be called only after native installation trust
// verification and action authorization. It cannot replace an installation while
// browser profiles retain state. Disabling preserves an authenticated revision.
func (o *Owner) SaveBitwardenInstallation(ctx context.Context, value BitwardenInstallation, expected uint64) (uint64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !value.valid() {
		return 0, vault.ErrFormat
	}
	if o.bitwardenInstallationBusy() {
		return 0, vault.ErrPolicy
	}
	record, revision, err := o.readBitwardenInstallationRecord(ctx, expected)
	if err != nil {
		return 0, err
	}
	if revision != expected {
		return 0, vaultstore.ErrConflict
	}
	// Only scoped packages are owned by this database's installation namespace.
	// The old ID and replacement commit together; a failed CAS cannot retire it.
	for _, id := range record.Retired {
		if id == value.InstallationID {
			return 0, vault.ErrPolicy
		}
	}
	previous := record.Installation
	if previous.Layout == 1 && previous.InstallationID != "" && previous.InstallationID != value.InstallationID {
		if len(record.Retired) >= bitwardenMaxRetiredInstallations {
			return 0, vault.ErrPolicy
		}
		record.Retired = append(record.Retired, previous.InstallationID)
	}
	record.Installation = value
	return o.writeBitwardenInstallationRecord(ctx, record, expected)
}

func (o *Owner) bitwardenInstallationBusy() bool {
	return len(o.bitwardenTransfers) != 0 || (o.bitwarden != nil && len(o.bitwarden.Profiles) != 0)
}

func (o *Owner) writeBitwardenInstallationRecord(ctx context.Context, record bitwardenInstallationRecord, expected uint64) (uint64, error) {
	record.Version = 1 + record.Installation.Layout
	if len(record.Retired) != 0 {
		record.Version = 3
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return 0, vault.ErrFormat
	}
	defer vault.Wipe(raw)
	state, err := o.writeLocalState(ctx, bitwardenInstallationKind, o.store.Identity().WorkspaceID, raw, expected, false)
	if err != nil {
		return 0, err
	}
	o.bitwardenInstallationFloor = state.RowVersion
	return state.RowVersion, nil
}
