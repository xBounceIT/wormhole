package localvault

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const bitwardenIntentKind = "bitwarden-install-intent"

// Intent is native-only evidence for one interrupted installation. Namespace is
// the database basename hash, not a path. Each phase requires the caller to have
// confirmed the corresponding filesystem operation before advancing it.
type BitwardenInstallationIntent struct {
	ID                   string `json:"id"`
	Namespace            string `json:"namespace"`
	InstallationRevision uint64 `json:"installationRevision"`
	Phase                string `json:"phase"`
}

type bitwardenIntentRecord struct {
	Version int                          `json:"version"`
	Intent  *BitwardenInstallationIntent `json:"intent"`
}

func (v BitwardenInstallationIntent) valid() bool {
	id, err := uuid.Parse(v.ID)
	if err != nil || id == uuid.Nil || id.String() != v.ID || len(v.Namespace) != 64 || v.InstallationRevision >= math.MaxInt64 {
		return false
	}
	namespace, err := hex.DecodeString(v.Namespace)
	return err == nil && hex.EncodeToString(namespace) == v.Namespace && (v.Phase == "prepared" || v.Phase == "created" || v.Phase == "published")
}

func (o *Owner) readBitwardenIntent(ctx context.Context) (bitwardenIntentRecord, uint64, error) {
	var record bitwardenIntentRecord
	if _, err := o.readSecurityProfile(ctx); err != nil {
		return record, 0, err
	}
	scope := o.store.Identity().WorkspaceID
	state, err := o.readLocalState(ctx, bitwardenIntentKind, scope)
	if errors.Is(err, vaultstore.ErrMissing) {
		if o.bitwardenIntentFloor != 0 {
			return record, 0, vault.ErrRollback
		}
		return bitwardenIntentRecord{Version: 1}, 0, nil
	}
	if err != nil {
		return record, 0, err
	}
	if state.RowVersion < o.bitwardenIntentFloor {
		return record, 0, vault.ErrRollback
	}
	if state.Deleted || state.Size > 1024 {
		return record, 0, vault.ErrFormat
	}
	err = o.withLocalState(ctx, bitwardenIntentKind, scope, state.RowVersion, func(raw []byte) error {
		if json.Unmarshal(raw, &record) != nil || record.Version != 1 || (record.Intent != nil && !record.Intent.valid()) {
			return vault.ErrFormat
		}
		canonical, e := json.Marshal(record)
		if e != nil || !bytes.Equal(raw, canonical) {
			return vault.ErrFormat
		}
		return nil
	})
	if err != nil {
		return bitwardenIntentRecord{}, 0, err
	}
	o.bitwardenIntentFloor = state.RowVersion
	return record, state.RowVersion, nil
}

func (o *Owner) writeBitwardenIntent(ctx context.Context, intent *BitwardenInstallationIntent, expected uint64) (uint64, error) {
	raw, err := json.Marshal(bitwardenIntentRecord{Version: 1, Intent: intent})
	if err != nil {
		return 0, vault.ErrFormat
	}
	defer vault.Wipe(raw)
	state, err := o.writeLocalState(ctx, bitwardenIntentKind, o.store.Identity().WorkspaceID, raw, expected, false)
	if err != nil {
		return 0, err
	}
	o.bitwardenIntentFloor = state.RowVersion
	return state.RowVersion, nil
}

// Begin records intent before any files are created. Pending intent must first be
// resolved; replacement never discards recovery evidence or changes the active
// installation revision. The service serializes the complete filesystem action.
func (o *Owner) BeginBitwardenInstallationIntent(ctx context.Context, value BitwardenInstallationIntent) (uint64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !value.valid() || value.Phase != "prepared" {
		return 0, vault.ErrFormat
	}
	if o.bitwardenInstallationBusy() {
		return 0, vault.ErrPolicy
	}
	installation, revision, err := o.readBitwardenInstallationRecord(ctx, value.InstallationRevision)
	if err != nil {
		return 0, err
	}
	if revision != value.InstallationRevision {
		return 0, vaultstore.ErrConflict
	}
	if value.ID == installation.Installation.InstallationID {
		return 0, vault.ErrPolicy
	}
	for _, id := range installation.Retired {
		if id == value.ID {
			return 0, vault.ErrPolicy
		}
	}
	record, version, err := o.readBitwardenIntent(ctx)
	if err != nil {
		return 0, err
	}
	if record.Intent != nil {
		return 0, vault.ErrPolicy
	}
	return o.writeBitwardenIntent(ctx, &value, version)
}

func (o *Owner) AdvanceBitwardenInstallationIntent(ctx context.Context, value BitwardenInstallationIntent, expected uint64) (uint64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !value.valid() {
		return 0, vault.ErrFormat
	}
	record, version, err := o.readBitwardenIntent(ctx)
	if err != nil {
		return 0, err
	}
	if version != expected {
		return 0, vaultstore.ErrConflict
	}
	previous := record.Intent
	if previous == nil || previous.ID != value.ID || previous.Namespace != value.Namespace || previous.InstallationRevision != value.InstallationRevision || !(previous.Phase == "prepared" && value.Phase == "created" || previous.Phase == "created" && value.Phase == "published") {
		return 0, vault.ErrPolicy
	}
	return o.writeBitwardenIntent(ctx, &value, version)
}

// Resolve runs a trusted native reconciliation callback under owner exclusion.
// referenced is true when the package is active or recorded as retired; those
// files must be preserved. The callback must not reenter the owner. The serving
// protocol must not invoke recovery concurrently with an in-progress installation.
func (o *Owner) ResolveBitwardenInstallationIntent(ctx context.Context, namespace string, resolve func(context.Context, BitwardenInstallationIntent, bool) error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if resolve == nil {
		return vault.ErrFormat
	}
	if o.bitwardenInstallationBusy() {
		return vault.ErrPolicy
	}
	installation, _, err := o.readBitwardenInstallationRecord(ctx, 0)
	if err != nil {
		return err
	}
	record, version, err := o.readBitwardenIntent(ctx)
	if err != nil {
		return err
	}
	if record.Intent == nil {
		return nil
	}
	intent := *record.Intent
	if intent.Namespace != namespace {
		return vault.ErrPolicy
	}
	referenced := installation.Installation.InstallationID == intent.ID
	for _, id := range installation.Retired {
		referenced = referenced || id == intent.ID
	}
	if err = resolve(ctx, intent, referenced); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	_, err = o.writeBitwardenIntent(ctx, nil, version)
	return err
}
