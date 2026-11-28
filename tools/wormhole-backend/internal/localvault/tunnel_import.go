package localvault

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// Target binds temporary profile material to one editor's opening revision. A
// provider change may differ from the stored kind, but must be explicit at save.
type TunnelImportTarget struct {
	TunnelID   string
	RowVersion uint64
	Kind       int
}
type tunnelImportStage struct {
	EditorID string
	Target   TunnelImportTarget
	Expires  time.Time
	Envelope vault.Envelope
}

const maxTunnelImportStages = 8

func tunnelImportID(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed != uuid.Nil && parsed.String() == id
}
func (o *Owner) validateTunnelImportTarget(ctx context.Context, target TunnelImportTarget) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store, err := o.tunnelStore()
	if err != nil {
		return err
	}
	if target.Kind < 0 || target.Kind > 9 || target.RowVersion >= math.MaxInt64 || (target.TunnelID == "") != (target.RowVersion == 0) {
		return vault.ErrFormat
	}
	if target.TunnelID == "" {
		return nil
	}
	if !tunnelImportID(target.TunnelID) {
		return vault.ErrFormat
	}
	value, err := store.ReadTunnel(ctx, target.TunnelID)
	if err != nil {
		return err
	}
	if value.ID != target.TunnelID {
		return vault.ErrAuthentication
	}
	if err = o.verifyTunnel(value); err != nil {
		return err
	}
	if value.Deleted {
		return vaultstore.ErrMissing
	}
	if value.RowVersion != target.RowVersion {
		return vaultstore.ErrConflict
	}
	return nil
}
func (o *Owner) tunnelImportBinding(id string, stage tunnelImportStage) vault.Binding {
	identity := o.store.Identity()
	return vault.Binding{WorkspaceID: identity.WorkspaceID, Table: "EphemeralTunnelImports", OwnerID: stage.EditorID,
		Field: fmt.Sprintf("%s:%s:%d:%d:%d", identity.FileID, stage.Target.TunnelID, stage.Target.RowVersion, stage.Target.Kind, stage.Expires.UnixNano()), KeyID: id, KeyVersion: 1}
}
func (o *Owner) discardTunnelImport(id string) {
	stage := o.tunnelImports[id]
	vault.Wipe(stage.Envelope.Ciphertext)
	vault.Wipe(stage.Envelope.Nonce)
	delete(o.tunnelImports, id)
}
func (o *Owner) pruneTunnelImports(now time.Time) {
	for id, stage := range o.tunnelImports {
		if !now.Before(stage.Expires) {
			o.discardTunnelImport(id)
		}
	}
}

// StageTunnelImport consumes configuration on every return path. Only ciphertext
// survives the call; no temporary profiles, database records or keys are written.
// Replacing an editor's stage is atomic: a failed import preserves its old stage.
func (o *Owner) StageTunnelImport(ctx context.Context, editor, id string, target TunnelImportTarget, configuration []byte) error {
	defer vault.Wipe(configuration)
	o.mu.Lock()
	defer o.mu.Unlock()
	if !tunnelImportID(editor) || !tunnelImportID(id) || len(configuration) == 0 || len(configuration) > vault.MaxSecretBytes {
		return vault.ErrFormat
	}
	if err := o.validateTunnelImportTarget(ctx, target); err != nil {
		return err
	}
	o.pruneTunnelImports(time.Now())
	if _, exists := o.tunnelImports[id]; exists {
		return vaultstore.ErrConflict
	}
	count := len(o.tunnelImports)
	for _, stage := range o.tunnelImports {
		if stage.EditorID == editor {
			count--
		}
	}
	if count >= maxTunnelImportStages {
		return vault.ErrPolicy
	}
	stage := tunnelImportStage{EditorID: editor, Target: target, Expires: time.Now().Add(5 * time.Minute)}
	binding := o.tunnelImportBinding(id, stage)
	err := o.root.With(func(root []byte) error {
		key, err := vault.DeriveKey(root, []byte(binding.WorkspaceID+":"+id), vault.PurposeTunnelImport)
		if err != nil {
			return err
		}
		defer vault.Wipe(key)
		stage.Envelope, err = vault.Seal(key, binding, configuration)
		return err
	})
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		vault.Wipe(stage.Envelope.Ciphertext)
		return err
	}
	if o.tunnelImports == nil {
		o.tunnelImports = make(map[string]tunnelImportStage)
	}
	for old, previous := range o.tunnelImports {
		if previous.EditorID == editor {
			o.discardTunnelImport(old)
		}
	}
	o.tunnelImports[id] = stage
	return nil
}

// ReadTunnelImport returns owned plaintext for one native mutation; the caller
// must wipe it. A failed save can retry until expiry; success explicitly discards
// the stage. The opening record is checked again before returning any material.
func (o *Owner) ReadTunnelImport(ctx context.Context, editor, id string, target TunnelImportTarget) ([]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.readTunnelImport(ctx, editor, id, target)
}

// CurrentTunnelImport borrows an editor's preceding encrypted snapshot only for
// the exact same opening/provider. No caller-selected previous stage is trusted.
// This lets multi-file native import assemble one atomic replacement stage.
func (o *Owner) CurrentTunnelImport(ctx context.Context, editor string, target TunnelImportTarget) ([]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !tunnelImportID(editor) {
		return nil, vault.ErrFormat
	}
	o.pruneTunnelImports(time.Now())
	for id, stage := range o.tunnelImports {
		if stage.EditorID == editor {
			return o.readTunnelImport(ctx, editor, id, target)
		}
	}
	if err := o.validateTunnelImportTarget(ctx, target); err != nil {
		return nil, err
	}
	return nil, nil
}

// Caller holds o.mu. Both exact-ID and current-editor reads use the same checks.
func (o *Owner) readTunnelImport(ctx context.Context, editor, id string, target TunnelImportTarget) ([]byte, error) {
	if !tunnelImportID(editor) || !tunnelImportID(id) {
		return nil, vault.ErrFormat
	}
	if err := o.validateTunnelImportTarget(ctx, target); err != nil {
		return nil, err
	}
	o.pruneTunnelImports(time.Now())
	stage, ok := o.tunnelImports[id]
	if !ok {
		return nil, vaultstore.ErrMissing
	}
	if stage.EditorID != editor || stage.Target != target {
		return nil, vaultstore.ErrConflict
	}
	var plaintext []byte
	err := o.root.With(func(root []byte) error {
		binding := o.tunnelImportBinding(id, stage)
		key, err := vault.DeriveKey(root, []byte(binding.WorkspaceID+":"+id), vault.PurposeTunnelImport)
		if err != nil {
			return err
		}
		defer vault.Wipe(key)
		plaintext, err = vault.Open(key, binding, stage.Envelope)
		return err
	})
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		vault.Wipe(plaintext)
		return nil, err
	}
	return plaintext, nil
}

// DiscardTunnelImport is idempotent and cannot discard another editor's stage.
// Empty id retires every stage owned by the closing editor.
func (o *Owner) DiscardTunnelImport(editor, id string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for candidate, stage := range o.tunnelImports {
		if stage.EditorID == editor && (id == "" || candidate == id) {
			o.discardTunnelImport(candidate)
		}
	}
}
