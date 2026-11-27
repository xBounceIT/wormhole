package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func (h *vaultFoundationHandler) rootRotationEnrollmentSource(ctx context.Context) (vault.SlotFile, error) {
	if h.owner == nil || h.shared != nil || h.enrollment != nil || h.rotationMaterial != nil || h.releaseWorkspace == nil {
		return vault.SlotFile{}, vaultwire.ErrProtocol
	}
	if err := requireNoRootRotation(h.databasePath); err != nil {
		return vault.SlotFile{}, err
	}
	if err := requireNoLegacyMigrationSetup(h.databasePath); err != nil {
		return vault.SlotFile{}, err
	}
	profile, err := h.owner.ReadSecurityProfile(ctx)
	if err != nil {
		return vault.SlotFile{}, err
	}
	if profile.Effective != vault.Default && profile.Effective != vault.Standard {
		return vault.SlotFile{}, vault.ErrPolicy
	}
	doc, err := readVaultSlotFile(h.databasePath)
	if err != nil {
		return vault.SlotFile{}, err
	}
	if doc.Migration != nil || doc.Rotation != nil || doc.Initializing || doc.RootKeyVersion == math.MaxUint32 || doc.Sequence > math.MaxUint64-vault.RootRotationSequenceSpan || doc.FileEpoch == math.MaxUint64 {
		return vault.SlotFile{}, vault.ErrPolicy
	}
	return doc, nil
}

func (h *vaultFoundationHandler) rootRotationSetupContext(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if len(payload) != 0 {
		return nil, vaultwire.ErrProtocol
	}
	doc, err := h.rootRotationEnrollmentSource(ctx)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Slots vault.SlotFileDescriptor `json:"slots"`
	}{doc.Descriptor()})
}

// Current authentication and the new password travel in one protected-window
// stdin request. Recovery confirmation never authorizes another source or root.
func (h *vaultFoundationHandler) beginRootRotationEnrollment(ctx context.Context, payload []byte) (_ json.RawMessage, resultErr error) {
	return h.beginRootRotationEnrollmentMode(ctx, payload, false)
}

func (h *vaultFoundationHandler) beginRootRotationEnrollmentMode(ctx context.Context, payload []byte, encryptDatabase bool) (_ json.RawMessage, resultErr error) {
	defer vault.Wipe(payload)
	if len(payload) > 16*1024 {
		return nil, vaultwire.ErrProtocol
	}
	doc, err := h.rootRotationEnrollmentSource(ctx)
	if err != nil {
		return nil, err
	}
	if encryptDatabase && doc.Encrypted {
		return nil, vault.ErrPolicy
	}
	var passwordJSON, publicJSON, authJSON json.RawMessage
	defer func() { vault.Wipe(passwordJSON); vault.Wipe(publicJSON); vault.Wipe(authJSON) }()
	if decodeVaultObject(payload, map[string]any{"password": &passwordJSON, "publicKey": &publicJSON, "authentication": &authJSON}, "password", "publicKey", "authentication") != nil {
		return nil, vaultwire.ErrProtocol
	}
	var password, publicKey, authentication []byte
	defer func() { vault.Wipe(password); vault.Wipe(publicKey); vault.Wipe(authentication) }()
	for _, field := range []struct {
		raw json.RawMessage
		out *[]byte
	}{{passwordJSON, &password}, {publicJSON, &publicKey}, {authJSON, &authentication}} {
		if len(field.raw) == 0 || field.raw[0] != '"' || json.Unmarshal(field.raw, field.out) != nil {
			return nil, vaultwire.ErrProtocol
		}
	}
	if len(password) == 0 || len(password) > 1024 || len(publicKey) != 32 {
		return nil, vaultwire.ErrProtocol
	}
	input, err := decodeVaultUnlock(authentication)
	defer input.wipe()
	if err != nil {
		return nil, err
	}
	if err := h.verifyCurrentVaultFactor(ctx, doc, &input); err != nil {
		return nil, err
	}
	input.wipe()
	vault.Wipe(authentication)
	// The old factor has served its single purpose. Do not retain its encoded
	// copies while deriving the replacement password slot or staging the graph.
	vault.Wipe(authJSON)
	vault.Wipe(passwordJSON)
	vault.Wipe(publicJSON)
	vault.Wipe(payload)
	material, err := securemem.New(32+76, true)
	if err != nil {
		return nil, err
	}
	p := newRootRotationEnrollment(doc, material)
	p.document.Encrypted = doc.Encrypted || encryptDatabase
	retained := false
	defer func() {
		if !retained {
			if closeErr := p.close(); closeErr != nil {
				h.enrollment = p
				resultErr = h.retire(errors.Join(resultErr, closeErr))
			}
		}
	}()
	result, err := p.prepare(ctx, password, publicKey)
	if err != nil {
		return nil, err
	}
	h.enrollment = p
	retained = true
	p.arm()
	return result, nil
}

func newRootRotationEnrollment(doc vault.SlotFile, material *securemem.Buffer) *vaultEnrollment {
	p := &vaultEnrollment{id: uuid.NewString(), material: material, rotationSource: &doc, document: doc}
	p.document.FormatVersion = vault.SlotFileFormatVersion
	p.document.RootKeyVersion++
	p.document.Sequence += vault.RootRotationSequenceSpan
	p.document.FileEpoch++
	return p
}

func (h *vaultFoundationHandler) confirmRootRotationEnrollment(ctx context.Context, payload []byte) (json.RawMessage, error) {
	p := h.enrollment
	if p == nil || p.rotationSource == nil || p.migration != nil || (h.owner == nil) != p.unprotectedUpgrade {
		return nil, vaultwire.ErrProtocol
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.verifyConfirmation(payload); err != nil {
		if errors.Is(err, securemem.ErrUnavailable) {
			return nil, h.retire(err)
		}
		return nil, err
	}
	// The confirmation deadline bounds user input, not the size of the encrypted
	// graph. A timely confirmation gets the bounded native preparation window.
	if p.timer != nil {
		p.timer.Stop()
	}
	commitCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	current, err := readVaultSlotFile(h.databasePath)
	if err == nil && !sameRootRotationDocument(current, *p.rotationSource) {
		err = errVaultSlotConflict
	}
	if err == nil {
		if p.unprotectedUpgrade {
			// From here an OS source may be opened solely for forward staging.
			// Keep both scope and lease until cleanup is positively acknowledged.
			h.releaseWorkspace, p.release = p.release, nil
			scope := localvault.NewUnprotectedRootUpgrade()
			h.rotationMaterial = scope
			err = p.material.With(func(storage []byte) error {
				return beginUnprotectedRootUpgrade(commitCtx, h.databasePath, scope, p.document.Slots, bytes.Clone(storage[:32]), func(string) error { return commitCtx.Err() })
			})
			closeErr := scope.Close()
			if closeErr == nil {
				h.rotationMaterial = nil
			}
			err = errors.Join(err, closeErr)
		} else {
			err = p.material.With(func(storage []byte) error {
				encryptDatabase := p.document.Encrypted && !current.Encrypted
				return beginLocalRootRotationMode(commitCtx, h.databasePath, h.owner, p.document.Slots, bytes.Clone(storage[:32]), func(string) error { return commitCtx.Err() }, encryptDatabase)
			})
		}
	}
	closeErr := p.closeLocked()
	if closeErr == nil {
		h.enrollment = nil
	}
	err = errors.Join(err, closeErr)
	// Confirmation may have closed the resident source before failing. No normal
	// operation or second enrollment is allowed until actual process retirement.
	h.closed = true
	if err != nil {
		return nil, h.retire(err)
	}
	return json.Marshal(struct {
		Prepared        bool   `json:"prepared"`
		RestartRequired bool   `json:"restartRequired"`
		VaultID         string `json:"vaultId"`
	}{true, true, p.document.VaultID})
}

func (h *vaultFoundationHandler) cancelRootRotationEnrollment(payload []byte) (json.RawMessage, error) {
	p := h.enrollment
	if len(payload) != 0 || p == nil || p.rotationSource == nil || (h.owner == nil) != p.unprotectedUpgrade {
		return nil, vaultwire.ErrProtocol
	}
	if err := p.close(); err != nil {
		return nil, h.retire(err)
	}
	h.enrollment = nil
	return json.RawMessage(`{"cancelled":true}`), nil
}
