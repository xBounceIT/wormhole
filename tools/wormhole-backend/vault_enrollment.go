package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"math/big"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

const vaultEnrollmentLifetime = 5 * time.Minute

// Enrollment holds no password. Only the root key and formatted recovery code
// survive begin, in locked native memory, until confirmation/cancel/expiry.
// The workspace lease prevents legacy startup creating a DB behind the dialog.
type vaultEnrollment struct {
	mu                 sync.Mutex
	id                 string
	document           vault.SlotFile
	groups             [2]int // zero-based full five-character groups; never the short tail
	material           *securemem.Buffer
	release            func()
	timer              *time.Timer
	expires            time.Time
	closed             bool
	attempts           int
	migration          *legacyMigrationSetup
	rotationSource     *vault.SlotFile
	unprotectedUpgrade bool // native enrollment mode, never a wire authority
}

func (p *vaultEnrollment) closeLocked() error {
	p.closed = true
	if p.timer != nil {
		p.timer.Stop()
	}
	err := p.material.Close()
	if err == nil && p.release != nil {
		p.release()
		p.release = nil
	}
	return err
}

func (p *vaultEnrollment) close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closeLocked()
}

// Native/main-only endpoint. The recipient must be the dedicated protected
// recovery dialog; a generic renderer IPC must never choose this public key.
func (h *vaultFoundationHandler) beginEnrollment(ctx context.Context, payload []byte) (json.RawMessage, error) {
	return h.beginEnrollmentMode(ctx, payload, false)
}

func (h *vaultFoundationHandler) beginMigrationEnrollment(ctx context.Context, payload []byte) (json.RawMessage, error) {
	return h.beginEnrollmentMode(ctx, payload, true)
}

func (h *vaultFoundationHandler) beginEnrollmentMode(ctx context.Context, payload []byte, migration bool) (result json.RawMessage, resultErr error) {
	if h.owner != nil || h.enrollment != nil || h.databasePath == "" || len(payload) > 4096 {
		return nil, vaultwire.ErrProtocol
	}
	var passwordJSON, publicJSON, legacyJSON json.RawMessage
	var legacyMethod string
	defer func() { vault.Wipe(passwordJSON); vault.Wipe(publicJSON); vault.Wipe(legacyJSON) }()
	fields := map[string]any{"password": &passwordJSON, "publicKey": &publicJSON}
	required := []string{"password", "publicKey"}
	if migration {
		fields["legacyMethod"], fields["legacyFactor"] = &legacyMethod, &legacyJSON
		required = append(required, "legacyMethod", "legacyFactor")
	}
	if decodeVaultObject(payload, fields, required...) != nil {
		return nil, vaultwire.ErrProtocol
	}
	var password, publicKey, legacyFactor []byte
	defer func() { vault.Wipe(password); vault.Wipe(publicKey); vault.Wipe(legacyFactor) }()
	if len(passwordJSON) == 0 || passwordJSON[0] != '"' || len(publicJSON) == 0 || publicJSON[0] != '"' || json.Unmarshal(passwordJSON, &password) != nil || json.Unmarshal(publicJSON, &publicKey) != nil || len(password) == 0 || len(password) > 1024 || len(publicKey) != 32 {
		return nil, vaultwire.ErrProtocol
	}
	if migration && (len(legacyJSON) == 0 || legacyJSON[0] != '"' || json.Unmarshal(legacyJSON, &legacyFactor) != nil || len(legacyFactor) > 1024) {
		return nil, vaultwire.ErrProtocol
	}
	floor, err := ospolicy.ReadFloor(ctx)
	if err != nil || (floor != vault.Default && floor != vault.Standard) {
		return nil, vault.ErrPolicy
	}
	release, err := acquireWorkspaceOwnership(h.databasePath, true)
	if err != nil {
		return nil, err
	}
	retained := false
	defer func() {
		if !retained {
			release()
		}
	}()
	var setup *legacyMigrationSetup
	if migration {
		if err := requireLegacyWorkspace(h.databasePath); err != nil {
			return nil, err
		}
		canonical, _, err := canonicalLegacyVaultSource(h.databasePath)
		if err != nil || !filepath.IsAbs(h.userDataPath) || filepath.Clean(h.userDataPath) != h.userDataPath {
			return nil, vault.ErrPolicy
		}
		if err := verifyLegacyMigrationFactor(ctx, h.databasePath, legacyMethod, legacyFactor); err != nil {
			return nil, err
		}
		vault.Wipe(legacyFactor)
		legacyFactor = nil
		setup = &legacyMigrationSetup{Version: 1, LogicalSource: h.databasePath, CanonicalSource: canonical, UserData: h.userDataPath}
	} else if err := requireNewVaultWorkspace(h.databasePath); err != nil {
		return nil, err
	}
	material, err := securemem.New(32+76, true)
	if err != nil {
		return nil, err
	}
	p := &vaultEnrollment{id: uuid.NewString(), material: material, migration: setup}
	defer func() {
		if !retained {
			if err := p.close(); err != nil {
				resultErr = h.retire(errors.Join(resultErr, err))
			}
		}
	}()
	p.document = vault.SlotFile{FormatVersion: 1, VaultID: uuid.NewString(), FileID: uuid.NewString(), RootKeyID: uuid.NewString(), RootKeyVersion: 1, Initializing: true, Sequence: 1, FileEpoch: 1}
	if setup != nil {
		p.document.Initializing = false
		database, err := openLegacyMigrationSource(setup.CanonicalSource)
		if err != nil {
			return nil, err
		}
		setup.Plan, err = prepareLegacyResolverMigration(ctx, database, p.document.VaultID)
		err = errors.Join(err, database.Close())
		if err != nil {
			return nil, err
		}
	}
	result, err = p.prepare(ctx, password, publicKey)
	if err != nil {
		return nil, err
	}
	p.release = release
	h.enrollment = p
	retained = true
	p.arm()
	return result, nil
}

// The caller owns the locked material and closes it on every failed preparation.
// The root version comes from the native workspace selection, never a UI field.
func (p *vaultEnrollment) prepare(ctx context.Context, password, publicKey []byte) (json.RawMessage, error) {
	var bundle vault.SealedBundle
	err := p.material.With(func(storage []byte) error {
		key, recovery := vault.NewRecoveryKey(), vault.NewRecoveryKey()
		defer vault.Wipe(key)
		defer vault.Wipe(recovery)
		code, err := vault.FormatRecoveryKey(recovery)
		defer vault.Wipe(code)
		if err != nil {
			return err
		}
		bundle, err = vault.SealRecoveryDisplay(publicKey, p.document.VaultID, p.id, code)
		if err != nil {
			return err
		}
		passwordSlot, err := vault.CreatePasswordSlot(ctx, p.document.VaultID, uuid.NewString(), p.document.RootKeyVersion, key, password, nil, vault.KDFV1)
		if err != nil {
			return err
		}
		recoverySlot, err := vault.CreateRecoverySlot(p.document.VaultID, uuid.NewString(), p.document.RootKeyVersion, key, recovery)
		if err != nil {
			return err
		}
		p.document.Slots = []vault.Slot{passwordSlot, recoverySlot}
		copy(storage, key)
		copy(storage[32:], code)
		return nil
	})
	if err != nil {
		return nil, err
	}
	first, err := rand.Int(rand.Reader, big.NewInt(11))
	if err != nil {
		return nil, err
	}
	second, err := rand.Int(rand.Reader, big.NewInt(10))
	if err != nil {
		return nil, err
	}
	p.groups = [2]int{int(first.Int64()), int(second.Int64())}
	if p.groups[1] >= p.groups[0] {
		p.groups[1]++
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result, err := json.Marshal(struct {
		EnrollmentID string             `json:"enrollmentId"`
		VaultID      string             `json:"vaultId"`
		Groups       [2]int             `json:"groups"`
		Bundle       vault.SealedBundle `json:"bundle"`
	}{p.id, p.document.VaultID, [2]int{p.groups[0] + 1, p.groups[1] + 1}, bundle})
	if err != nil {
		return nil, err
	}
	p.expires = time.Now().Add(vaultEnrollmentLifetime)
	return result, nil
}

func (p *vaultEnrollment) arm() {
	p.mu.Lock()
	p.timer = time.AfterFunc(vaultEnrollmentLifetime, func() { _ = p.close() })
	p.mu.Unlock()
}

func (h *vaultFoundationHandler) confirmEnrollment(ctx context.Context, payload []byte) (json.RawMessage, error) {
	return h.confirmEnrollmentMode(ctx, payload, false)
}

func (h *vaultFoundationHandler) confirmMigrationEnrollment(ctx context.Context, payload []byte) (json.RawMessage, error) {
	return h.confirmEnrollmentMode(ctx, payload, true)
}

func (h *vaultFoundationHandler) confirmEnrollmentMode(ctx context.Context, payload []byte, migration bool) (json.RawMessage, error) {
	p := h.enrollment
	if p == nil || h.owner != nil || p.rotationSource != nil || len(payload) > 1024 || (p.migration != nil) != migration {
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
	commitCtx, cancel := context.WithDeadline(ctx, p.expires)
	defer cancel()
	if p.migration != nil {
		err := p.material.With(func(material []byte) error {
			raw, err := vault.EncodeSlotFile(material[:32], p.document)
			if err != nil {
				return err
			}
			p.migration.Initial, err = vault.DecodeSlotFile(raw)
			if err != nil {
				return err
			}
			return saveLegacyMigrationSetup(commitCtx, *p.migration, material[:32])
		})
		err = errors.Join(err, p.closeLocked())
		h.enrollment = nil
		if err != nil {
			return nil, h.retire(err)
		}
		return json.Marshal(struct {
			Prepared        bool   `json:"prepared"`
			RestartRequired bool   `json:"restartRequired"`
			VaultID         string `json:"vaultId"`
		}{true, true, p.document.VaultID})
	}
	// Keep the lease through publication. A failed/torn commit retires this
	// process; confirmed password/recovery slots resume on restart.
	err := p.material.With(func(material []byte) error {
		var err error
		h.owner, err = initializeVaultFiles(commitCtx, h.databasePath, p.document, material[:32])
		return err
	})
	if h.owner != nil {
		h.releaseWorkspace, p.release = p.release, nil
	}
	err = errors.Join(err, p.closeLocked())
	h.enrollment = nil
	if err != nil {
		return nil, h.retire(err)
	}
	return marshalLocalVaultUnlock(h.owner)
}

// Caller holds p.mu through verification and its single commit. No reusable
// authentication token survives a successful recovery-group confirmation.
func (p *vaultEnrollment) verifyConfirmation(payload []byte) error {
	if len(payload) > 1024 {
		return vaultwire.ErrProtocol
	}
	var id string
	var raw json.RawMessage
	defer func() { vault.Wipe(raw) }()
	if decodeVaultObject(payload, map[string]any{"enrollmentId": &id, "groups": &raw}, "enrollmentId", "groups") != nil || id != p.id {
		return vaultwire.ErrProtocol
	}
	var groups []byte
	defer func() { vault.Wipe(groups) }()
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &groups) != nil || len(groups) != 10 {
		return vaultwire.ErrProtocol
	}
	if p.closed || !time.Now().Before(p.expires) {
		return errors.Join(vault.ErrAuthentication, p.closeLocked())
	}
	matched := false
	err := p.material.With(func(material []byte) error {
		code := material[32:]
		a, b := 7+p.groups[0]*6, 7+p.groups[1]*6
		matched = subtle.ConstantTimeCompare(groups[:5], code[a:a+5])&subtle.ConstantTimeCompare(groups[5:], code[b:b+5]) == 1
		return nil
	})
	if err != nil {
		return err
	}
	if !matched {
		p.attempts++
		if p.attempts >= 3 {
			return errors.Join(vault.ErrAuthentication, p.closeLocked())
		}
		return vault.ErrAuthentication
	}
	return nil
}

func (h *vaultFoundationHandler) cancelEnrollment(payload []byte) (json.RawMessage, error) {
	if len(payload) != 0 || h.owner != nil {
		return nil, vaultwire.ErrProtocol
	}
	if p := h.enrollment; p != nil {
		if err := p.close(); err != nil {
			return nil, h.retire(err)
		}
		h.enrollment = nil
	}
	return json.RawMessage(`{"cancelled":true}`), nil
}
