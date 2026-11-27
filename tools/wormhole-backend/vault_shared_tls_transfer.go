package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func sharedTLSBundlePathValid(path string) bool {
	return sharedFilePathValid(path, ".whtls")
}

func sharedFilePathValid(path, extension string) bool {
	return len(path) <= 4096 && filepath.IsAbs(path) && filepath.Clean(path) == path &&
		strings.EqualFold(filepath.Ext(path), extension) && strings.IndexFunc(path, unicode.IsControl) < 0
}

// An established, password-unlocked device can advance its pinned TLS bundle
// before connecting. The file contributes only the signed public document.
func (s *sharedSelectedDevice) applyTLSUpdate(ctx context.Context, path string, protection sharedStartupProtection) error {
	if s == nil || s.mode != sharedDeviceOrdinary || ctx == nil || !sharedTLSBundlePathValid(path) {
		return vaultwire.ErrProtocol
	}
	o := s.options
	anchor, err := readSharedStartupAnchor(o.TrustPath, protection)
	if err != nil {
		return err
	}
	err = s.account.Borrow(func(_ *sharedpg.AccountMaster, root *sharedpg.DeviceTrustRoot) error {
		return root.Use(func(key []byte) error {
			current, err := readActiveSharedTrustFile(o.TrustPath, key, o.Binding, o.MinimumRevision)
			if err != nil {
				return err
			}
			raw, err := readSharedTrustBytes(path, sharedpg.MaxTLSTrustBundleBytes)
			if err != nil {
				return err
			}
			bundle, err := current.VerifyTLS(raw)
			if err != nil {
				return err
			}
			settings, err := readSharedTransportSetup(o, key, current)
			if err != nil {
				return err
			}
			if settings.TLS != sharedpg.TLSVerified || settings.TLSBundle == nil {
				return sharedpg.ErrTLSRequired
			}
			settings.TLSBundle = bundle
			// Check the unchanged endpoints and runtime policy before making a
			// document with a different host set the durable minimum.
			next, err := current.AdvanceTLS(bundle)
			if err != nil {
				return err
			}
			if _, err := next.PrepareTransport(settings, o.OSFloor, o.UserFloor, o.Request.API); err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			o.Settings = settings
			next, err = acceptSharedTLSBundle(o, key, current)
			if err != nil {
				return err
			}
			o.MinimumRevision = next.Revision
			return nil
		})
	})
	if err != nil {
		return err
	}
	// Persist the OS-protected startup observation too. If acknowledgement
	// was lost, reselecting the same signed file can finish this publication.
	if o.MinimumRevision != anchor.Trust.Revision {
		if _, err := writeSharedStartupAnchor(ctx, o, s.account, anchor.DisplayName, anchor.Revision, protection); err != nil {
			return err
		}
	}
	s.options.MinimumRevision = o.MinimumRevision
	return nil
}

func (h *vaultFoundationHandler) exportSharedTLSBundle(ctx context.Context, payload []byte) (json.RawMessage, error) {
	var path string
	if len(payload) > 8192 || decodeVaultObject(payload, map[string]any{"path": &path}, "path") != nil ||
		!sharedTLSBundlePathValid(path) {
		return nil, vaultwire.ErrProtocol
	}
	controller, err := h.sharedOwner(ctx)
	if err != nil {
		return nil, err
	}
	session, ok := controller.session.(sharedRuntimeStateSession)
	if !ok {
		return nil, h.retire(sharedpg.ErrConfiguration)
	}
	exported := false
	err = controller.withWorkspaceTrust(ctx, session, func(ctx context.Context, _ sharedpg.TrustState, bundle *sharedpg.VerifiedTLSBundle) error {
		if bundle != nil {
			if err := ctx.Err(); err != nil {
				return err
			}
			exported = publishSharedSetupFile(path, bundle.Encode()) == nil
		}
		return nil
	})
	if err != nil {
		return nil, h.retire(err)
	}
	return json.Marshal(struct {
		Exported bool `json:"exported"`
	}{exported})
}
