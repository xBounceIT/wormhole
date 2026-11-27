package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedWorkspaceCARotationSession interface {
	sharedRuntimeStateSession
	PublishWorkspaceCAOverlap(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, []byte, []byte, []byte, time.Time) (*sharedpg.VerifiedTLSBundle, error)
	PublishWorkspaceCARetirement(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, sharedpg.Settings, []byte, []byte) (*sharedpg.VerifiedTLSBundle, error)
}

type sharedWorkspaceCAResult struct {
	Status    string `json:"status"`
	ServerPEM string `json:"serverPem,omitempty"`
	Reconnect bool   `json:"reconnect,omitempty"`
}

func (h *vaultFoundationHandler) sharedWorkspaceCA(ctx context.Context, operation string, payload []byte) (json.RawMessage, error) {
	var csr []byte
	if operation == "shared-ca-rotate" {
		var err error
		csr, err = decodeSharedServerCSR(payload)
		if err != nil {
			return nil, err
		}
	} else if len(payload) != 0 {
		return nil, vaultwire.ErrProtocol
	}
	controller, err := h.sharedOwner(ctx)
	if err != nil {
		return nil, err
	}
	result, err := controller.workspaceCA(ctx, operation, csr)
	if err != nil {
		return nil, h.retire(err)
	}
	if result.Reconnect {
		h.closed = true
	}
	return json.Marshal(result)
}

func (c *sharedAdmissionController) workspaceCA(ctx context.Context, operation string, csr []byte) (sharedWorkspaceCAResult, error) {
	var result sharedWorkspaceCAResult
	session, ok := c.session.(sharedWorkspaceCARotationSession)
	if !ok {
		return result, sharedpg.ErrConfiguration
	}
	err := c.withWorkspaceTrust(ctx, session, func(ctx context.Context, trust sharedpg.TrustState, bundle *sharedpg.VerifiedTLSBundle) error {
		if bundle == nil {
			result.Status = "unavailable"
			return nil
		}
		leaf := bundle.PendingServerCertificate()
		if operation == "shared-ca-status" {
			result.Status = "ready"
			if len(leaf) != 0 {
				result = sharedWorkspaceCAResult{Status: "staged", ServerPEM: string(leaf)}
			}
			return nil
		}
		if (operation == "shared-ca-rotate") == (len(leaf) != 0) {
			result.Status = "unavailable"
			return nil
		}
		options := sharedAdmissionOptions{TrustPath: c.trustPath, Binding: c.trustBinding,
			OSFloor: c.runtimeOSFloor, UserFloor: c.runtimeUserFloor, Request: sharedpg.AdmissionRequest{API: 1}}
		var settings sharedpg.Settings
		if operation == "shared-ca-retire" {
			if err := c.root.With(func(root []byte) error {
				var err error
				settings, err = readSharedTransportSetup(options, root, trust)
				return err
			}); err != nil {
				return err
			}
			// The authenticated cache passed separately may be the same
			// bundle loaded through a different protected read.
			settings.TLSBundle = bundle
		}
		var next *sharedpg.VerifiedTLSBundle
		err := c.privateKeys.With(func(keys []byte) error {
			if len(keys) != 64 {
				return sharedpg.ErrAuthentication
			}
			var err error
			if operation == "shared-ca-rotate" {
				next, err = session.PublishWorkspaceCAOverlap(ctx, trust, bundle, keys[:32:32], keys[32:], csr, time.Now())
			} else {
				next, err = session.PublishWorkspaceCARetirement(ctx, trust, bundle, settings, keys[:32:32], keys[32:])
			}
			return err
		})
		switch {
		case errors.Is(err, sharedpg.ErrServerCertificateAuthority):
			result.Status = "unavailable"
			return nil
		case errors.Is(err, sharedpg.ErrServerCertificate):
			result.Status = "invalid-csr"
			return nil
		case errors.Is(err, sharedpg.ErrWorkspaceCARotation) && operation == "shared-ca-retire":
			result.Status = "installation-required"
			return nil
		case err != nil:
			return err
		}
		options.Settings.TLSBundle = next
		var advanced sharedpg.TrustState
		if err := c.root.With(func(root []byte) error {
			var err error
			advanced, err = acceptSharedTLSBundle(options, root, trust)
			return err
		}); err != nil {
			return err
		}
		if err := c.checkpointCatalogTrust(advanced); err != nil {
			return err
		}
		// Retire the pre-update transport before acknowledging either
		// transition. The requesting host locks the service on receipt.
		// An unexpected owner loss must still terminate the wire request.
		if c.stopOwnerExit != nil && !c.stopOwnerExit() {
			return sharedpg.ErrSessionClosed
		}
		c.admitted.Store(false)
		c.cancel()
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if err := c.closeLocked(cleanup); err != nil {
			return err
		}
		result = sharedWorkspaceCAResult{Status: "retired", Reconnect: true}
		if leaf := next.PendingServerCertificate(); len(leaf) != 0 {
			result.Status = "staged"
			result.ServerPEM = string(leaf)
		}
		return nil
	})
	if err != nil {
		return sharedWorkspaceCAResult{}, err
	}
	return result, nil
}
