package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedServerCertificateSession interface {
	sharedRuntimeStateSession
	RenewServerCertificate(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, []byte, []byte, []byte, time.Time) ([]byte, error)
}

type sharedServerCertificateResult struct {
	Status    string `json:"status"`
	ServerPEM string `json:"serverPem,omitempty"`
}

func (h *vaultFoundationHandler) sharedRenewServerCertificate(ctx context.Context, payload []byte) (json.RawMessage, error) {
	csr, err := decodeSharedServerCSR(payload)
	if err != nil {
		return nil, err
	}
	controller, err := h.sharedOwner(ctx)
	if err != nil {
		return nil, err
	}
	result, err := controller.renewServerCertificate(ctx, csr)
	if err != nil {
		return nil, h.retire(err)
	}
	return json.Marshal(result)
}

func decodeSharedServerCSR(payload []byte) ([]byte, error) {
	var csr string
	if len(payload) > 2*sharedpg.MaxServerCSRBytes ||
		decodeVaultObject(payload, map[string]any{"csr": &csr}, "csr") != nil ||
		len(csr) == 0 || len(csr) > sharedpg.MaxServerCSRBytes {
		return nil, vaultwire.ErrProtocol
	}
	return []byte(csr), nil
}

func (c *sharedAdmissionController) renewServerCertificate(ctx context.Context, csr []byte) (sharedServerCertificateResult, error) {
	var result sharedServerCertificateResult
	session, ok := c.session.(sharedServerCertificateSession)
	if !ok {
		return result, sharedpg.ErrConfiguration
	}
	err := c.withWorkspaceTrust(ctx, session, func(ctx context.Context, trust sharedpg.TrustState, bundle *sharedpg.VerifiedTLSBundle) error {
		if bundle == nil {
			result.Status = "unavailable"
			return nil
		}
		return c.privateKeys.With(func(keys []byte) error {
			if len(keys) != 64 {
				return sharedpg.ErrAuthentication
			}
			cert, err := session.RenewServerCertificate(ctx, trust, bundle, keys[:32:32], keys[32:], csr, time.Now())
			switch {
			case errors.Is(err, sharedpg.ErrServerCertificateAuthority):
				result.Status = "unavailable"
			case errors.Is(err, sharedpg.ErrServerCertificate):
				result.Status = "invalid-csr"
			case err != nil:
				return err
			default:
				result = sharedServerCertificateResult{Status: "issued", ServerPEM: string(cert)}
			}
			return nil
		})
	})
	if err != nil {
		return sharedServerCertificateResult{}, err
	}
	return result, nil
}

// Authenticate runtime policy and account state and commit the observed floors
// before using the exact TLS cache selected by the protected trust file.
func (c *sharedAdmissionController) withWorkspaceTrust(ctx context.Context, session sharedRuntimeStateSession, use func(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle) error) error {
	var bundle *sharedpg.VerifiedTLSBundle
	return c.withCatalogOperation(ctx, func(ctx context.Context, current sharedpg.TrustState, pending *sharedpg.TrustState) error {
		if !c.tlsManaged || c.runtimeTLS != sharedpg.TLSVerified {
			return nil
		}
		if _, err := c.observeRuntime(ctx, session, current, pending); err != nil {
			return err
		}
		var err error
		bundle, err = readSharedTLSCache(c.trustPath, current)
		return err
	}, func(ctx context.Context, trust sharedpg.TrustState) error {
		return use(ctx, trust, bundle)
	}, false)
}
