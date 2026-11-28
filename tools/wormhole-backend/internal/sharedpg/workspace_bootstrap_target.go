package sharedpg

import (
	"bytes"
	"context"
	"crypto/tls"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// prepareWorkspaceBootstrapFromDeployment authenticates an already deployed
// database and selects the trust anchors from its verified certificate chains.
// Provider bundles can contain roots for other regions/databases; only roots
// that verified this peer become part of the signed workspace trust bundle.
func prepareWorkspaceBootstrapFromDeployment(ctx context.Context, settings Settings, password []byte, workspace uuid.UUID, roleTag, login string, profile vault.Profile, requireASK bool, org *bootstrapOrganisation) (*workspaceBootstrap, *workspaceBootstrapSecrets, error) {
	if ctx == nil || len(settings.Endpoints) != 1 || settings.TLS != TLSVerified || settings.TLSBundle != nil ||
		deploy.ValidateIdentity(roleTag, workspace.String()) != nil || ValidateDeploymentTarget(settings.Endpoints[0], settings.Database, settings.CAPEM) != nil {
		return nil, nil, ErrConfiguration
	}
	var roots [][]byte
	conn, err := connect(ctx, settings, password, func(ctx context.Context, config *pgconn.Config) (*pgconn.PgConn, error) {
		// The initial plan uses explicit Verified TLS with a single endpoint.
		// Reject unexpected fallbacks rather than capturing a different peer.
		if config.TLSConfig == nil || config.TLSConfig.InsecureSkipVerify || config.TLSConfig.VerifyConnection != nil || len(config.Fallbacks) != 0 {
			return nil, ErrConfiguration
		}
		config.TLSConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if org != nil && (len(state.PeerCertificates) == 0 || !bytes.Equal(state.PeerCertificates[0].Raw, org.serverDER)) {
				return ErrServerCertificate
			}
			roots = nil
			for _, chain := range state.VerifiedChains {
				if len(chain) > 0 {
					der := chain[len(chain)-1].Raw
					if slices.ContainsFunc(roots, func(root []byte) bool { return bytes.Equal(root, der) }) {
						continue
					}
					if len(roots) == 8 {
						return vault.ErrPolicy
					}
					roots = append(roots, bytes.Clone(der))
				}
			}
			if len(roots) == 0 {
				return vault.ErrAuthentication
			}
			return nil
		}
		return pgconn.ConnectConfig(ctx, config)
	})
	if err != nil {
		return nil, nil, err
	}
	defer closeDeploymentConnection(conn)
	deployment, err := checkSchemaDeployment(ctx, conn, roleTag, workspace.String())
	if err != nil {
		return nil, nil, err
	}
	if !deployment.Provisioning || !deployment.RequiresTLS {
		return nil, nil, ErrDeploymentMismatch
	}
	settings.Profile = profile
	return prepareWorkspaceBootstrap(workspace, roleTag, settings, roots, login, requireASK, time.Now(), org)
}
