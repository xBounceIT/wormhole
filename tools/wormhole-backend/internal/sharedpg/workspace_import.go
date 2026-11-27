package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/workspaceimport"
)

var ErrWorkspaceImport = errors.New("workspace_import_rejected")
var ErrImportedConnectionPins = errors.New("workspace_imported_connection_pins_required")

const commitWorkspaceImportSQL = `SELECT wormhole_api_v1.commit_workspace_import(` + serverCAArguments + `,$10::text,pg_catalog.decode($11,'hex'))`

// CommitWorkspaceImport publishes a single native document over the admitted
// Verified TLS connection. Keep the same sealed attempt to reconcile an
// uncertain reply. PostgreSQL rechecks identity, boundary revisions and Write
// under its transaction lock before inserting any of the graph.
func (s *Session) CommitWorkspaceImport(ctx context.Context, trust TrustState, current *VerifiedTLSBundle,
	author vault.UserPublicKeys, sealed *workspaceimport.SealedImport) (string, error) {
	if ctx == nil || sealed == nil {
		return "", ErrConfiguration
	}
	if _, err := authenticatedServerCAContext(trust, current); err != nil {
		return "", err
	}
	digest := enrollmentPublicDigest(author)
	if !bytes.Equal(digest[:], trust.Enrollment.PublicDigest) {
		return "", vault.ErrAuthentication
	}
	if err := sealed.VerifyPostgresAuthor(trust.WorkspaceID, trust.UserID, trust.Enrollment.Signing, author.Signing); err != nil {
		return "", err
	}
	body, signature := sealed.PostgresPayload()
	defer vault.Wipe(body)
	if len(body) > 128*1024*1024 {
		return "", ErrResultLimit
	}
	var receipt string
	err := s.queryServerCA(ctx, trust, commitWorkspaceImportSQL, [][]byte{body, hex.AppendEncode(nil, signature)}, 64, 1, 1, func(rows [][][]byte) error {
		if len(rows) != 1 || len(rows[0]) != 1 {
			return ErrAdmissionResponse
		}
		candidate := string(rows[0][0])
		if candidate != "imported" && candidate != "already-imported" {
			return ErrAdmissionResponse
		}
		receipt = candidate
		return nil
	})
	return receipt, err
}
