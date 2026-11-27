package sharedpg

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
)

// PinDeploymentServerCertificate adds an exact leaf check to initial setup's
// existing CA and hostname validation. It is never part of session settings.
func PinDeploymentServerCertificate(s Settings, certificate string) (Settings, error) {
	if s.TLS != TLSVerified || s.TLSBundle != nil || len(s.Endpoints) != 1 || len(certificate) > 64*1024 {
		return Settings{}, ErrConfiguration
	}
	block, rest := pem.Decode([]byte(certificate))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(rest) != 0 {
		return Settings{}, ErrConfiguration
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || leaf.IsCA {
		return Settings{}, ErrConfiguration
	}
	pin := sha256.Sum256(leaf.Raw)
	s.deploymentLeaf = &pin
	return s, nil
}

var (
	ErrDeploymentRejected  = errors.New("shared workspace schema deployment rejected by PostgreSQL")
	ErrDeploymentUncertain = errors.New("shared workspace schema deployment outcome is uncertain")
	ErrDeploymentMismatch  = errors.New("unexpected shared workspace schema identity, version or catalog")
)

//go:embed deployment_catalog.sql
var deploymentCatalogSQL string

// Pinned from the fresh superuser and delegated installations in the real
// schema deployment tests. These fingerprints contain no workspace identities.
const (
	catalogSchemaVersion       = 93
	standardDeploymentCatalog  = "QSg4VV7hka3VfCEmP9ylvekojpc7IuDunUlz7zirSVE="
	delegatedDeploymentCatalog = "iUaGme3+qf5nsFYz87BBmZhzCJ2x+q6RYNW4ZMxES2o="
	standardRLSCatalog         = "r+z8UnqVqs2INz1pDPBvvitnP7wNapug2PdCXdrRcUw="
	delegatedRLSCatalog        = "rI+VOxoSjOjdVgIpCaSYL3S83T2rNIJVIDigW77B+Q0="
)

// SchemaDeployment is a DBA observation for Check deployment, not proof of
// signed workspace identity or authority to admit an application user.
type SchemaDeployment struct {
	Version      int  `json:"version"`
	Provisioning bool `json:"provisioning"`
	RequiresTLS  bool `json:"requiresTls"`
}

// DeploySchema executes only locally generated migrations through a temporary
// native DBA connection. It borrows the password and never persists it. A lost
// commit acknowledgement requires CheckSchemaDeployment before another attempt.
func DeploySchema(ctx context.Context, settings Settings, password []byte, roleTag, workspaceID string) (SchemaDeployment, error) {
	script, err := deploy.SchemaScript(roleTag, workspaceID)
	if err != nil {
		return SchemaDeployment{}, err
	}
	if ctx == nil {
		return SchemaDeployment{}, ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	conn, err := Connect(ctx, settings, password)
	if err != nil {
		return SchemaDeployment{}, err
	}
	defer closeDeploymentConnection(conn)
	last, err := executeDeploymentScript(ctx, conn, script)
	if err != nil {
		var postgres *pgconn.PgError
		// An interrupted connection may have committed. Only an SQL error on
		// a still-open connection with an aborted transaction proves failure.
		if errors.As(err, &postgres) && !conn.IsClosed() && conn.TxStatus() == 'E' {
			return SchemaDeployment{}, ErrDeploymentRejected
		}
		return SchemaDeployment{}, ErrDeploymentUncertain
	}
	if last != "COMMIT" || conn.TxStatus() != 'I' {
		return SchemaDeployment{}, ErrDeploymentUncertain
	}
	// Use the same independent catalog check as an exported deployment after
	// PostgreSQL has removed the temporary DBA memberships.
	state, err := checkSchemaDeployment(ctx, conn, roleTag, workspaceID)
	if err != nil && !errors.Is(err, ErrDeploymentMismatch) {
		return SchemaDeployment{}, errors.Join(ErrDeploymentUncertain, err)
	}
	if err == nil && (!state.Provisioning || !state.RequiresTLS) {
		return SchemaDeployment{}, ErrDeploymentMismatch
	}
	return state, err
}

// The embedded migrations emit command tags only. Close the dedicated
// connection on an unexpected result without draining a server's row stream.
func executeDeploymentScript(ctx context.Context, conn *pgconn.PgConn, script string) (string, error) {
	const maxCommands = 4096
	results := conn.Exec(ctx, script)
	var last string
	for n := 0; results.NextResult(); n++ {
		result := results.ResultReader()
		if n == maxCommands || result.NextRow() {
			return "", ErrDeploymentUncertain
		}
		tag, err := result.Close()
		if err != nil {
			return "", err
		}
		last = tag.String()
	}
	return last, results.Close()
}

// CheckSchemaDeployment inspects the expected current schema on a standalone
// DBA connection. It reports the server's workspace policy, logging settings
// and response to a password-free plaintext startup for the workspace deployer.
func CheckSchemaDeployment(ctx context.Context, settings Settings, password []byte, roleTag, workspaceID string) (DeploymentInspection, error) {
	if err := deploy.ValidateIdentity(roleTag, workspaceID); err != nil {
		return DeploymentInspection{}, err
	}
	// Fixed diagnostic reads must still report unsafe logging on the DBA
	// login. Deployment and administrator enrollment retain their stricter
	// connection policy.
	conn, err := connectForDeploymentCheck(ctx, settings, password)
	if err != nil {
		return DeploymentInspection{}, err
	}
	defer closeDeploymentConnection(conn)
	schema, err := checkSchemaDeployment(ctx, conn, roleTag, workspaceID)
	if err != nil {
		return DeploymentInspection{}, err
	}
	row, err := readDeploymentRow(ctx, conn, "SELECT "+deploymentSettingsColumns, 4)
	if err != nil {
		return DeploymentInspection{}, err
	}
	serverSettings, err := parseDeploymentServerSettings(row)
	if err != nil {
		return DeploymentInspection{}, err
	}
	plain := checkPlainStartup(ctx, conn.Conn(), settings.Database, roleTag)
	if err := ctx.Err(); err != nil {
		return DeploymentInspection{}, err
	}
	return DeploymentInspection{schema, DeploymentChecks{serverSettings, plain}}, nil
}

func closeDeploymentConnection(conn *pgconn.PgConn) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = conn.Close(ctx)
}

func checkSchemaDeployment(ctx context.Context, conn *pgconn.PgConn, roleTag, workspaceID string) (SchemaDeployment, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Callers close this dedicated connection on every exit. Each catalog
	// response contains at most five short fields, including field metadata.
	conn.Frontend().SetMaxBodyLen(4096)
	if tag, err := executeDeploymentScript(ctx, conn, "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY"); err != nil || tag != "BEGIN" || conn.TxStatus() != 'T' {
		return SchemaDeployment{}, errors.Join(ErrQuery, ctx.Err())
	}
	digest, err := deploymentCatalog(ctx, conn, roleTag, workspaceID)
	if err != nil {
		return SchemaDeployment{}, err
	}
	if deploy.SchemaVersion != catalogSchemaVersion {
		return SchemaDeployment{}, ErrDeploymentMismatch
	}
	switch digest {
	case standardDeploymentCatalog, delegatedDeploymentCatalog, standardRLSCatalog, delegatedRLSCatalog:
	default:
		return SchemaDeployment{}, ErrDeploymentMismatch
	}
	row, err := readDeploymentRow(ctx, conn, `SELECT workspace_id::text, role_tag, schema_version::text, state, require_tls::text
FROM wormhole_data.workspace_meta WHERE singleton`, 5)
	if err != nil {
		return SchemaDeployment{}, err
	}
	result, err := parseSchemaDeploymentRow(row, roleTag, workspaceID)
	if err != nil {
		return SchemaDeployment{}, err
	}
	if tag, err := executeDeploymentScript(ctx, conn, "COMMIT"); err != nil || tag != "COMMIT" || conn.TxStatus() != 'I' {
		return SchemaDeployment{}, errors.Join(ErrQuery, ctx.Err())
	}
	return result, nil
}

func deploymentCatalog(ctx context.Context, conn *pgconn.PgConn, roleTag, workspaceID string) (string, error) {
	hashes, err := deploy.RoutineSourceHashes(roleTag, workspaceID)
	if err != nil {
		return "", err
	}
	row, err := readDeploymentRow(ctx, conn, deploymentCatalogSQL, 2, []byte(roleTag), hashes)
	if err != nil {
		return "", err
	}
	if len(row[0]) != 44 || string(row[1]) != "0" {
		return "", ErrDeploymentMismatch
	}
	return string(row[0]), nil
}

func readDeploymentRow(ctx context.Context, conn *pgconn.PgConn, query string, columns int, args ...[]byte) ([][]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	result := conn.ExecParams(ctx, query, args, nil, nil, nil)
	if !result.NextRow() {
		_, err := result.Close()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err != nil && !hasSQLState(err, "42P01", 0) && !hasSQLState(err, "42703", 0) {
			return nil, ErrQuery
		}
		return nil, ErrDeploymentMismatch
	}
	values := result.Values()
	if len(values) != columns || len(result.FieldDescriptions()) != columns {
		return nil, ErrDeploymentMismatch
	}
	row := make([][]byte, len(values))
	for i, value := range values {
		if len(value) > 63 {
			return nil, ErrDeploymentMismatch
		}
		row[i] = append([]byte(nil), value...)
	}
	if result.NextRow() {
		return nil, ErrDeploymentMismatch
	}
	if _, err := result.Close(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrQuery
	}
	return row, nil
}

func parseSchemaDeploymentRow(row [][]byte, roleTag, workspaceID string) (SchemaDeployment, error) {
	if len(row) != 5 {
		return SchemaDeployment{}, ErrDeploymentMismatch
	}
	state, tls := string(row[3]), string(row[4])
	if string(row[0]) != workspaceID || string(row[1]) != roleTag || string(row[2]) != strconv.Itoa(deploy.SchemaVersion) ||
		(state != "provisioning" && state != "ready") || (tls != "true" && tls != "false") {
		return SchemaDeployment{}, ErrDeploymentMismatch
	}
	return SchemaDeployment{Version: deploy.SchemaVersion, Provisioning: state == "provisioning", RequiresTLS: tls == "true"}, nil
}
