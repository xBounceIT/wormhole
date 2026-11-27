package sharedpg

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// ValidateDeploymentTarget checks the wizard's public transport data without
// creating a driver connection or consulting ambient PostgreSQL settings.
func ValidateDeploymentTarget(endpoint Endpoint, database string, caPEM []byte) error {
	if !validDeploymentCABundle(caPEM) {
		return ErrConfiguration
	}
	_, err := validateTransportSettings(Settings{Endpoints: []Endpoint{endpoint}, Database: database, DeviceRole: "deployer", TLS: TLSVerified, CAPEM: caPEM, Profile: vault.Standard})
	return err
}

// A saved deployment plan may contain only public certificate material.
// CertPool alone silently skips other PEM blocks, including private keys.
func validDeploymentCABundle(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 256*1024 {
		return false
	}
	const start = "-----BEGIN CERTIFICATE-----"
	const end = "-----END CERTIFICATE-----"
	count := 0
	for rest := bytes.TrimSpace(raw); len(rest) > 0; rest = bytes.TrimSpace(rest) {
		if rest[0] == '#' {
			_, rest, _ = bytes.Cut(rest, []byte{'\n'})
			continue
		}
		beforeEnd, afterEnd, ok := bytes.Cut(rest, []byte(end))
		if !ok || !bytes.HasPrefix(beforeEnd, []byte(start)) || bytes.Contains(beforeEnd[len(start):], []byte("-----BEGIN")) {
			return false
		}
		block, _ := pem.Decode(rest[:len(beforeEnd)+len(end)])
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return false
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return false
		}
		count++
		rest = afterEnd
	}
	return count > 0
}

// DeploymentPreflight contains only fixed diagnostic fields. A successful
// connection already proved that the named database exists and accepted SCRAM.
// If TLS is enabled it also proved SCRAM-PLUS on the actual transport.
type DeploymentPreflight struct {
	ServerVersion      int     `json:"serverVersion"`
	TLS                TLSMode `json:"tls"`
	CanCreateRoles     bool    `json:"canCreateRoles"`
	OwnsDatabase       bool    `json:"ownsDatabase"`
	OwnsPublicSchema   bool    `json:"ownsPublicSchema"`
	CanGrantStatistics bool    `json:"canGrantStatistics"`
	EmptyDatabase      bool    `json:"emptyDatabase"`
	DeploymentLogging
}

type DeploymentLogging struct {
	LogsStatements    bool   `json:"logsStatements"`
	LogsParameters    bool   `json:"logsParameters"`
	StatementTracking string `json:"statementTracking"`
}

// ReadyToDeploy summarizes the server prerequisites observed here. The first
// migration rechecks emptiness and checks cluster role collisions. This check
// performs no DDL and retains no credential.
func (p DeploymentPreflight) ReadyToDeploy() bool {
	return p.ServerVersion >= 160000 && p.CanCreateRoles && p.OwnsDatabase && p.OwnsPublicSchema && p.CanGrantStatistics && p.EmptyDatabase
}

// Use the same namespaces and object categories as the migration 0001 guard.
const deploymentPreflightSQL = `WITH custom_namespace AS (
 SELECT oid,nspname FROM pg_catalog.pg_namespace WHERE nspname NOT IN ('pg_catalog','information_schema') AND nspname !~ '^pg_'
)
SELECT
 pg_catalog.current_setting('server_version_num'),
 (r.rolsuper OR r.rolcreaterole)::text,
 (r.rolsuper OR pg_catalog.pg_has_role(d.datdba, 'USAGE'))::text,
 (n.oid IS NOT NULL AND (r.rolsuper OR pg_catalog.pg_has_role(n.nspowner, 'USAGE')))::text,
 (r.rolsuper OR EXISTS (
  SELECT 1 FROM pg_catalog.pg_auth_members AS m JOIN pg_catalog.pg_roles AS target ON target.oid=m.roleid
  WHERE target.rolname='pg_read_all_stats' AND m.admin_option AND pg_catalog.pg_has_role(m.member, 'USAGE')
 ))::text,
 (NOT EXISTS (SELECT FROM custom_namespace WHERE nspname <> 'public')
  AND NOT EXISTS (SELECT FROM pg_catalog.pg_class c JOIN custom_namespace n ON n.oid=c.relnamespace)
  AND NOT EXISTS (SELECT FROM pg_catalog.pg_proc p JOIN custom_namespace n ON n.oid=p.pronamespace)
  AND NOT EXISTS (SELECT FROM pg_catalog.pg_type t JOIN custom_namespace n ON n.oid=t.typnamespace))::text,` + deploymentLoggingColumns + `
FROM pg_catalog.pg_roles AS r, pg_catalog.pg_database AS d
LEFT JOIN pg_catalog.pg_namespace AS n ON n.nspname='public'
WHERE r.rolname=current_user AND d.datname=pg_catalog.current_database()`

const deploymentLoggingColumns = `
 (pg_catalog.current_setting('log_statement') <> 'none')::text,
 (pg_catalog.current_setting('log_parameter_max_length') <> '0'
  OR pg_catalog.current_setting('log_parameter_max_length_on_error') <> '0')::text,
 coalesce(pg_catalog.current_setting('pg_stat_statements.track', true), 'unavailable')`

func CheckDeploymentPrerequisites(ctx context.Context, settings Settings, password []byte) (DeploymentPreflight, error) {
	conn, err := connectForDeploymentCheck(ctx, settings, password)
	if err != nil {
		return DeploymentPreflight{}, err
	}
	defer closeDeploymentConnection(conn)
	row, err := readDeploymentRow(ctx, conn, deploymentPreflightSQL, 9)
	if err != nil {
		return DeploymentPreflight{}, err
	}
	return parseDeploymentPreflight(row, settings.TLS)
}

func parseDeploymentPreflight(row [][]byte, tls TLSMode) (DeploymentPreflight, error) {
	if len(row) != 9 {
		return DeploymentPreflight{}, ErrDeploymentMismatch
	}
	version, err := strconv.Atoi(string(row[0]))
	if err != nil || version <= 0 || strconv.Itoa(version) != string(row[0]) {
		return DeploymentPreflight{}, ErrDeploymentMismatch
	}
	logging, err := parseDeploymentLogging(row[6:])
	if err != nil {
		return DeploymentPreflight{}, err
	}
	p := DeploymentPreflight{ServerVersion: version, TLS: tls, DeploymentLogging: logging}
	for i, dst := range []*bool{&p.CanCreateRoles, &p.OwnsDatabase, &p.OwnsPublicSchema, &p.CanGrantStatistics, &p.EmptyDatabase} {
		switch string(row[i+1]) {
		case "true":
			*dst = true
		case "false":
		default:
			return DeploymentPreflight{}, ErrDeploymentMismatch
		}
	}
	return p, nil
}

func parseDeploymentLogging(row [][]byte) (DeploymentLogging, error) {
	if len(row) != 3 || (string(row[0]) != "true" && string(row[0]) != "false") || (string(row[1]) != "true" && string(row[1]) != "false") {
		return DeploymentLogging{}, ErrDeploymentMismatch
	}
	p := DeploymentLogging{LogsStatements: string(row[0]) == "true", LogsParameters: string(row[1]) == "true", StatementTracking: string(row[2])}
	switch p.StatementTracking {
	case "none", "top", "all", "unavailable":
		return p, nil
	default:
		return DeploymentLogging{}, ErrDeploymentMismatch
	}
}
