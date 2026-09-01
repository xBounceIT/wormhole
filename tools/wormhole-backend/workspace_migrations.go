package main

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type workspaceMigration struct {
	id        string
	ensure    func(context.Context, *sql.Conn) error
	transform []string
}

type workspaceColumn struct {
	name       string
	definition string
}

// ensureElectronWorkspaceSchema gives the Go backend ownership of the Electron database while
// keeping the file fully interoperable with the legacy WinUI 3 migration runner. Every shared
// migration id is recorded only after its final schema and one-time data transform are complete.
func ensureElectronWorkspaceSchema(databasePath string) error {
	database, err := openDatabase(databasePath, false)
	if err != nil {
		return err
	}
	defer database.Close()

	ctx := context.Background()
	connection, err := database.Conn(ctx)
	if err != nil {
		return fmt.Errorf("cannot open the Wormhole migration connection: %w", err)
	}
	defer connection.Close()
	if _, err := connection.ExecContext(ctx, "BEGIN IMMEDIATE;"); err != nil {
		return fmt.Errorf("cannot lock the Wormhole database for migration: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = connection.ExecContext(ctx, "ROLLBACK;")
		}
	}()

	if _, err := connection.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS __migration_history (
    Id           TEXT PRIMARY KEY NOT NULL,
    AppliedAtUtc TEXT NOT NULL
);`); err != nil {
		return fmt.Errorf("cannot create the Wormhole migration history: %w", err)
	}

	migrations := []workspaceMigration{
		{
			id: "0001_initial",
			ensure: func(ctx context.Context, connection *sql.Conn) error {
				_, err := connection.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS Nodes (
    Id                       TEXT PRIMARY KEY NOT NULL,
    ParentId                 TEXT NULL REFERENCES Nodes(Id) ON DELETE CASCADE,
    Name                     TEXT NOT NULL,
    Kind                     INTEGER NOT NULL,
    SortOrder                INTEGER NOT NULL DEFAULT 0,
    Protocol                 INTEGER NULL,
    Host                     TEXT NULL,
    Port                     INTEGER NULL,
    HttpPath                 TEXT NULL,
    Username                 TEXT NULL,
    CredentialId             TEXT NULL,
    RdpDomain                TEXT NULL,
    RdpScreenSize            TEXT NULL,
    RdpFullScreen            INTEGER NULL,
    SshKeyFileName           TEXT NULL,
    SshKnownHostFingerprint  TEXT NULL,
    CreatedAt                TEXT NOT NULL,
    UpdatedAt                TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS IX_Nodes_ParentId ON Nodes(ParentId);
CREATE TABLE IF NOT EXISTS CredentialProfiles (
    Id                  TEXT PRIMARY KEY NOT NULL,
    Name                TEXT NOT NULL,
    Username            TEXT NULL,
    Domain              TEXT NULL,
    Kind                INTEGER NOT NULL,
    PrivateKeyFileName  TEXT NULL,
    CreatedAt           TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS UX_CredentialProfiles_Name ON CredentialProfiles(Name);`)
				return err
			},
		},
		{
			id: "0002_credential_protocol",
			ensure: func(ctx context.Context, connection *sql.Conn) error {
				return ensureWorkspaceColumns(ctx, connection, "CredentialProfiles", []workspaceColumn{
					{"Protocol", "INTEGER NOT NULL DEFAULT 0"},
				})
			},
			transform: []string{`UPDATE CredentialProfiles
SET Protocol = 1
WHERE Domain IS NOT NULL AND TRIM(Domain) <> '';`},
		},
		{
			id: "0003_add_tunnel_config",
			ensure: func(ctx context.Context, connection *sql.Conn) error {
				if err := ensureWorkspaceColumns(ctx, connection, "Nodes", []workspaceColumn{
					{"TunnelEnabled", "INTEGER NULL"},
					{"TunnelConfigId", "TEXT NULL"},
				}); err != nil {
					return err
				}
				_, err := connection.ExecContext(ctx, `
CREATE INDEX IF NOT EXISTS IX_Nodes_TunnelConfigId
    ON Nodes(TunnelConfigId) WHERE TunnelConfigId IS NOT NULL;
CREATE TABLE IF NOT EXISTS TunnelConfigs (
    Id        TEXT PRIMARY KEY NOT NULL,
    Name      TEXT NOT NULL,
    Kind      INTEGER NOT NULL,
    CreatedAt TEXT NOT NULL,
    UpdatedAt TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS UX_TunnelConfigs_Name ON TunnelConfigs(Name);`)
				return err
			},
		},
		{
			id: "0003_rdp_extras",
			ensure: func(ctx context.Context, connection *sql.Conn) error {
				return ensureWorkspaceColumns(ctx, connection, "Nodes", []workspaceColumn{
					{"RdpColorDepth", "INTEGER NULL"},
					{"RdpUseAllMonitors", "INTEGER NULL"},
					{"RdpAudioMode", "INTEGER NULL"},
					{"RdpAudioCaptureMode", "INTEGER NULL"},
					{"RdpKeyboardHookMode", "INTEGER NULL"},
					{"RdpRedirectClipboard", "INTEGER NULL"},
					{"RdpRedirectPrinters", "INTEGER NULL"},
					{"RdpRedirectSmartCards", "INTEGER NULL"},
					{"RdpRedirectPorts", "INTEGER NULL"},
					{"RdpRedirectDevices", "INTEGER NULL"},
					{"RdpRedirectDrives", "TEXT NULL"},
					{"RdpConnectionSpeed", "INTEGER NULL"},
					{"RdpDesktopBackground", "INTEGER NULL"},
					{"RdpFontSmoothing", "INTEGER NULL"},
					{"RdpDesktopComposition", "INTEGER NULL"},
					{"RdpWindowDrag", "INTEGER NULL"},
					{"RdpMenuAnimation", "INTEGER NULL"},
					{"RdpVisualStyles", "INTEGER NULL"},
					{"RdpBitmapCaching", "INTEGER NULL"},
					{"RdpAutoReconnect", "INTEGER NULL"},
					{"RdpServerAuthentication", "INTEGER NULL"},
					{"RdpGatewayUsageMethod", "INTEGER NULL"},
					{"RdpGatewayHostname", "TEXT NULL"},
					{"RdpGatewayCredentialId", "TEXT NULL"},
					{"RdpGatewayBypassLocal", "INTEGER NULL"},
					{"RdpGatewayUseSameCreds", "INTEGER NULL"},
				})
			},
		},
		{
			id: "0004_rdp_use_external_client",
			ensure: func(ctx context.Context, connection *sql.Conn) error {
				return ensureWorkspaceColumns(ctx, connection, "Nodes", []workspaceColumn{
					{"RdpUseExternalClient", "INTEGER NULL"},
				})
			},
		},
		{
			id: "0005_aad_credentials_use_external_client",
			transform: []string{`UPDATE Nodes
SET RdpUseExternalClient = 1
WHERE Kind = 1 AND Protocol = 1
  AND (RdpUseExternalClient IS NULL OR RdpUseExternalClient = 0)
  AND CredentialId IN (
      SELECT Id FROM CredentialProfiles
      WHERE LOWER(IFNULL(Domain, '')) = 'azuread'
         OR LOWER(IFNULL(Username, '')) LIKE 'azuread\%'
  );`},
		},
		{
			id: "0006_aad_node_fields_use_external_client",
			transform: []string{`UPDATE Nodes
SET RdpUseExternalClient = 1
WHERE Kind = 1 AND Protocol = 1
  AND (RdpUseExternalClient IS NULL OR RdpUseExternalClient = 0)
  AND (
      LOWER(IFNULL(TRIM(RdpDomain), '')) = 'azuread'
      OR LOWER(IFNULL(Username, '')) LIKE 'azuread\%'
  );`},
		},
		{
			id: "0007_nodes_parent_sort_index",
			ensure: func(ctx context.Context, connection *sql.Conn) error {
				_, err := connection.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS IX_Nodes_ParentId_SortOrder_Name
ON Nodes(ParentId, SortOrder, Name);`)
				return err
			},
		},
		{
			id: "0007_rdp_server_auth_warn_mapping",
			transform: []string{`UPDATE Nodes
SET RdpServerAuthentication = CASE RdpServerAuthentication
    WHEN 0 THEN 2
    WHEN 2 THEN 1
    ELSE RdpServerAuthentication
END
WHERE RdpServerAuthentication IN (0, 2);`},
		},
		{
			id: "0008_ssh_auto_sudo",
			ensure: func(ctx context.Context, connection *sql.Conn) error {
				return ensureWorkspaceColumns(ctx, connection, "Nodes", []workspaceColumn{
					{"SshAutoSudo", "INTEGER NULL"},
				})
			},
		},
		{
			id:        "0009_drop_sftp_protocol",
			transform: []string{"UPDATE Nodes SET Protocol = 0 WHERE Protocol = 2;"},
		},
		{
			id: "0010_inline_password",
			ensure: func(ctx context.Context, connection *sql.Conn) error {
				return ensureWorkspaceColumns(ctx, connection, "Nodes", []workspaceColumn{
					{"UseInlinePassword", "INTEGER NULL"},
				})
			},
		},
		{
			id: "0011_http_ignore_cert_errors",
			ensure: func(ctx context.Context, connection *sql.Conn) error {
				return ensureWorkspaceColumns(ctx, connection, "Nodes", []workspaceColumn{
					{"HttpIgnoreCertErrors", "INTEGER NULL"},
				})
			},
		},
		{
			id: "0012_credential_inheritance",
			ensure: func(ctx context.Context, connection *sql.Conn) error {
				return ensureWorkspaceColumns(ctx, connection, "Nodes", []workspaceColumn{
					{"CredentialMode", "INTEGER NULL"},
				})
			},
		},
		{
			id: "0013_serial_protocol",
			ensure: func(ctx context.Context, connection *sql.Conn) error {
				return ensureWorkspaceColumns(ctx, connection, "Nodes", []workspaceColumn{
					{"SerialBaudRate", "INTEGER NULL"},
					{"SerialDataBits", "INTEGER NULL"},
					{"SerialStopBits", "INTEGER NULL"},
					{"SerialParity", "INTEGER NULL"},
					{"SerialFlowControl", "INTEGER NULL"},
				})
			},
		},
		{
			id: "0014_bitwarden_credentials",
			ensure: func(ctx context.Context, connection *sql.Conn) error {
				return ensureWorkspaceColumns(ctx, connection, "CredentialProfiles", []workspaceColumn{
					{"SecretProvider", "INTEGER NOT NULL DEFAULT 0"},
					{"BitwardenItemId", "TEXT NULL"},
					{"BitwardenItemName", "TEXT NULL"},
					{"BitwardenFieldPath", "TEXT NOT NULL DEFAULT 'login.password'"},
				})
			},
		},
		{
			id: "0015_bitwarden_credential_cache",
			ensure: func(ctx context.Context, connection *sql.Conn) error {
				_, err := connection.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS BitwardenCredentialCache (
    ItemId          TEXT PRIMARY KEY NOT NULL,
    SshCredentialId TEXT NOT NULL,
    RdpCredentialId TEXT NOT NULL,
    VncCredentialId TEXT NOT NULL,
    Name            TEXT NOT NULL,
    Username        TEXT NULL,
    RevisionDate    TEXT NULL,
    LastSeenSyncUtc TEXT NOT NULL,
    UpdatedAtUtc    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS IX_BitwardenCredentialCache_Name
    ON BitwardenCredentialCache(Name);`)
				return err
			},
		},
		{
			id: "0016_credential_private_key_operations",
			ensure: func(ctx context.Context, connection *sql.Conn) error {
				_, err := connection.ExecContext(ctx, credentialPrivateKeyOperationsTableSQL)
				return err
			},
		},
		{
			id: "0017_credential_secret_operations",
			ensure: func(ctx context.Context, connection *sql.Conn) error {
				_, err := connection.ExecContext(ctx, credentialSecretOperationsTableSQL)
				return err
			},
		},
		{
			id: "0018_http_path",
			ensure: func(ctx context.Context, connection *sql.Conn) error {
				return ensureWorkspaceColumns(ctx, connection, "Nodes", []workspaceColumn{
					{"HttpPath", "TEXT NULL"},
				})
			},
		},
	}

	for _, migration := range migrations {
		if err := applyWorkspaceMigration(ctx, connection, migration); err != nil {
			return err
		}
	}
	if _, err := connection.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS CredentialSecrets (
    Id        TEXT PRIMARY KEY NOT NULL,
    Secret    TEXT NOT NULL,
    Encoding  TEXT NOT NULL,
    UpdatedAt TEXT NOT NULL
);`); err != nil {
		return fmt.Errorf("cannot create the credential secret table: %w", err)
	}
	if _, err := connection.ExecContext(ctx, "COMMIT;"); err != nil {
		return fmt.Errorf("cannot commit the Wormhole database migrations: %w", err)
	}
	committed = true
	return nil
}

func applyWorkspaceMigration(
	ctx context.Context,
	connection *sql.Conn,
	migration workspaceMigration,
) error {
	if migration.ensure != nil {
		if err := migration.ensure(ctx, connection); err != nil {
			return fmt.Errorf("cannot ensure Wormhole migration %s: %w", migration.id, err)
		}
	}
	var applied int
	if err := connection.QueryRowContext(
		ctx,
		"SELECT COUNT(*) FROM __migration_history WHERE Id = ?;",
		migration.id,
	).Scan(&applied); err != nil {
		return fmt.Errorf("cannot inspect Wormhole migration %s: %w", migration.id, err)
	}
	if applied != 0 {
		return nil
	}
	for _, statement := range migration.transform {
		if _, err := connection.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("cannot apply Wormhole migration %s: %w", migration.id, err)
		}
	}
	if _, err := connection.ExecContext(
		ctx,
		"INSERT INTO __migration_history (Id, AppliedAtUtc) VALUES (?, ?);",
		migration.id,
		time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		return fmt.Errorf("cannot record Wormhole migration %s: %w", migration.id, err)
	}
	return nil
}

func ensureWorkspaceColumns(
	ctx context.Context,
	connection *sql.Conn,
	table string,
	columns []workspaceColumn,
) error {
	existing := make(map[string]struct{})
	rows, err := connection.QueryContext(ctx, "PRAGMA table_info("+table+");")
	if err != nil {
		return err
	}
	for rows.Next() {
		var sequence, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err := rows.Scan(&sequence, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return err
		}
		existing[name] = struct{}{}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, column := range columns {
		if _, present := existing[column.name]; present {
			continue
		}
		if _, err := connection.ExecContext(
			ctx,
			"ALTER TABLE "+table+" ADD COLUMN "+column.name+" "+column.definition+";",
		); err != nil {
			return err
		}
	}
	return nil
}
