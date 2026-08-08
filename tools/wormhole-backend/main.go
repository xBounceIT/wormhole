package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	_ "modernc.org/sqlite"
)

const (
	windowsCredentialMigrationID = "windows-credential-manager-to-sqlite-v1"
	tunnelConfigMigrationID      = "0003_add_tunnel_config"
	credentialPrefix             = "Wormhole:"
	mcpTokenCredentialID         = "a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91"
	credentialReaderTimeout      = 15 * time.Second
	credentialReaderMaxOutput    = 16 * 1024 * 1024
	backendMaxRequestBytes       = 64 * 1024
	backendMaxTunnelRequestBytes = 4 * 1024 * 1024
	maxCredentialTargetLength    = 256
	maxCredentialAccountLength   = 513
	maxCredentialPasswordUnits   = 1280
)

type migrationResult struct {
	Status   string `json:"status"`
	Migrated int    `json:"migrated"`
	Missing  int    `json:"missing"`
}

type credentialReaderEntry struct {
	Target   string `json:"target"`
	Account  string `json:"account"`
	Password string `json:"password"`
}

type workspaceSnapshot struct {
	Tree              []*treeNode                   `json:"tree"`
	Credentials       []credentialRecord            `json:"credentials"`
	CredentialOptions map[string][]credentialRecord `json:"credentialOptions"`
	Tunnels           []tunnelRecord                `json:"tunnels"`
}

type appSettingsSnapshot struct {
	PromptBeforeTunnelConnect bool    `json:"promptBeforeTunnelConnect"`
	AutoCopyOnSelect          bool    `json:"autoCopyOnSelect"`
	ConfirmOnTabClose         bool    `json:"confirmOnTabClose"`
	SidebarWidth              int     `json:"sidebarWidth"`
	AutoCheckForUpdates       bool    `json:"autoCheckForUpdates"`
	LastUpdateCheck           *string `json:"lastUpdateCheck"`
	SkippedUpdateVersion      *string `json:"skippedUpdateVersion"`
}

// startupSnapshot deliberately returns the workspace only while app authentication is disabled.
// A configured workspace crosses the process boundary only after startupUnlock has verified the
// user's secret. Combining these reads in one process avoids paying the Windows process, logging,
// settings, and SQLite initialization costs several times during every launch.
type startupSnapshot struct {
	Auth            authStateResponse   `json:"auth"`
	Workspace       *workspaceSnapshot  `json:"workspace,omitempty"`
	Settings        appSettingsSnapshot `json:"settings"`
	Migration       migrationResult     `json:"migration"`
	MigrationFailed bool                `json:"migrationFailed"`
}

type startupUnlockSnapshot struct {
	Succeeded bool               `json:"succeeded"`
	Message   string             `json:"message"`
	Workspace *workspaceSnapshot `json:"workspace,omitempty"`
}

type treeNode struct {
	ID                   string      `json:"id"`
	Name                 string      `json:"name"`
	Kind                 string      `json:"kind"`
	Protocol             string      `json:"protocol,omitempty"`
	Host                 string      `json:"host,omitempty"`
	Port                 int         `json:"port,omitempty"`
	SerialBaudRate       *int        `json:"serialBaudRate,omitempty"`
	SerialDataBits       *int        `json:"serialDataBits,omitempty"`
	SerialStopBits       *int        `json:"serialStopBits,omitempty"`
	SerialParity         *int        `json:"serialParity,omitempty"`
	SerialFlowControl    *int        `json:"serialFlowControl,omitempty"`
	HTTPIgnoreCertErrors *bool       `json:"httpIgnoreCertErrors,omitempty"`
	Children             []*treeNode `json:"children,omitempty"`
	SshAutoSudo          *bool       `json:"sshAutoSudo,omitempty"`
	TunnelEnabled        *bool       `json:"tunnelEnabled,omitempty"`
	TunnelConfigID       string      `json:"tunnelConfigId,omitempty"`
	CredentialMode       *int        `json:"credentialMode,omitempty"`
	CredentialID         string      `json:"credentialId,omitempty"`
	Persisted            bool        `json:"persisted,omitempty"`
}

type workspaceNodeSshSettingsRequest struct {
	NodeID      string `json:"nodeId"`
	SshAutoSudo *bool  `json:"sshAutoSudo"`
}

type workspaceNodeWebSettingsRequest struct {
	NodeID               string `json:"nodeId"`
	HTTPIgnoreCertErrors *bool  `json:"httpIgnoreCertErrors"`
}

type workspaceNodeTunnelSettingsRequest struct {
	NodeID         string `json:"nodeId"`
	TunnelEnabled  *bool  `json:"tunnelEnabled"`
	TunnelConfigID string `json:"tunnelConfigId"`
}

type workspaceNodeCredentialSettingsRequest struct {
	NodeID       string `json:"nodeId"`
	Mode         int    `json:"mode"`
	CredentialID string `json:"credentialId"`
}

type credentialsForProtocolRequest struct {
	Protocol string `json:"protocol"`
}

type credentialRecord struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Protocol           string `json:"protocol"`
	Username           string `json:"username"`
	Domain             string `json:"domain,omitempty"`
	Provider           string `json:"provider"`
	CanEdit            bool   `json:"canEdit"`
	CanDelete          bool   `json:"canDelete"`
	BitwardenItemID    string `json:"bitwardenItemId,omitempty"`
	BitwardenItemName  string `json:"bitwardenItemName,omitempty"`
	IsVirtualBitwarden bool   `json:"isVirtualBitwarden,omitempty"`
}

type tunnelRecord struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type nodeRow struct {
	ID                   string
	ParentID             sql.NullString
	Name                 string
	Kind                 int64
	SortOrder            int64
	Protocol             sql.NullInt64
	Host                 sql.NullString
	Port                 sql.NullInt64
	SshAutoSudo          sql.NullInt64
	HTTPIgnoreCertErrors sql.NullInt64
	TunnelEnabled        sql.NullInt64
	TunnelConfigID       sql.NullString
	CredentialMode       sql.NullInt64
	CredentialID         sql.NullString
}

type credentialRow struct {
	ID       string
	Name     string
	Username sql.NullString
	Domain   sql.NullString
	Protocol int64
	Provider int64
	Kind     int64
}

type tunnelRow struct {
	ID   string
	Name string
	Kind int64
}

func main() {
	operation := flag.String("operation", "workspace", "backend operation: startup, startup-unlock, workspace, workspace-duplicate-node, workspace-delete-node, workspace-show-credentials, backup-*, credential-*, tunnel-*, workspace-node-*, workspace-update-node-*, web-target, migrate, ssh, serial, ssh-trust-host-key, logs-info, settings-set-log-retention, settings-set-log-level, open-log-file, open-logs-folder, serve, rdp, extension-*, bitwarden-*, or auth-*")
	databasePath := flag.String("database", "", "path to the Wormhole SQLite database")
	electronUserDataPath := flag.String("electron-user-data", "", "path to the Electron user-data directory")
	credentialReader := flag.String("credential-reader", "", "path to the Windows Credential Manager reader")
	rdpHost := flag.String("rdp-host", "", "path to the Windows ActiveX RDP host")
	freerdpPath := flag.String("freerdp", "", "path to the FreeRDP client")
	flag.Parse()

	if *databasePath == "" {
		writeError("database path is required")
		os.Exit(1)
		return
	}
	initAppLogging(*databasePath)
	defer closeAppLog()
	if err := ensureElectronWorkspaceSchema(*databasePath); err != nil {
		writeError(err.Error())
		os.Exit(1)
		return
	}
	if *operation == "ssh" {
		logInfo("native SSH backend started")
		if err := serveSSH(*databasePath, os.Stdin, os.Stdout, *electronUserDataPath); err != nil {
			logError("native SSH backend failed: %v", err)
			writeError(err.Error())
			os.Exit(1)
		}
		logInfo("native SSH backend stopped")
		return
	}
	if *operation == "serial" {
		logInfo("native serial backend started")
		if err := serveSerial(*databasePath, os.Stdin, os.Stdout, *electronUserDataPath); err != nil {
			logError("native serial backend failed: %v", err)
			writeError(err.Error())
			os.Exit(1)
		}
		logInfo("native serial backend stopped")
		return
	}
	if *operation == "update-download" {
		// The download streams JSON progress lines to stdout and can run for minutes, so it
		// deliberately bypasses the one-shot result envelope of the other operations.
		if err := serveUpdateDownload(*databasePath, os.Stdin, os.Stdout); err != nil {
			writeError(err.Error())
			os.Exit(1)
		}
		return
	}
	var result any
	var err error
	logDebug("backend operation %s started", *operation)
	switch *operation {
	case "startup":
		result, err = loadStartupSnapshot(*databasePath, *credentialReader)
	case "startup-unlock":
		var request authVerifyRequest
		err = decodeInput(&request)
		if err == nil {
			result, err = unlockStartup(*databasePath, request)
		}
	case "workspace":
		result, err = loadWorkspace(*databasePath)
		if err == nil {
			if workspace, ok := result.(workspaceSnapshot); ok {
				logInfo("workspace loaded: %d roots, %d credentials, %d tunnels", len(workspace.Tree), len(workspace.Credentials), len(workspace.Tunnels))
			}
		}
	case "workspace-duplicate-node":
		var request workspaceNodeRequest
		err = decodeInput(&request)
		if err == nil {
			result, err = duplicateWorkspaceNode(*databasePath, request)
		}
	case "workspace-delete-node":
		var request workspaceNodeRequest
		err = decodeInput(&request)
		if err == nil {
			result, err = deleteWorkspaceNode(*databasePath, request)
		}
	case "workspace-show-credentials":
		var request workspaceNodeRequest
		err = decodeInput(&request)
		if err == nil {
			result, err = showWorkspaceNodeCredentials(*databasePath, request, *electronUserDataPath)
		}
	case "mremote-import-inspect":
		var request mremoteImportRequest
		err = decodeInput(&request)
		if err == nil {
			result, err = inspectMRemoteImport(request)
		}
	case "mremote-import-analyze":
		var request mremoteImportRequest
		err = decodeInput(&request)
		if err == nil {
			result, err = analyzeMRemoteImport(*databasePath, request)
		}
	case "mremote-import-commit":
		var request mremoteImportRequest
		err = decodeInput(&request)
		if err == nil {
			result, err = commitMRemoteImport(*databasePath, request)
		}
	case "backup-inspect":
		var request backupRequest
		err = decodeInput(&request)
		if err == nil {
			result, err = inspectBackup(request)
		}
	case "backup-export":
		var request backupRequest
		err = decodeInput(&request)
		if err == nil {
			result, err = exportBackup(*databasePath, request)
		}
	case "backup-import":
		var request backupRequest
		err = decodeInput(&request)
		if err == nil {
			result, err = importBackup(*databasePath, request)
		}
	case "web-target":
		var request webTargetRequest
		err = decodeInput(&request)
		if err == nil {
			result, err = resolveWebTarget(*databasePath, request)
		}
	case "watchguard-import":
		var request watchguardImportRequest
		err = decodeInput(&request)
		if err == nil {
			result, err = importWatchguardFile(request)
		}
	case "azure-vpn-import":
		var request azureImportRequest
		err = decodeInput(&request)
		if err == nil {
			result, err = importAzureVPNFile(request)
		}
	case "cisco-profile-import":
		var request ciscoImportRequest
		err = decodeInput(&request)
		if err == nil {
			result, err = importCiscoProfileFile(request)
		}
	case "ovpn-file-import":
		var request ovpnImportRequest
		err = decodeInput(&request)
		if err == nil {
			result, err = importOvpnFile(request)
		}
	case "credential-create":
		var request credentialCreateRequest
		err = decodeInput(&request)
		if err == nil {
			result, err = createCredential(*databasePath, request)
		}
	case "credential-update":
		var request credentialUpdateRequest
		err = decodeInput(&request)
		if err == nil {
			result, err = updateCredential(*databasePath, request)
		}
	case "credential-delete":
		var request credentialDeleteRequest
		err = decodeInput(&request)
		if err == nil {
			err = deleteCredential(*databasePath, request)
			if err == nil {
				result = map[string]bool{"deleted": true}
			}
		}
	case "credentials-for-protocol":
		var request credentialsForProtocolRequest
		err = decodeInput(&request)
		if err == nil {
			result, err = loadCredentialsForProtocol(*databasePath, request.Protocol)
		}
	case "workspace-update-node":
		var request workspaceNodeSshSettingsRequest
		err = decodeInput(&request)
		if err == nil {
			err = updateWorkspaceNodeSshSettings(*databasePath, request)
			if err == nil {
				result = map[string]bool{"updated": true}
			}
		}
	case "workspace-update-node-web-settings":
		var request workspaceNodeWebSettingsRequest
		err = decodeInput(&request)
		if err == nil {
			err = updateWorkspaceNodeWebSettings(*databasePath, request)
			if err == nil {
				result = map[string]bool{"updated": true}
			}
		}
	case "workspace-update-node-tunnel":
		var request workspaceNodeTunnelSettingsRequest
		err = decodeInput(&request)
		if err == nil {
			err = updateWorkspaceNodeTunnelSettings(*databasePath, request)
			if err == nil {
				result = map[string]bool{"updated": true}
			}
		}
	case "workspace-update-node-credential":
		var request workspaceNodeCredentialSettingsRequest
		err = decodeInput(&request)
		if err == nil {
			err = updateWorkspaceNodeCredentialSettings(*databasePath, request)
			if err == nil {
				result = map[string]bool{"updated": true}
			}
		}
	case "workspace-node-create":
		var request workspaceNodeWriteRequest
		err = decodeInput(&request)
		if err == nil {
			var nodeID string
			nodeID, err = createWorkspaceNode(*databasePath, request)
			if err == nil {
				result = map[string]string{"nodeId": nodeID}
			}
		}
	case "workspace-node-update":
		var request workspaceNodeWriteRequest
		err = decodeInput(&request)
		if err == nil {
			err = updateWorkspaceNode(*databasePath, request)
			if err == nil {
				result = map[string]bool{"updated": true}
			}
		}
	case "tunnel-create":
		var request tunnelWriteRequest
		err = decodeInputLimit(os.Stdin, &request, backendMaxTunnelRequestBytes)
		if err == nil {
			result, err = createTunnel(*databasePath, request)
		}
	case "tunnel-read":
		var request tunnelReadRequest
		err = decodeInput(&request)
		if err == nil {
			result, err = readTunnel(*databasePath, request)
		}
	case "tunnel-update":
		var request tunnelWriteRequest
		err = decodeInputLimit(os.Stdin, &request, backendMaxTunnelRequestBytes)
		if err == nil {
			result, err = updateTunnel(*databasePath, request)
		}
	case "tunnel-delete":
		var request tunnelDeleteRequest
		err = decodeInput(&request)
		if err == nil {
			err = deleteTunnel(*databasePath, request)
			if err == nil {
				result = map[string]bool{"deleted": true}
			}
		}
	case "migrate":
		result, err = migrateCredentials(*databasePath, *credentialReader)
		if err == nil {
			if migration, ok := result.(migrationResult); ok {
				logInfo("credential migration completed: %d migrated, %d missing", migration.Migrated, migration.Missing)
			}
		}
	case "auth-status":
		result, err = authState(*databasePath)
	case "auth-verify":
		var request authVerifyRequest
		err = decodeInput(&request)
		if err == nil {
			result, err = authVerify(*databasePath, request)
		}
	case "auth-set-secret":
		var request authSetSecretRequest
		err = decodeInput(&request)
		if err == nil {
			result, err = authSetSecret(*databasePath, request)
		}
	case "auth-update-settings":
		var request authSettingsRequest
		err = decodeInput(&request)
		if err == nil {
			result, err = authUpdateSettings(*databasePath, request)
		}
	case "settings-read":
		var settings appSettingsValues
		settings, err = readAppSettings(*databasePath)
		if err == nil {
			result = map[string]any{
				"promptBeforeTunnelConnect": settings.PromptBeforeTunnelConnect,
				"autoCopyOnSelect":          settings.AutoCopyOnSelect,
				"confirmOnTabClose":         settings.ConfirmOnTabClose,
				"sidebarWidth":              settings.SidebarWidth,
				"autoCheckForUpdates":       settings.AutoCheckForUpdates,
				"lastUpdateCheck":           settings.LastUpdateCheck,
				"skippedUpdateVersion":      settings.SkippedUpdateVersion,
			}
		}
	case "settings-migrate":
		result, err = persistLegacySettingsMigration(*databasePath)
	case "settings-set-prompt-before-tunnel":
		var request struct {
			Enabled bool `json:"enabled"`
		}
		err = decodeInput(&request)
		if err == nil {
			err = writePromptBeforeTunnelConnect(*databasePath, request.Enabled)
			if err == nil {
				result = map[string]bool{"updated": true}
			}
		}
	case "settings-set-auto-copy-on-select":
		var request struct {
			Enabled bool `json:"enabled"`
		}
		err = decodeInput(&request)
		if err == nil {
			err = writeAutoCopyOnSelect(*databasePath, request.Enabled)
			if err == nil {
				result = map[string]bool{"updated": true}
			}
		}
	case "settings-set-confirm-on-tab-close":
		var request struct {
			Enabled *bool `json:"enabled"`
		}
		err = decodeInput(&request)
		if err == nil && request.Enabled == nil {
			err = errors.New("connected-tab close setting is invalid")
		}
		if err == nil && request.Enabled != nil {
			err = writeConfirmOnTabClose(*databasePath, *request.Enabled)
			if err == nil {
				result = map[string]bool{"updated": true}
			}
		}
	case "settings-set-sidebar-width":
		var request struct {
			Width *int `json:"width"`
		}
		err = decodeInput(&request)
		if err == nil && request.Width == nil {
			err = errors.New("sidebar width is invalid")
		}
		if err == nil && request.Width != nil {
			err = writeSidebarWidth(*databasePath, *request.Width)
			if err == nil {
				result = map[string]any{"updated": true, "sidebarWidth": clampSidebarWidth(*request.Width)}
			}
		}
	case "settings-set-update-preferences":
		var request struct {
			AutoCheckForUpdates  *bool           `json:"autoCheckForUpdates"`
			SkippedUpdateVersion json.RawMessage `json:"skippedUpdateVersion"`
		}
		err = decodeInput(&request)
		if err == nil {
			values := map[string]any{}
			if request.AutoCheckForUpdates != nil {
				values[autoCheckForUpdatesKey] = *request.AutoCheckForUpdates
			}
			if len(request.SkippedUpdateVersion) > 0 {
				var skipped *string
				if string(request.SkippedUpdateVersion) != "null" {
					var value string
					if json.Unmarshal(request.SkippedUpdateVersion, &value) != nil {
						err = errors.New("update preferences are invalid")
					} else {
						skipped = &value
					}
				}
				if err == nil {
					values[skippedUpdateVersionKey] = skipped
				}
			}
			if err == nil {
				err = writeSettingsValues(*databasePath, values)
			}
			if err == nil {
				result = map[string]bool{"updated": true}
			}
		}
	case "update-check":
		var request updateCheckRequest
		err = decodeInput(&request)
		if err == nil {
			result, err = checkForUpdate(*databasePath, request)
		}
	case "logs-info":
		result, err = logsInfo(*databasePath)
	case "settings-set-log-retention":
		var request struct {
			Days int `json:"days"`
		}
		err = decodeInput(&request)
		if err == nil {
			var days int
			days, err = writeLogRetentionDays(*databasePath, request.Days)
			if err == nil {
				result = map[string]any{"updated": true, "logRetentionDays": days}
			}
		}
	case "settings-set-log-level":
		var request struct {
			Level string `json:"level"`
		}
		err = decodeInput(&request)
		if err == nil {
			var level string
			level, err = writeLogLevel(*databasePath, request.Level)
			if err == nil {
				result = map[string]any{"updated": true, "logLevel": level}
			}
		}
	case "open-log-file":
		err = openCurrentDayLogFile(*databasePath)
		if err == nil {
			result = map[string]bool{"opened": true}
		}
	case "open-logs-folder":
		err = openLogsDirectory(*databasePath)
		if err == nil {
			result = map[string]bool{"opened": true}
		}
	case "bitwarden-onboarding-read":
		var request struct {
			AppVersion string `json:"appVersion"`
		}
		err = decodeInput(&request)
		if err == nil {
			result, err = readBitwardenOnboardingNotice(*databasePath, request.AppVersion)
		}
	case "bitwarden-onboarding-dismiss":
		err = dismissBitwardenOnboardingNotice(*databasePath)
		if err == nil {
			result = map[string]bool{"updated": true}
		}
	case "extension-read":
		result, err = readBitwardenExtensionState(*databasePath)
	case "extension-set-enabled":
		var request struct {
			Enabled bool `json:"enabled"`
		}
		err = decodeInput(&request)
		if err == nil {
			result, err = setBitwardenExtensionEnabled(*databasePath, request.Enabled)
		}
	case "extension-install":
		result, err = installBitwardenExtensionLatest(*databasePath)
	case "extension-ensure-installed":
		result, err = ensureBitwardenExtensionInstalled(*databasePath)
	case "extension-import-zip":
		var request struct {
			Path string `json:"path"`
		}
		err = decodeInput(&request)
		if err == nil {
			result, err = importBitwardenExtensionZip(*databasePath, request.Path)
		}
	case "extension-import-folder":
		var request struct {
			Path string `json:"path"`
		}
		err = decodeInput(&request)
		if err == nil {
			result, err = importBitwardenExtensionFolder(*databasePath, request.Path)
		}
	case "extension-update-if-stale":
		result, err = updateBitwardenExtensionIfStale(*databasePath)
	case "auth-hello-status":
		result = checkWindowsHello()
	case "auth-hello-verify":
		var request authHelloVerifyRequest
		err = decodeInput(&request)
		if err == nil {
			result = verifyWindowsHello(request)
		}
	case "auth-system-idle":
		result = map[string]int64{"seconds": systemIdleSeconds()}
	case "ssh-trust-host-key":
		var request sshHostKeyTrustRequest
		err = decodeInput(&request)
		if err == nil {
			err = trustSSHFingerprint(*databasePath, request)
			if err == nil {
				result = map[string]bool{"updated": true}
			}
		}
	case "serve":
		logInfo("native VNC backend started")
		if err := serveBackend(*databasePath, *electronUserDataPath); err != nil {
			logError("native VNC backend failed: %v", err)
			writeError(err.Error())
			os.Exit(1)
		}
		logInfo("native VNC backend stopped")
		return
	case "rdp":
		err = runRdpController(*databasePath, *rdpHost, *freerdpPath)
	default:
		err = fmt.Errorf("unsupported operation %q", *operation)
	}

	if err != nil {
		logError("backend operation %s failed: %v", *operation, err)
		writeError(err.Error())
		os.Exit(1)
		return
	}
	logDebug("backend operation %s completed", *operation)

	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		logError("failed to encode backend response: %v", err)
		writeError("failed to encode backend response")
		os.Exit(1)
	}
}

func decodeInput[T any](target *T) error {
	return decodeInputReader(os.Stdin, target)
}

func decodeInputReader[T any](reader io.Reader, target *T) error {
	return decodeInputLimit(reader, target, backendMaxRequestBytes)
}

func decodeInputLimit[T any](reader io.Reader, target *T, limit int64) error {
	contents, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil || len(contents) > int(limit) {
		return errors.New("backend request was invalid")
	}
	if err := json.Unmarshal(contents, target); err != nil {
		return errors.New("backend request was invalid")
	}
	return nil
}

// rdpOutputMu is deliberately process-wide. The RDP controller writes events from the
// FreeRDP wait goroutine and from the Windows helper's event reader while the command loop may
// also be writing acknowledgements. Interleaved JSON lines would make the IPC stream
// unrecoverable for the Electron main process.
var rdpOutputMu sync.Mutex

func writeError(message string) {
	// Backend errors are intentionally generic at the process boundary. In particular, never
	// include a credential value or a helper's raw output in stderr.
	_, _ = fmt.Fprintln(os.Stderr, message)
}

func openDatabase(databasePath string, readOnly bool) (*sql.DB, error) {
	if readOnly {
		if _, err := os.Stat(databasePath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, nil
			}
			return nil, fmt.Errorf("cannot inspect the Wormhole database: %w", err)
		}
	} else if err := os.MkdirAll(filepath.Dir(databasePath), 0o700); err != nil {
		return nil, fmt.Errorf("cannot create the Wormhole data directory: %w", err)
	}

	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		return nil, fmt.Errorf("cannot open the Wormhole database: %w", err)
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	if _, err := database.Exec("PRAGMA busy_timeout = 5000;"); err != nil {
		database.Close()
		return nil, fmt.Errorf("cannot configure the Wormhole database: %w", err)
	}
	if readOnly {
		if _, err := database.Exec("PRAGMA query_only = ON;"); err != nil {
			database.Close()
			return nil, fmt.Errorf("cannot configure read-only database access: %w", err)
		}
	}
	return database, nil
}

func ensureMigrationSchema(database *sql.DB) error {
	_, err := database.Exec(`
CREATE TABLE IF NOT EXISTS CredentialSecrets (
    Id        TEXT PRIMARY KEY NOT NULL,
    Secret    TEXT NOT NULL,
    Encoding  TEXT NOT NULL,
    UpdatedAt TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ElectronMigrations (
    Id            TEXT PRIMARY KEY NOT NULL,
    AppliedAt     TEXT NOT NULL,
    Status        TEXT NOT NULL,
    MigratedCount INTEGER NOT NULL DEFAULT 0,
    MissingCount  INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS TunnelConfigs (
    Id         TEXT PRIMARY KEY NOT NULL,
    Name       TEXT NOT NULL,
    Kind       INTEGER NOT NULL,
    CreatedAt  TEXT NOT NULL,
    UpdatedAt  TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS UX_TunnelConfigs_Name ON TunnelConfigs(Name);`)
	if err != nil {
		return fmt.Errorf("cannot create migration tables: %w", err)
	}
	nodesExist, err := tableExists(database, "Nodes")
	if err != nil {
		return err
	}
	if !nodesExist {
		return nil
	}
	columns, err := tableColumns(database, "Nodes")
	if err != nil {
		return err
	}
	for _, column := range []struct{ name, statement string }{
		{"TunnelEnabled", "ALTER TABLE Nodes ADD COLUMN TunnelEnabled INTEGER NULL;"},
		{"TunnelConfigId", "ALTER TABLE Nodes ADD COLUMN TunnelConfigId TEXT NULL;"},
	} {
		if _, exists := columns[column.name]; exists {
			continue
		}
		if _, err := database.Exec(column.statement); err != nil {
			refreshed, inspectErr := tableColumns(database, "Nodes")
			if inspectErr != nil {
				return inspectErr
			}
			if _, concurrentlyAdded := refreshed[column.name]; !concurrentlyAdded {
				return fmt.Errorf("cannot add VPN tunnel support: %w", err)
			}
		}
	}
	if _, err := database.Exec("CREATE INDEX IF NOT EXISTS IX_Nodes_TunnelConfigId ON Nodes(TunnelConfigId) WHERE TunnelConfigId IS NOT NULL;"); err != nil {
		return fmt.Errorf("cannot index VPN tunnel assignments: %w", err)
	}
	// Keep the legacy .NET runner interoperable while Go takes ownership of Electron migrations.
	// Without this marker, a later WinUI launch would replay 0003 and fail on duplicate columns.
	if _, err := database.Exec(`
CREATE TABLE IF NOT EXISTS __migration_history (
    Id TEXT PRIMARY KEY NOT NULL,
    AppliedAtUtc TEXT NOT NULL
);
INSERT OR IGNORE INTO __migration_history (Id, AppliedAtUtc) VALUES (?, ?);`,
		tunnelConfigMigrationID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("cannot record the VPN tunnel migration: %w", err)
	}
	return nil
}

func migrateCredentials(databasePath, readerPath string) (migrationResult, error) {
	return migrateCredentialsWithReader(databasePath, readerPath, readWindowsCredentials)
}

func loadStartupSnapshot(databasePath, readerPath string) (startupSnapshot, error) {
	migration, migrationErr := migrateCredentials(databasePath, readerPath)
	if migrationErr != nil {
		// Credential migration is retryable and has never been allowed to make the application
		// unusable. Keep the bootstrap useful while recording the failure in the native log.
		logError("credential migration failed during startup: %v", migrationErr)
	}

	auth, err := authState(databasePath)
	if err != nil {
		return startupSnapshot{}, err
	}
	settings, err := loadAppSettingsSnapshot(databasePath)
	if err != nil {
		return startupSnapshot{}, err
	}
	result := startupSnapshot{
		Auth:            auth,
		Settings:        settings,
		Migration:       migration,
		MigrationFailed: migrationErr != nil,
	}
	if auth.Configured {
		return result, nil
	}
	workspace, err := loadWorkspace(databasePath)
	if err != nil {
		return startupSnapshot{}, err
	}
	result.Workspace = &workspace
	return result, nil
}

func unlockStartup(databasePath string, request authVerifyRequest) (startupUnlockSnapshot, error) {
	verification, err := authVerify(databasePath, request)
	if err != nil {
		return startupUnlockSnapshot{}, err
	}
	result := startupUnlockSnapshot{
		Succeeded: verification.Succeeded,
		Message:   verification.Message,
	}
	if !verification.Succeeded {
		return result, nil
	}
	workspace, err := loadWorkspace(databasePath)
	if err != nil {
		return startupUnlockSnapshot{}, err
	}
	result.Workspace = &workspace
	return result, nil
}

func loadAppSettingsSnapshot(databasePath string) (appSettingsSnapshot, error) {
	settings, err := readAppSettings(databasePath)
	if err != nil {
		return appSettingsSnapshot{}, err
	}
	return appSettingsSnapshot{
		PromptBeforeTunnelConnect: settings.PromptBeforeTunnelConnect,
		AutoCopyOnSelect:          settings.AutoCopyOnSelect,
		ConfirmOnTabClose:         settings.ConfirmOnTabClose,
		SidebarWidth:              settings.SidebarWidth,
		AutoCheckForUpdates:       settings.AutoCheckForUpdates,
		LastUpdateCheck:           settings.LastUpdateCheck,
		SkippedUpdateVersion:      settings.SkippedUpdateVersion,
	}, nil
}

func migrateCredentialsWithReader(
	databasePath string,
	readerPath string,
	reader func(string) ([]credentialReaderEntry, error),
) (migrationResult, error) {
	if !isWindowsRuntime() {
		return migrationResult{Status: "skipped-non-windows"}, nil
	}

	database, err := openDatabase(databasePath, false)
	if err != nil {
		return migrationResult{}, err
	}
	defer database.Close()

	// The completed markers are the overwhelmingly common launch path. Checking them first
	// avoids replaying CREATE/ALTER/INDEX statements and schema introspection on every startup.
	// Older databases without both markers still take the full idempotent migration path.
	completed, err := startupMigrationsAlreadyApplied(database)
	if err != nil {
		return migrationResult{}, err
	}
	if completed {
		return migrationResult{Status: "already-completed"}, nil
	}

	if err := ensureMigrationSchema(database); err != nil {
		return migrationResult{}, err
	}
	completed, err = hasCompletedMigration(database)
	if err != nil {
		return migrationResult{}, err
	}
	if completed {
		return migrationResult{Status: "already-completed"}, nil
	}

	candidateIDs, err := readCandidateIDs(database)
	if err != nil {
		return migrationResult{}, err
	}
	if strings.TrimSpace(readerPath) == "" {
		return migrationResult{}, errors.New("Credential Manager reader is missing")
	}
	entries, err := reader(readerPath)
	if err != nil {
		return migrationResult{}, err
	}
	passwords := credentialPasswords(entries)

	secrets := make([]secretToStore, 0, len(candidateIDs))
	missing := 0
	for _, id := range candidateIDs {
		password, found := passwords[normalizeID(id)]
		if !found {
			missing++
			continue
		}
		secrets = append(secrets, secretToStore{ID: normalizeID(id), Value: password})
	}

	if _, err := database.Exec("BEGIN IMMEDIATE;"); err != nil {
		return migrationResult{}, fmt.Errorf("cannot lock the Wormhole database for migration: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = database.Exec("ROLLBACK;")
		}
	}()

	completed, err = hasCompletedMigration(database)
	if err != nil {
		return migrationResult{}, err
	}
	if completed {
		if _, err := database.Exec("ROLLBACK;"); err != nil {
			return migrationResult{}, fmt.Errorf("cannot release migration lock: %w", err)
		}
		committed = true
		return migrationResult{Status: "already-completed"}, nil
	}

	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	for _, secret := range secrets {
		protected, err := protectSecret(secret.Value)
		if err != nil {
			return migrationResult{}, fmt.Errorf("cannot protect a migrated credential: %w", err)
		}
		if _, err := database.Exec(`
INSERT INTO CredentialSecrets (Id, Secret, Encoding, UpdatedAt)
VALUES (?, ?, ?, ?)
ON CONFLICT(Id) DO NOTHING;`, secret.ID, protected, protectedSecretEncoding, timestamp); err != nil {
			return migrationResult{}, fmt.Errorf("cannot store migrated credentials: %w", err)
		}
	}

	if _, err := database.Exec(`
INSERT INTO ElectronMigrations (Id, AppliedAt, Status, MigratedCount, MissingCount)
VALUES (?, ?, 'completed', ?, ?)
ON CONFLICT(Id) DO UPDATE SET
    AppliedAt = excluded.AppliedAt,
    Status = excluded.Status,
    MigratedCount = excluded.MigratedCount,
    MissingCount = excluded.MissingCount;`, windowsCredentialMigrationID, timestamp, len(secrets), missing); err != nil {
		return migrationResult{}, fmt.Errorf("cannot record credential migration: %w", err)
	}

	if _, err := database.Exec("COMMIT;"); err != nil {
		return migrationResult{}, fmt.Errorf("cannot commit credential migration: %w", err)
	}
	committed = true
	return migrationResult{Status: "completed", Migrated: len(secrets), Missing: missing}, nil
}

func startupMigrationsAlreadyApplied(database *sql.DB) (bool, error) {
	for _, table := range []string{"ElectronMigrations", "__migration_history"} {
		exists, err := tableExists(database, table)
		if err != nil {
			return false, err
		}
		if !exists {
			return false, nil
		}
	}
	credentialMigrationComplete, err := hasCompletedMigration(database)
	if err != nil || !credentialMigrationComplete {
		return false, err
	}
	var schemaMigrationPresent int
	err = database.QueryRow(
		`SELECT 1 FROM __migration_history WHERE Id = ? LIMIT 1;`,
		tunnelConfigMigrationID,
	).Scan(&schemaMigrationPresent)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("cannot read the VPN tunnel migration status: %w", err)
	}
	return schemaMigrationPresent == 1, nil
}

type secretToStore struct {
	ID    string
	Value string
}

func hasCompletedMigration(database *sql.DB) (bool, error) {
	var present int
	err := database.QueryRow(`SELECT 1 FROM ElectronMigrations WHERE Id = ? AND Status = 'completed' LIMIT 1;`, windowsCredentialMigrationID).Scan(&present)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("cannot read migration status: %w", err)
	}
	return present == 1, nil
}

func readCandidateIDs(database *sql.DB) ([]string, error) {
	ids := map[string]struct{}{}
	if exists, err := tableExists(database, "CredentialProfiles"); err != nil {
		return nil, err
	} else if exists {
		columns, err := tableColumns(database, "CredentialProfiles")
		if err != nil {
			return nil, err
		}
		query := "SELECT Id FROM CredentialProfiles;"
		if _, ok := columns["SecretProvider"]; ok {
			query = "SELECT Id FROM CredentialProfiles WHERE SecretProvider IS NULL OR SecretProvider = 0;"
		}
		rows, err := database.Query(query)
		if err != nil {
			return nil, fmt.Errorf("cannot read credential profiles: %w", err)
		}
		if err := addIDRows(ids, rows); err != nil {
			return nil, err
		}
	}

	if exists, err := tableExists(database, "Nodes"); err != nil {
		return nil, err
	} else if exists {
		columns, err := tableColumns(database, "Nodes")
		if err != nil {
			return nil, err
		}
		if _, ok := columns["UseInlinePassword"]; ok {
			rows, err := database.Query("SELECT Id FROM Nodes WHERE UseInlinePassword = 1;")
			if err != nil {
				return nil, fmt.Errorf("cannot read inline-password connections: %w", err)
			}
			if err := addIDRows(ids, rows); err != nil {
				return nil, err
			}
		}
	}

	ids[normalizeID(mcpTokenCredentialID)] = struct{}{}
	result := make([]string, 0, len(ids))
	for id := range ids {
		result = append(result, id)
	}
	sort.Strings(result)
	return result, nil
}

func addIDRows(ids map[string]struct{}, rows *sql.Rows) error {
	defer rows.Close()
	for rows.Next() {
		var id sql.NullString
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("cannot read a credential ID: %w", err)
		}
		if id.Valid && strings.TrimSpace(id.String) != "" {
			ids[normalizeID(id.String)] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("cannot enumerate credential IDs: %w", err)
	}
	return nil
}

func tableExists(database *sql.DB, tableName string) (bool, error) {
	var present int
	err := database.QueryRow("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1;", tableName).Scan(&present)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("cannot inspect the database schema: %w", err)
	}
	return present == 1, nil
}

func tableColumns(database *sql.DB, tableName string) (map[string]struct{}, error) {
	rows, err := database.Query("PRAGMA table_info(" + tableName + ");")
	if err != nil {
		return nil, fmt.Errorf("cannot inspect the %s schema: %w", tableName, err)
	}
	defer rows.Close()
	columns := map[string]struct{}{}
	for rows.Next() {
		var cid int64
		var name string
		var columnType sql.NullString
		var notNull, primaryKey int64
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, fmt.Errorf("cannot read the %s schema: %w", tableName, err)
		}
		columns[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot enumerate the %s schema: %w", tableName, err)
	}
	return columns, nil
}

func readWindowsCredentials(executablePath string) ([]credentialReaderEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), credentialReaderTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, executablePath)
	command.Stderr = io.Discard
	output := &limitedOutput{limit: credentialReaderMaxOutput}
	command.Stdout = output
	err := command.Run()
	if output.exceeded {
		return nil, errors.New("Credential Manager reader returned too much data")
	}
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("Credential Manager reader timed out")
		}
		return nil, errors.New("Credential Manager reader failed")
	}

	var entries []credentialReaderEntry
	if err := json.Unmarshal(output.Bytes(), &entries); err != nil {
		return nil, errors.New("Credential Manager reader returned invalid data")
	}
	if entries == nil {
		return nil, errors.New("Credential Manager reader returned invalid data")
	}
	for _, entry := range entries {
		if !validCredentialReaderEntry(entry) {
			return nil, errors.New("Credential Manager reader returned an invalid credential entry")
		}
	}
	return entries, nil
}

func validCredentialReaderEntry(entry credentialReaderEntry) bool {
	if entry.Target == "" || len([]rune(entry.Target)) > maxCredentialTargetLength {
		return false
	}
	if entry.Account == "" || len([]rune(entry.Account)) > maxCredentialAccountLength {
		return false
	}
	return len(utf16.Encode([]rune(entry.Password))) <= maxCredentialPasswordUnits
}

func credentialPasswords(entries []credentialReaderEntry) map[string]string {
	passwords := make(map[string]string, len(entries))
	for _, entry := range entries {
		account := normalizeID(entry.Account)
		if entry.Target != credentialTarget(account) {
			continue
		}
		passwords[account] = entry.Password
	}
	return passwords
}

func credentialTarget(id string) string {
	return credentialPrefix + normalizeID(id)
}

func normalizeID(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}

func loadWorkspace(databasePath string) (workspaceSnapshot, error) {
	database, err := openDatabase(databasePath, true)
	if err != nil {
		return workspaceSnapshot{}, err
	}
	if database == nil {
		return workspaceSnapshot{
			Tree:              []*treeNode{},
			Credentials:       []credentialRecord{},
			CredentialOptions: emptyCredentialOptions(),
			Tunnels:           []tunnelRecord{},
		}, nil
	}
	defer database.Close()

	tree, err := loadTree(database)
	if err != nil {
		return workspaceSnapshot{}, err
	}
	credentials, err := loadCredentials(database, databasePath)
	if err != nil {
		return workspaceSnapshot{}, err
	}
	credentialOptions := emptyCredentialOptions()
	for _, protocol := range []string{"ssh", "rdp", "vnc"} {
		credentialOptions[protocol], err = loadCredentialsForProtocolFromDatabase(
			database,
			databasePath,
			protocol,
		)
		if err != nil {
			return workspaceSnapshot{}, err
		}
	}
	tunnels, err := loadTunnels(database)
	if err != nil {
		return workspaceSnapshot{}, err
	}
	return workspaceSnapshot{
		Tree:              tree,
		Credentials:       credentials,
		CredentialOptions: credentialOptions,
		Tunnels:           tunnels,
	}, nil
}

func emptyCredentialOptions() map[string][]credentialRecord {
	return map[string][]credentialRecord{
		"ssh": {},
		"rdp": {},
		"vnc": {},
	}
}

func loadTree(database *sql.DB) ([]*treeNode, error) {
	exists, err := tableExists(database, "Nodes")
	if err != nil || !exists {
		return []*treeNode{}, err
	}
	columns, err := tableColumns(database, "Nodes")
	if err != nil {
		return nil, err
	}
	portExpression := "NULL"
	if _, ok := columns["Port"]; ok {
		portExpression = "Port"
	}
	sshAutoSudoExpression := "NULL"
	if _, ok := columns["SshAutoSudo"]; ok {
		sshAutoSudoExpression = "SshAutoSudo"
	}
	httpIgnoreCertErrorsExpression := "NULL"
	if _, ok := columns["HttpIgnoreCertErrors"]; ok {
		httpIgnoreCertErrorsExpression = "HttpIgnoreCertErrors"
	}
	tunnelEnabledExpression := "NULL"
	if _, ok := columns["TunnelEnabled"]; ok {
		tunnelEnabledExpression = "TunnelEnabled"
	}
	tunnelConfigIDExpression := "NULL"
	if _, ok := columns["TunnelConfigId"]; ok {
		tunnelConfigIDExpression = "TunnelConfigId"
	}
	credentialModeExpression := "NULL"
	if _, ok := columns["CredentialMode"]; ok {
		credentialModeExpression = "CredentialMode"
	}
	credentialIDExpression := "NULL"
	if _, ok := columns["CredentialId"]; ok {
		credentialIDExpression = "CredentialId"
	}
	rows, err := database.Query(`
SELECT Id, ParentId, Name, Kind, SortOrder, Protocol, Host, ` + portExpression + ` AS Port, ` + sshAutoSudoExpression + ` AS SshAutoSudo, ` + httpIgnoreCertErrorsExpression + ` AS HttpIgnoreCertErrors, ` + tunnelEnabledExpression + ` AS TunnelEnabled, ` + tunnelConfigIDExpression + ` AS TunnelConfigId, ` + credentialModeExpression + ` AS CredentialMode, ` + credentialIDExpression + ` AS CredentialId
FROM Nodes
ORDER BY SortOrder, Name, Id;`)
	if err != nil {
		return nil, fmt.Errorf("cannot read connections: %w", err)
	}
	defer rows.Close()

	all := make([]*treeNode, 0)
	parents := make([]string, 0)
	byID := map[string]*treeNode{}
	parentByID := map[string]string{}
	protocolByID := map[string]sql.NullInt64{}
	for rows.Next() {
		var row nodeRow
		if err := rows.Scan(&row.ID, &row.ParentID, &row.Name, &row.Kind, &row.SortOrder, &row.Protocol, &row.Host, &row.Port, &row.SshAutoSudo, &row.HTTPIgnoreCertErrors, &row.TunnelEnabled, &row.TunnelConfigID, &row.CredentialMode, &row.CredentialID); err != nil {
			return nil, fmt.Errorf("cannot read a connection: %w", err)
		}
		node := &treeNode{ID: strings.TrimSpace(row.ID), Name: row.Name, Persisted: true}
		if row.SshAutoSudo.Valid {
			value := row.SshAutoSudo.Int64 != 0
			node.SshAutoSudo = &value
		}
		if row.HTTPIgnoreCertErrors.Valid {
			value := row.HTTPIgnoreCertErrors.Int64 != 0
			node.HTTPIgnoreCertErrors = &value
		}
		if row.TunnelEnabled.Valid {
			value := row.TunnelEnabled.Int64 != 0
			node.TunnelEnabled = &value
		}
		node.TunnelConfigID = normalizeTunnelID(nullableString(row.TunnelConfigID))
		if row.CredentialMode.Valid {
			value := int(row.CredentialMode.Int64)
			node.CredentialMode = &value
		}
		node.CredentialID = normalizeID(nullableString(row.CredentialID))
		if row.Kind == 0 {
			node.Kind = "folder"
		} else {
			node.Kind = "connection"
			node.Protocol = protocolName(row.Protocol)
			if row.Host.Valid {
				node.Host = row.Host.String
			}
			if row.Port.Valid && row.Port.Int64 > 0 && row.Port.Int64 <= 65535 {
				node.Port = int(row.Port.Int64)
			}
		}
		all = append(all, node)
		parents = append(parents, "")
		normalizedID := normalizeID(row.ID)
		byID[normalizedID] = node
		protocolByID[normalizedID] = row.Protocol
		if row.ParentID.Valid {
			parentID := normalizeID(row.ParentID.String)
			parents[len(parents)-1] = parentID
			parentByID[normalizedID] = parentID
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot enumerate connections: %w", err)
	}
	for _, node := range all {
		if node.Kind != "connection" {
			continue
		}
		currentID := normalizeID(node.ID)
		resolvedProtocol := protocolByID[currentID]
		seen := map[string]struct{}{}
		for !resolvedProtocol.Valid {
			if _, ok := seen[currentID]; ok {
				return nil, errors.New("cannot resolve inherited protocol: node tree contains a cycle")
			}
			seen[currentID] = struct{}{}
			parentID := parentByID[currentID]
			if parentID == "" {
				break
			}
			parentProtocol, ok := protocolByID[parentID]
			if !ok {
				break
			}
			resolvedProtocol = parentProtocol
			currentID = parentID
		}
		node.Protocol = protocolName(resolvedProtocol)
	}

	serialNodes, err := loadSerialNodes(database)
	if err != nil {
		return nil, err
	}
	for _, node := range all {
		if node.Kind != "connection" || node.Protocol != "serial" {
			continue
		}
		target, err := resolveSerialTargetFromNodes(serialNodes, node.ID)
		if err != nil {
			return nil, err
		}
		node.Host = target.PortName
		node.SerialBaudRate = serialIntPointer(target.BaudRate)
		node.SerialDataBits = serialIntPointer(target.DataBits)
		node.SerialStopBits = serialIntPointer(target.StopBits)
		node.SerialParity = serialIntPointer(target.Parity)
		node.SerialFlowControl = serialIntPointer(target.FlowControl)
	}

	roots := make([]*treeNode, 0, len(all))
	for index, node := range all {
		parentID := parents[index]
		parent := byID[parentID]
		if parent == nil || parent.Kind != "folder" || parent == node {
			roots = append(roots, node)
			continue
		}
		parent.Children = append(parent.Children, node)
	}
	return roots, nil
}

func updateWorkspaceNodeSshSettings(databasePath string, request workspaceNodeSshSettingsRequest) error {
	nodeID := strings.TrimSpace(request.NodeID)
	if nodeID == "" || len(nodeID) > 128 {
		return errors.New("workspace node id is invalid")
	}

	database, err := openDatabase(databasePath, false)
	if err != nil {
		return err
	}
	defer database.Close()

	exists, err := tableExists(database, "Nodes")
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("Wormhole database has no connections")
	}
	columns, err := tableColumns(database, "Nodes")
	if err != nil {
		return err
	}
	if _, ok := columns["SshAutoSudo"]; !ok {
		return errors.New("Wormhole database schema is missing the SSH auto-sudo migration")
	}

	var value any
	if request.SshAutoSudo != nil {
		if *request.SshAutoSudo {
			value = int64(1)
		} else {
			value = int64(0)
		}
	}
	result, err := database.Exec(
		"UPDATE Nodes SET SshAutoSudo = ?, UpdatedAt = ? WHERE lower(Id) = ?;",
		value,
		time.Now().UTC().Format(time.RFC3339Nano),
		normalizeID(nodeID),
	)
	if err != nil {
		return fmt.Errorf("could not update SSH auto-sudo setting: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected > 0 {
		return nil
	}

	var present int
	err = database.QueryRow(
		"SELECT 1 FROM Nodes WHERE lower(Id) = ? LIMIT 1;",
		normalizeID(nodeID),
	).Scan(&present)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("workspace node was not found")
	}
	return err
}

func updateWorkspaceNodeWebSettings(databasePath string, request workspaceNodeWebSettingsRequest) error {
	nodeID := strings.TrimSpace(request.NodeID)
	if nodeID == "" || len(nodeID) > 128 {
		return errors.New("workspace node id is invalid")
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		return err
	}
	defer database.Close()
	exists, err := tableExists(database, "Nodes")
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("Wormhole database has no connections")
	}
	columns, err := tableColumns(database, "Nodes")
	if err != nil {
		return err
	}
	if _, ok := columns["HttpIgnoreCertErrors"]; !ok {
		return errors.New("Wormhole database schema is missing the HTTP certificate migration")
	}
	if request.HTTPIgnoreCertErrors != nil && *request.HTTPIgnoreCertErrors {
		nodes, err := loadWebNodes(database)
		if err != nil {
			return err
		}
		leaf := nodes[normalizeID(nodeID)]
		if leaf == nil || leaf.Kind != 1 {
			return errors.New("workspace connection was not found")
		}
		protocol, err := resolvedProtocolForWebNode(leaf, nodes)
		if err != nil {
			return err
		}
		if !protocol.Valid || protocol.Int64 != 4 {
			return errors.New("certificate errors can only be ignored for an HTTPS connection")
		}
	}

	var value any
	if request.HTTPIgnoreCertErrors != nil {
		if *request.HTTPIgnoreCertErrors {
			value = int64(1)
		} else {
			value = int64(0)
		}
	}
	result, err := database.Exec(
		"UPDATE Nodes SET HttpIgnoreCertErrors = ?, UpdatedAt = ? WHERE lower(Id) = ? AND Kind = 1;",
		value,
		time.Now().UTC().Format(time.RFC3339Nano),
		normalizeID(nodeID),
	)
	if err != nil {
		return fmt.Errorf("could not update HTTP certificate setting: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected > 0 {
		return nil
	}
	return errors.New("workspace connection was not found")
}

func updateWorkspaceNodeTunnelSettings(databasePath string, request workspaceNodeTunnelSettingsRequest) error {
	nodeID := strings.TrimSpace(request.NodeID)
	if nodeID == "" || len(nodeID) > 128 {
		return errors.New("workspace node id is invalid")
	}
	configID := normalizeTunnelID(request.TunnelConfigID)
	if request.TunnelConfigID != "" && configID == "" {
		return errors.New("VPN tunnel id is invalid")
	}
	if request.TunnelEnabled == nil || !*request.TunnelEnabled {
		if configID != "" {
			return errors.New("VPN route must inherit or disable tunneling when no tunnel is selected")
		}
	} else if configID == "" {
		return errors.New("VPN route must select a tunnel when tunneling is enabled")
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := ensureMigrationSchema(database); err != nil {
		return err
	}
	columns, err := tableColumns(database, "Nodes")
	if err != nil {
		return err
	}
	if _, ok := columns["TunnelEnabled"]; !ok {
		return errors.New("the Wormhole database schema is missing VPN tunnel support")
	}
	if _, ok := columns["TunnelConfigId"]; !ok {
		return errors.New("the Wormhole database schema is missing VPN tunnel support")
	}
	if configID != "" {
		var found int
		err := database.QueryRow("SELECT 1 FROM TunnelConfigs WHERE lower(Id) = lower(?) LIMIT 1;", configID).Scan(&found)
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("the selected VPN tunnel was not found")
		}
		if err != nil {
			return fmt.Errorf("could not validate VPN tunnel: %w", err)
		}
	}
	var enabled any
	if request.TunnelEnabled != nil {
		if *request.TunnelEnabled {
			enabled = int64(1)
		} else {
			enabled = int64(0)
		}
	}
	var config any
	if configID != "" {
		config = configID
	}
	result, err := database.Exec(
		"UPDATE Nodes SET TunnelEnabled = ?, TunnelConfigId = ?, UpdatedAt = ? WHERE lower(Id) = lower(?);",
		enabled, config, time.Now().UTC().Format(time.RFC3339Nano), nodeID,
	)
	if err != nil {
		return fmt.Errorf("could not update VPN tunnel settings: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errors.New("workspace node was not found")
	}
	return nil
}

func updateWorkspaceNodeCredentialSettings(
	databasePath string,
	request workspaceNodeCredentialSettingsRequest,
) error {
	nodeID := strings.TrimSpace(request.NodeID)
	if nodeID == "" || len(nodeID) > 128 || request.Mode < 0 || request.Mode > 2 {
		return errors.New("workspace credential setting is invalid")
	}
	credentialID := normalizeID(request.CredentialID)
	if request.Mode == 2 && !validCredentialID(credentialID) {
		return errors.New("selected credential id is invalid")
	}
	if request.Mode != 2 {
		credentialID = ""
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		return err
	}
	defer database.Close()
	columns, err := tableColumns(database, "Nodes")
	if err != nil || len(columns) == 0 {
		if err != nil {
			return err
		}
		return errors.New("Wormhole database has no connections")
	}
	for _, column := range []struct{ name, statement string }{
		{"CredentialMode", "ALTER TABLE Nodes ADD COLUMN CredentialMode INTEGER NULL;"},
		{"CredentialId", "ALTER TABLE Nodes ADD COLUMN CredentialId TEXT NULL;"},
	} {
		if _, ok := columns[column.name]; ok {
			continue
		}
		if _, err := database.Exec(column.statement); err != nil {
			return fmt.Errorf("could not add connection credential support: %w", err)
		}
	}
	var kind int64
	var nodeProtocol sql.NullInt64
	if err := database.QueryRow(
		"SELECT Kind, Protocol FROM Nodes WHERE lower(Id) = ? LIMIT 1;",
		normalizeID(nodeID),
	).Scan(&kind, &nodeProtocol); errors.Is(err, sql.ErrNoRows) {
		return errors.New("workspace node was not found")
	} else if err != nil {
		return fmt.Errorf("could not read workspace node: %w", err)
	}
	if credentialID != "" {
		credentialProtocol, found, err := credentialProtocolByID(database, credentialID)
		if err != nil {
			return err
		}
		if !found {
			return errors.New("selected credential was not found")
		}
		if kind == 1 && nodeProtocol.Valid && nodeProtocol.Int64 != credentialProtocol {
			return errors.New("selected credential does not match the connection protocol")
		}
	}
	var storedID any
	if credentialID != "" {
		storedID = credentialID
	}
	updatedAt := ""
	if _, ok := columns["UpdatedAt"]; ok {
		updatedAt = ", UpdatedAt = ?"
	}
	args := []any{request.Mode, storedID}
	if updatedAt != "" {
		args = append(args, time.Now().UTC().Format(time.RFC3339Nano))
	}
	args = append(args, normalizeID(nodeID))
	result, err := database.Exec(
		"UPDATE Nodes SET CredentialMode = ?, CredentialId = ?"+updatedAt+" WHERE lower(Id) = ?;",
		args...,
	)
	if err != nil {
		return fmt.Errorf("could not update connection credential: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errors.New("workspace node was not found")
	}
	return nil
}

func credentialProtocolByID(database *sql.DB, credentialID string) (int64, bool, error) {
	var protocol int64
	profilesExist, err := tableExists(database, "CredentialProfiles")
	if err != nil {
		return 0, false, err
	}
	if profilesExist {
		err = database.QueryRow(
			"SELECT COALESCE(Protocol, 0) FROM CredentialProfiles WHERE lower(Id) = ? LIMIT 1;",
			credentialID,
		).Scan(&protocol)
		if err == nil {
			return protocol, true, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return 0, false, fmt.Errorf("could not validate selected credential: %w", err)
		}
	}
	exists, err := tableExists(database, "BitwardenCredentialCache")
	if err != nil || !exists {
		return 0, false, err
	}
	var sshID, rdpID, vncID string
	err = database.QueryRow(`
SELECT SshCredentialId, RdpCredentialId, VncCredentialId
FROM BitwardenCredentialCache
WHERE lower(SshCredentialId) = ? OR lower(RdpCredentialId) = ? OR lower(VncCredentialId) = ?
LIMIT 1;`, credentialID, credentialID, credentialID).Scan(&sshID, &rdpID, &vncID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("could not validate virtual Bitwarden credential: %w", err)
	}
	switch credentialID {
	case normalizeID(rdpID):
		return 1, true, nil
	case normalizeID(vncID):
		return 6, true, nil
	default:
		return 0, true, nil
	}
}

func loadCredentials(database *sql.DB, databasePath string) ([]credentialRecord, error) {
	credentials, linkedBitwardenItems, err := loadStoredCredentials(database)
	if err != nil {
		return nil, err
	}
	settings, settingsErr := readBitwardenCliSettings(databasePath)
	if settingsErr != nil {
		return nil, settingsErr
	}
	if settings.Enabled {
		entries, cacheErr := loadBitwardenCredentialCache(database)
		if cacheErr != nil {
			return nil, cacheErr
		}
		for _, entry := range entries {
			if _, linked := linkedBitwardenItems[entry.ItemID]; linked {
				continue
			}
			credentials = append(credentials, credentialRecord{
				ID:                 entry.SshCredentialID,
				Name:               entry.Name,
				Protocol:           "ssh",
				Username:           displayCredentialUsername(entry.Username),
				Provider:           "Bitwarden",
				BitwardenItemID:    entry.ItemID,
				BitwardenItemName:  entry.Name,
				IsVirtualBitwarden: true,
			})
		}
	}
	sort.SliceStable(credentials, func(left, right int) bool {
		if credentials[left].Name != credentials[right].Name {
			return credentials[left].Name < credentials[right].Name
		}
		return credentials[left].ID < credentials[right].ID
	})
	return credentials, nil
}

func loadStoredCredentials(database *sql.DB) ([]credentialRecord, map[string]struct{}, error) {
	exists, err := tableExists(database, "CredentialProfiles")
	if err != nil {
		return nil, nil, err
	}
	credentials := make([]credentialRecord, 0)
	linkedBitwardenItems := make(map[string]struct{})
	if !exists {
		return credentials, linkedBitwardenItems, nil
	}
	columns, err := tableColumns(database, "CredentialProfiles")
	if err != nil {
		return nil, nil, err
	}
	protocolExpression := "0"
	if _, ok := columns["Protocol"]; ok {
		protocolExpression = "COALESCE(Protocol, 0)"
	}
	providerExpression := "0"
	if _, ok := columns["SecretProvider"]; ok {
		providerExpression = "COALESCE(SecretProvider, 0)"
	}
	kindExpression := "0"
	if _, ok := columns["Kind"]; ok {
		kindExpression = "COALESCE(Kind, 0)"
	}
	bitwardenItemIDExpression := "NULL"
	if _, ok := columns["BitwardenItemId"]; ok {
		bitwardenItemIDExpression = "BitwardenItemId"
	}
	bitwardenItemNameExpression := "NULL"
	if _, ok := columns["BitwardenItemName"]; ok {
		bitwardenItemNameExpression = "BitwardenItemName"
	}
	rows, err := database.Query(`SELECT Id, Name, Username, Domain, ` + protocolExpression + `, ` + providerExpression + `, ` + kindExpression + `, ` + bitwardenItemIDExpression + `, ` + bitwardenItemNameExpression + `
FROM CredentialProfiles ORDER BY Name, Id;`)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read credentials: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var row credentialRow
		var itemID, itemName sql.NullString
		if err := rows.Scan(&row.ID, &row.Name, &row.Username, &row.Domain, &row.Protocol, &row.Provider, &row.Kind, &itemID, &itemName); err != nil {
			return nil, nil, fmt.Errorf("cannot read a credential: %w", err)
		}
		username := "No username"
		if row.Username.Valid && strings.TrimSpace(row.Username.String) != "" {
			username = row.Username.String
		}
		record := credentialRecord{
			ID:       row.ID,
			Name:     row.Name,
			Protocol: protocolName(sql.NullInt64{Int64: row.Protocol, Valid: true}),
			Username: username,
			Domain:   nullableString(row.Domain),
			Provider: providerName(row.Provider),
			CanEdit: row.Kind == 0 && (row.Provider == 0 || row.Provider == 1) &&
				(row.Protocol == 0 || row.Protocol == 1 || row.Protocol == 6),
			CanDelete:         (row.Kind == 0 || row.Kind == 1) && (row.Provider == 0 || row.Provider == 1),
			BitwardenItemID:   strings.TrimSpace(nullableString(itemID)),
			BitwardenItemName: strings.TrimSpace(nullableString(itemName)),
		}
		credentials = append(credentials, record)
		if row.Provider == 1 && record.BitwardenItemID != "" {
			linkedBitwardenItems[record.BitwardenItemID] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("cannot enumerate credentials: %w", err)
	}
	return credentials, linkedBitwardenItems, nil
}

func loadCredentialsForProtocol(databasePath, protocol string) ([]credentialRecord, error) {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol != "ssh" && protocol != "rdp" && protocol != "vnc" {
		return nil, errors.New("credential protocol is invalid")
	}
	database, err := openDatabase(databasePath, true)
	if err != nil {
		return nil, err
	}
	if database == nil {
		return []credentialRecord{}, nil
	}
	defer database.Close()
	return loadCredentialsForProtocolFromDatabase(database, databasePath, protocol)
}

func loadCredentialsForProtocolFromDatabase(
	database *sql.DB,
	databasePath string,
	protocol string,
) ([]credentialRecord, error) {
	protocolValue := int64(0)
	switch protocol {
	case "rdp":
		protocolValue = 1
	case "vnc":
		protocolValue = 6
	}
	storedCredentials, _, err := loadStoredCredentials(database)
	if err != nil {
		return nil, err
	}
	profiles := make([]credentialRecord, 0)
	linkedItems := make(map[string]struct{})
	for _, credential := range storedCredentials {
		if credential.Protocol != protocol {
			continue
		}
		profiles = append(profiles, credential)
		if credential.Provider == "Bitwarden" && credential.BitwardenItemID != "" {
			linkedItems[credential.BitwardenItemID] = struct{}{}
		}
	}
	settings, err := readBitwardenCliSettings(databasePath)
	if err != nil || !settings.Enabled {
		return profiles, err
	}
	entries, err := loadBitwardenCredentialCache(database)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if _, linked := linkedItems[entry.ItemID]; linked {
			continue
		}
		credentialID := entry.SshCredentialID
		if protocolValue == 1 {
			credentialID = entry.RdpCredentialID
		} else if protocolValue == 6 {
			credentialID = entry.VncCredentialID
		}
		profiles = append(profiles, credentialRecord{
			ID:                 credentialID,
			Name:               entry.Name,
			Protocol:           protocol,
			Username:           displayCredentialUsername(entry.Username),
			Provider:           "Bitwarden",
			BitwardenItemID:    entry.ItemID,
			BitwardenItemName:  entry.Name,
			IsVirtualBitwarden: true,
		})
	}
	sort.SliceStable(profiles, func(left, right int) bool {
		if profiles[left].Name != profiles[right].Name {
			return profiles[left].Name < profiles[right].Name
		}
		return profiles[left].ID < profiles[right].ID
	})
	return profiles, nil
}

func loadTunnels(database *sql.DB) ([]tunnelRecord, error) {
	exists, err := tableExists(database, "TunnelConfigs")
	if err != nil || !exists {
		return []tunnelRecord{}, err
	}
	rows, err := database.Query("SELECT Id, Name, Kind FROM TunnelConfigs ORDER BY Name, Id;")
	if err != nil {
		return nil, fmt.Errorf("cannot read VPN tunnels: %w", err)
	}
	defer rows.Close()
	tunnels := make([]tunnelRecord, 0)
	for rows.Next() {
		var row tunnelRow
		if err := rows.Scan(&row.ID, &row.Name, &row.Kind); err != nil {
			return nil, fmt.Errorf("cannot read a VPN tunnel: %w", err)
		}
		tunnels = append(tunnels, tunnelRecord{ID: row.ID, Name: row.Name, Kind: tunnelName(row.Kind)})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot enumerate VPN tunnels: %w", err)
	}
	return tunnels, nil
}

func nullableString(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func protocolName(value sql.NullInt64) string {
	if !value.Valid {
		return "ssh"
	}
	switch value.Int64 {
	case 1:
		return "rdp"
	case 3:
		return "http"
	case 4:
		return "https"
	case 5:
		return "serial"
	case 6:
		return "vnc"
	default:
		return "ssh"
	}
}

func providerName(value int64) string {
	if value == 1 {
		return "Bitwarden"
	}
	return "Local"
}

func tunnelName(value int64) string {
	switch value {
	case 0:
		return "WireGuard"
	case 1:
		return "OpenVPN"
	case 2:
		return "Fortinet"
	case 3:
		return "WatchGuard"
	case 4:
		return "Stormshield"
	case 5:
		return "Azure VPN"
	case 6:
		return "Cisco Secure Client"
	default:
		return "Unknown"
	}
}

func isWindowsRuntime() bool {
	return runtimeGOOS == "windows"
}

// runtimeGOOS is defined in runtime.go so tests can exercise the non-Windows branch without
// mutating the process runtime. The production value is constant for the built executable.
var runtimeGOOS = goos()

var errCredentialReaderOutputTooLarge = errors.New("credential reader output limit exceeded")

type limitedOutput struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (output *limitedOutput) Write(chunk []byte) (int, error) {
	remaining := output.limit - output.Len()
	if remaining <= 0 {
		output.exceeded = true
		return 0, errCredentialReaderOutputTooLarge
	}
	if len(chunk) > remaining {
		_, _ = output.Buffer.Write(chunk[:remaining])
		output.exceeded = true
		return remaining, errCredentialReaderOutputTooLarge
	}
	return output.Buffer.Write(chunk)
}
