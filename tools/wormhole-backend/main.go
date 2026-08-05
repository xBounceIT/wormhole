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
	credentialPrefix             = "Wormhole:"
	mcpTokenCredentialID         = "a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91"
	credentialReaderTimeout      = 15 * time.Second
	credentialReaderMaxOutput    = 16 * 1024 * 1024
	backendMaxRequestBytes       = 64 * 1024
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
	Tree        []*treeNode        `json:"tree"`
	Credentials []credentialRecord `json:"credentials"`
	Tunnels     []tunnelRecord     `json:"tunnels"`
}

type treeNode struct {
	ID       string      `json:"id"`
	Name     string      `json:"name"`
	Kind     string      `json:"kind"`
	Protocol string      `json:"protocol,omitempty"`
	Host     string      `json:"host,omitempty"`
	Port     int         `json:"port,omitempty"`
	Children []*treeNode `json:"children,omitempty"`
}

type credentialRecord struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Username string `json:"username"`
	Domain   string `json:"domain,omitempty"`
	Provider string `json:"provider"`
	ReadOnly bool   `json:"readOnly,omitempty"`
}

type tunnelRecord struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type nodeRow struct {
	ID        string
	ParentID  sql.NullString
	Name      string
	Kind      int64
	SortOrder int64
	Protocol  sql.NullInt64
	Host      sql.NullString
	Port      sql.NullInt64
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
	operation := flag.String("operation", "workspace", "backend operation: workspace, migrate, ssh, ssh-trust-host-key, serve, rdp, or auth-*")
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
	if *operation == "ssh" {
		if err := serveSSH(*databasePath, os.Stdin, os.Stdout, *electronUserDataPath); err != nil {
			writeError(err.Error())
			os.Exit(1)
		}
		return
	}

	var result any
	var err error
	switch *operation {
	case "workspace":
		result, err = loadWorkspace(*databasePath)
	case "migrate":
		result, err = migrateCredentials(*databasePath, *credentialReader)
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
	case "auth-hello-status":
		result = checkWindowsHello()
	case "auth-hello-verify":
		result = verifyWindowsHello()
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
		if err := serveBackend(*databasePath, *electronUserDataPath); err != nil {
			writeError(err.Error())
			os.Exit(1)
		}
		return
	case "rdp":
		err = runRdpController(*rdpHost, *freerdpPath)
	default:
		err = fmt.Errorf("unsupported operation %q", *operation)
	}

	if err != nil {
		writeError(err.Error())
		os.Exit(1)
		return
	}

	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		writeError("failed to encode backend response")
		os.Exit(1)
	}
}

func decodeInput[T any](target *T) error {
	return decodeInputReader(os.Stdin, target)
}

func decodeInputReader[T any](reader io.Reader, target *T) error {
	contents, err := io.ReadAll(io.LimitReader(reader, backendMaxRequestBytes+1))
	if err != nil || len(contents) > backendMaxRequestBytes {
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
);`)
	if err != nil {
		return fmt.Errorf("cannot create migration tables: %w", err)
	}
	return nil
}

func migrateCredentials(databasePath, readerPath string) (migrationResult, error) {
	return migrateCredentialsWithReader(databasePath, readerPath, readWindowsCredentials)
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

	if err := ensureMigrationSchema(database); err != nil {
		return migrationResult{}, err
	}
	completed, err := hasCompletedMigration(database)
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
		return workspaceSnapshot{Tree: []*treeNode{}, Credentials: []credentialRecord{}, Tunnels: []tunnelRecord{}}, nil
	}
	defer database.Close()

	tree, err := loadTree(database)
	if err != nil {
		return workspaceSnapshot{}, err
	}
	credentials, err := loadCredentials(database)
	if err != nil {
		return workspaceSnapshot{}, err
	}
	tunnels, err := loadTunnels(database)
	if err != nil {
		return workspaceSnapshot{}, err
	}
	return workspaceSnapshot{Tree: tree, Credentials: credentials, Tunnels: tunnels}, nil
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
	rows, err := database.Query(`
SELECT Id, ParentId, Name, Kind, SortOrder, Protocol, Host, ` + portExpression + ` AS Port
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
		if err := rows.Scan(&row.ID, &row.ParentID, &row.Name, &row.Kind, &row.SortOrder, &row.Protocol, &row.Host, &row.Port); err != nil {
			return nil, fmt.Errorf("cannot read a connection: %w", err)
		}
		node := &treeNode{ID: strings.TrimSpace(row.ID), Name: row.Name}
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

func loadCredentials(database *sql.DB) ([]credentialRecord, error) {
	exists, err := tableExists(database, "CredentialProfiles")
	if err != nil || !exists {
		return []credentialRecord{}, err
	}
	columns, err := tableColumns(database, "CredentialProfiles")
	if err != nil {
		return nil, err
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
	rows, err := database.Query(`SELECT Id, Name, Username, Domain, ` + protocolExpression + `, ` + providerExpression + `, ` + kindExpression + `
FROM CredentialProfiles ORDER BY Name, Id;`)
	if err != nil {
		return nil, fmt.Errorf("cannot read credentials: %w", err)
	}
	defer rows.Close()
	credentials := make([]credentialRecord, 0)
	for rows.Next() {
		var row credentialRow
		if err := rows.Scan(&row.ID, &row.Name, &row.Username, &row.Domain, &row.Protocol, &row.Provider, &row.Kind); err != nil {
			return nil, fmt.Errorf("cannot read a credential: %w", err)
		}
		username := "No username"
		if row.Username.Valid && strings.TrimSpace(row.Username.String) != "" {
			username = row.Username.String
		}
		credentials = append(credentials, credentialRecord{
			ID:       row.ID,
			Name:     row.Name,
			Protocol: protocolName(sql.NullInt64{Int64: row.Protocol, Valid: true}),
			Username: username,
			Domain:   nullableString(row.Domain),
			Provider: providerName(row.Provider),
			ReadOnly: row.Kind == 1,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot enumerate credentials: %w", err)
	}
	return credentials, nil
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
