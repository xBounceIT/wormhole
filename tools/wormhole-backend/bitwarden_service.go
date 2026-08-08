package main

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type bitwardenResolvedCredential struct {
	Bitwarden bool   `json:"bitwarden"`
	ItemID    string `json:"itemId,omitempty"`
	ItemName  string `json:"itemName,omitempty"`
	Username  string `json:"username,omitempty"`
	Domain    string `json:"domain,omitempty"`
	Password  string `json:"password,omitempty"`
}

var errBitwardenSessionInvalidated = errors.New("Bitwarden session was cleared; unlock the vault and try again")

func (m *vncManager) handleBitwarden(command backendCommand, expectedGeneration uint64) {
	if command.Action == "bitwarden.clear-session" {
		m.clearBitwardenSession()
		m.cancelPendingVncConnections()
		m.respondResult(command.ID, map[string]bool{"cleared": true}, nil)
		return
	}

	if command.Action == "bitwarden.browser-storage-read" ||
		command.Action == "bitwarden.browser-storage-capture" ||
		command.Action == "bitwarden.browser-profile-seed" ||
		command.Action == "bitwarden.browser-profile-register" {
		m.bitwardenBrowserMu.Lock()
		defer m.bitwardenBrowserMu.Unlock()
	} else {
		m.bitwardenOperationMu.Lock()
		defer m.bitwardenOperationMu.Unlock()
		if !m.bitwardenGenerationIs(expectedGeneration) {
			m.respondResult(command.ID, nil, errBitwardenSessionInvalidated)
			return
		}
	}

	var result any
	var err error
	switch command.Action {
	case "bitwarden.read":
		result, err = readBitwardenCliState(m.databasePath)
	case "bitwarden.set-enabled":
		var state bitwardenCliState
		state, err = setBitwardenCliEnabled(m.databasePath, *command.Enabled)
		result = state
		if err == nil {
			if !*command.Enabled {
				m.resetBitwardenSession()
			} else {
				if state.Installed == nil {
					_, _ = ensureBitwardenCliInstalled(m.databasePath)
					state, _ = readBitwardenCliState(m.databasePath)
				}
				if state.Installed != nil {
					_, _ = m.syncBitwardenCredentialsIfStale()
				}
				result, err = readBitwardenCliState(m.databasePath)
			}
		}
	case "bitwarden.set-config":
		var state bitwardenCliState
		var changed bool
		state, changed, err = setBitwardenCliConfig(m.databasePath, command.Path, command.ServerRegion)
		result = state
		if err == nil && changed {
			m.resetBitwardenSession()
		}
	case "bitwarden.install":
		result, err = installBitwardenCliLatestWrapped(m.databasePath)
	case "bitwarden.ensure-installed":
		result, err = ensureBitwardenCliInstalled(m.databasePath)
	case "bitwarden.status":
		result, err = bitwardenCliStatusOperation(m.databasePath)
		if err == nil {
			if status, ok := result.(map[string]any); ok {
				status["hasSessionKey"] = m.bitwardenSession() != ""
			}
		}
	case "bitwarden.login":
		settings, readErr := readBitwardenCliSettings(m.databasePath)
		if readErr != nil {
			err = readErr
			break
		}
		if !settings.Enabled {
			err = errors.New("Bitwarden credential vault is disabled in Settings")
			break
		}
		m.resetBitwardenSession()
		var sessionKey string
		sessionKey, err = bitwardenCliLogin(
			m.databasePath,
			settings,
			command.Email,
			command.MasterPassword,
			command.AuthenticatorCode,
		)
		if err == nil && m.setBitwardenSessionForGeneration(sessionKey, expectedGeneration) {
			result = map[string]any{"loggedIn": true}
		} else if err == nil {
			err = errBitwardenSessionInvalidated
		}
	case "bitwarden.unlock":
		settings, readErr := readBitwardenCliSettings(m.databasePath)
		if readErr != nil {
			err = readErr
			break
		}
		if !settings.Enabled {
			err = errors.New("Bitwarden credential vault is disabled in Settings")
			break
		}
		var sessionKey string
		sessionKey, err = bitwardenCliUnlock(m.databasePath, settings, command.MasterPassword)
		if err == nil && m.setBitwardenSessionForGeneration(sessionKey, expectedGeneration) {
			result, err = m.syncBitwardenCredentials(sessionKey)
		} else if err == nil {
			err = errBitwardenSessionInvalidated
		}
	case "bitwarden.logout":
		err = bitwardenCliLogoutOperation(m.databasePath, m.bitwardenSession())
		m.resetBitwardenSession()
		if err == nil {
			result = map[string]bool{"loggedOut": true}
		}
	case "bitwarden.sync":
		result, err = m.syncBitwardenCredentials(m.bitwardenSession())
	case "bitwarden.sync-if-stale":
		result, err = m.syncBitwardenCredentialsIfStale()
	case "bitwarden.list":
		if err = m.requireBitwardenEnabled(); err == nil {
			result, err = bitwardenCliListOperation(m.databasePath, m.bitwardenSession(), command.Query)
		}
	case "bitwarden.search":
		if err = m.requireBitwardenEnabled(); err == nil {
			result, err = bitwardenCliSearchOperation(m.databasePath, m.bitwardenSession(), command.Query)
		}
	case "bitwarden.get":
		if err = m.requireBitwardenEnabled(); err == nil {
			result, err = bitwardenCliGetOperation(m.databasePath, m.bitwardenSession(), command.ItemID)
		}
	case "bitwarden.resolve-credential":
		result, err = m.resolveBitwardenCredential(command.CredentialID, bitwardenProtocolValue(command.Protocol))
	case "bitwarden.resolve-node":
		result, err = m.resolveBitwardenNodeCredential(command.NodeID, bitwardenProtocolValue(command.Protocol))
	case "rdp.resolve-profile":
		var manual *rdpManualCredential
		if command.ManualCredentials {
			manual = &rdpManualCredential{
				Username: command.Username, Domain: command.Domain, Password: command.Password,
			}
		}
		result, err = m.resolveRdpRuntimeProfile(command.NodeID, manual)
	case "bitwarden.node-reference":
		result, err = m.bitwardenNodeReference(command.NodeID, bitwardenProtocolValue(command.Protocol))
	case "bitwarden.browser-storage-read":
		result, err = m.readBitwardenBrowserStorage(command.ProfilePath)
	case "bitwarden.browser-storage-capture":
		result, err = m.captureBitwardenBrowserStorage(
			command.LocalJSON,
			command.SessionJSON,
			command.SourceRevision,
			command.ProfilePath,
		)
	case "bitwarden.browser-profile-seed":
		result, err = m.seedBitwardenBrowserProfile(command.ProfilePath, command.Path, command.Query)
	case "bitwarden.browser-profile-register":
		result, err = m.registerBitwardenBrowserProfile(
			command.ProfilePath,
			command.Path,
			command.Value,
			command.Query,
		)
	default:
		err = fmt.Errorf("unsupported Bitwarden action %q", command.Action)
	}
	if isBitwardenCliAuthError(err) {
		m.clearBitwardenSession()
	}
	if err == nil && command.Action != "bitwarden.browser-storage-read" &&
		command.Action != "bitwarden.browser-storage-capture" &&
		command.Action != "bitwarden.browser-profile-seed" &&
		command.Action != "bitwarden.browser-profile-register" &&
		!m.bitwardenGenerationIs(expectedGeneration) {
		result = nil
		err = errBitwardenSessionInvalidated
	}
	m.respondResult(command.ID, result, err)
}

func (m *vncManager) readBitwardenBrowserStorage(profilePath string) (bitwardenBrowserStorageSnapshot, error) {
	if !m.bitwardenBrowserLoaded {
		snapshot, ready, primaryNeedsRepair := readPersistedBitwardenBrowserStorage(m.databasePath)
		if ready {
			if m.bitwardenBrowserStorage.LocalJSON != "" && !m.bitwardenBrowserStorage.Durable {
				m.bitwardenBrowserStorage.Revision = max(
					m.bitwardenBrowserStorage.Revision,
					snapshot.Revision+1,
				)
			} else {
				m.bitwardenBrowserStorage = snapshot
			}
			m.bitwardenBrowserLoaded = true
			m.bitwardenBrowserPrimaryNeedsRepair = primaryNeedsRepair
		} else if m.bitwardenBrowserStorage.LocalJSON == "" {
			m.bitwardenBrowserStorage = snapshot
		}
	}
	return bitwardenBrowserStorageForProfile(m.bitwardenBrowserStorage, profilePath), nil
}

func (m *vncManager) captureBitwardenBrowserStorage(
	localJSON,
	sessionJSON string,
	sourceRevision int64,
	profilePath string,
) (bitwardenBrowserStorageSnapshot, error) {
	currentResponse, err := m.readBitwardenBrowserStorage(profilePath)
	if err != nil {
		return bitwardenBrowserStorageSnapshot{}, err
	}
	current := m.bitwardenBrowserStorage
	localJSON, err = normalizeBitwardenBrowserStorageJSON(localJSON)
	if err != nil {
		return bitwardenBrowserStorageSnapshot{}, err
	}
	sessionJSON, err = normalizeBitwardenBrowserStorageJSON(sessionJSON)
	if err != nil {
		return bitwardenBrowserStorageSnapshot{}, err
	}
	if !m.bitwardenBrowserLoaded {
		if current.LocalJSON != localJSON || current.SessionJSON != sessionJSON {
			m.bitwardenBrowserStorage = bitwardenBrowserStorageSnapshot{
				Revision:    current.Revision + 1,
				LocalJSON:   localJSON,
				SessionJSON: sessionJSON,
			}
		}
		return bitwardenBrowserStorageForProfile(m.bitwardenBrowserStorage, profilePath), nil
	}
	if sourceRevision < current.Revision &&
		(localJSON != current.LocalJSON || sessionJSON != current.SessionJSON) {
		return currentResponse, nil
	}
	if current.Revision > 0 && localJSON == current.LocalJSON && sessionJSON == current.SessionJSON {
		if !current.Durable || m.bitwardenBrowserPrimaryNeedsRepair {
			recoveryReady, persistErr := persistBitwardenBrowserStorage(m.databasePath, current)
			if persistErr == nil {
				current.Durable = true
				m.bitwardenBrowserStorage = current
				m.bitwardenBrowserPrimaryNeedsRepair = !recoveryReady
			}
		}
		if current.Durable && current.Revision > 0 {
			writeBitwardenBrowserProfileRevision(profilePath, current.Revision)
		}
		return bitwardenBrowserStorageForProfile(current, profilePath), nil
	}
	next := bitwardenBrowserStorageSnapshot{
		Revision:    max(current.Revision, sourceRevision) + 1,
		LocalJSON:   localJSON,
		SessionJSON: sessionJSON,
	}
	m.bitwardenBrowserStorage = next
	recoveryReady, persistErr := persistBitwardenBrowserStorage(m.databasePath, next)
	if persistErr != nil {
		return bitwardenBrowserStorageForProfile(next, profilePath), nil
	}
	next.Durable = true
	m.bitwardenBrowserStorage = next
	m.bitwardenBrowserPrimaryNeedsRepair = !recoveryReady
	writeBitwardenBrowserProfileRevision(profilePath, next.Revision)
	return bitwardenBrowserStorageForProfile(next, profilePath), nil
}

func (m *vncManager) syncBitwardenCredentialsIfStale() (any, error) {
	settings, err := readBitwardenCliSettings(m.databasePath)
	if err != nil || !settings.Enabled || !bitwardenSyncIsStale(settings, time.Now()) {
		return buildBitwardenCliState(m.databasePath, settings), err
	}
	status, err := bitwardenCliStatusState(m.databasePath, settings)
	if err != nil {
		return m.syncBitwardenCredentials(m.bitwardenSession())
	}
	statusName, _ := status["status"].(string)
	if statusName == "Unauthenticated" || (statusName == "Locked" && m.bitwardenSession() == "") {
		if statusName == "Unauthenticated" {
			settings.LastSyncStatus = "Needs Bitwarden login to refresh."
		} else {
			settings.LastSyncStatus = "Needs Bitwarden unlock to refresh."
		}
		settings.LastSyncError = ""
		if err := writeBitwardenCliSettings(m.databasePath, settings); err != nil {
			return nil, err
		}
		return buildBitwardenCliState(m.databasePath, settings), nil
	}
	return m.syncBitwardenCredentials(m.bitwardenSession())
}

func (m *vncManager) bitwardenNodeReference(nodeID string, protocol int64) (map[string]bool, error) {
	if protocol < 0 {
		return nil, errors.New("Bitwarden credential protocol is invalid")
	}
	credentialID, err := resolveNodeCredentialID(m.database, nodeID, protocol)
	if err != nil || credentialID == "" {
		return map[string]bool{"bitwarden": false}, err
	}
	_, found, err := resolveBitwardenCredentialReference(m.database, credentialID, protocol)
	return map[string]bool{"bitwarden": found}, err
}

func (m *vncManager) syncBitwardenCredentials(sessionKey string) (any, error) {
	settings, readErr := readBitwardenCliSettings(m.databasePath)
	if readErr != nil {
		return nil, readErr
	}
	if !settings.Enabled {
		return buildBitwardenCliState(m.databasePath, settings), nil
	}
	result, err := bitwardenCliSyncOperation(m.databasePath, sessionKey)
	if err == nil {
		return result, nil
	}
	settings, readErr = readBitwardenCliSettings(m.databasePath)
	if readErr != nil {
		return nil, readErr
	}
	settings.LastSyncStatus = "Bitwarden sync failed; using cached credentials."
	settings.LastSyncError = summarizeBitwardenCliError(err)
	if writeErr := writeBitwardenCliSettings(m.databasePath, settings); writeErr != nil {
		return nil, writeErr
	}
	lastSyncUTC := ""
	if settings.LastSyncUtc != nil {
		lastSyncUTC = settings.LastSyncUtc.Format(time.RFC3339Nano)
	}
	availableCount := 0
	if settings.AvailableCount != nil {
		availableCount = *settings.AvailableCount
	}
	return map[string]any{
		"lastSyncUtc":    lastSyncUTC,
		"lastSyncStatus": settings.LastSyncStatus,
		"availableCount": availableCount,
		"usedCache":      true,
		"lastSyncError":  settings.LastSyncError,
	}, nil
}

func (m *vncManager) requireBitwardenEnabled() error {
	settings, err := readBitwardenCliSettings(m.databasePath)
	if err != nil {
		return err
	}
	if !settings.Enabled {
		return errors.New("Bitwarden credential vault is disabled in Settings")
	}
	return nil
}

func (m *vncManager) setBitwardenSessionForGeneration(sessionKey string, expectedGeneration uint64) bool {
	m.bitwardenMu.Lock()
	defer m.bitwardenMu.Unlock()
	if m.bitwardenSessionGeneration != expectedGeneration {
		return false
	}
	m.bitwardenSessionKey = strings.TrimSpace(sessionKey)
	return true
}

func (m *vncManager) bitwardenSession() string {
	m.bitwardenMu.RLock()
	defer m.bitwardenMu.RUnlock()
	return m.bitwardenSessionKey
}

func (m *vncManager) clearBitwardenSession() {
	m.bitwardenMu.Lock()
	m.bitwardenSessionKey = ""
	m.bitwardenSessionGeneration++
	m.bitwardenMu.Unlock()
}

func (m *vncManager) resetBitwardenSession() {
	m.bitwardenMu.Lock()
	m.bitwardenSessionKey = ""
	m.bitwardenMu.Unlock()
}

func (m *vncManager) bitwardenGeneration() uint64 {
	m.bitwardenMu.RLock()
	defer m.bitwardenMu.RUnlock()
	return m.bitwardenSessionGeneration
}

func (m *vncManager) bitwardenGenerationIs(expected uint64) bool {
	m.bitwardenMu.RLock()
	defer m.bitwardenMu.RUnlock()
	return m.bitwardenSessionGeneration == expected
}

func bitwardenProtocolValue(protocol string) int64 {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "ssh":
		return 0
	case "rdp":
		return 1
	case "vnc":
		return 6
	default:
		return -1
	}
}

func (m *vncManager) resolveBitwardenCredential(
	credentialID string,
	protocol int64,
) (bitwardenResolvedCredential, error) {
	resolved, err := m.resolveBitwardenCredentialRaw(credentialID, protocol)
	if err == nil && resolved.Bitwarden && protocol == 1 && resolved.Domain == "" {
		resolved.Username, resolved.Domain = splitRdpDomainUsername(resolved.Username)
	}
	return resolved, err
}

func (m *vncManager) resolveBitwardenCredentialRaw(
	credentialID string,
	protocol int64,
) (bitwardenResolvedCredential, error) {
	if protocol < 0 {
		return bitwardenResolvedCredential{}, errors.New("Bitwarden credential protocol is invalid")
	}
	database := m.database
	if database == nil {
		return bitwardenResolvedCredential{}, errors.New("Wormhole database is not available")
	}
	reference, found, err := resolveBitwardenCredentialReference(database, credentialID, protocol)
	if err != nil || !found {
		return bitwardenResolvedCredential{Bitwarden: false}, err
	}
	settings, err := readBitwardenCliSettings(m.databasePath)
	if err != nil {
		return bitwardenResolvedCredential{}, err
	}
	if !settings.Enabled {
		return bitwardenResolvedCredential{}, errors.New("Bitwarden credential vault is disabled in Settings")
	}
	item, err := bitwardenCliGetItem(m.databasePath, settings, m.bitwardenSession(), reference.ItemID)
	if err != nil {
		return bitwardenResolvedCredential{}, err
	}
	if item == nil {
		if err := bitwardenCliSync(m.databasePath, settings, m.bitwardenSession()); err != nil {
			return bitwardenResolvedCredential{}, err
		}
		item, err = bitwardenCliGetItem(m.databasePath, settings, m.bitwardenSession(), reference.ItemID)
		if err != nil {
			return bitwardenResolvedCredential{}, err
		}
	}
	if item == nil {
		return bitwardenResolvedCredential{}, errors.New("the linked Bitwarden item was not found")
	}
	if item.Password == "" {
		return bitwardenResolvedCredential{}, errors.New("the linked Bitwarden item does not contain login.password")
	}
	username := reference.Username
	if username == "" {
		username = strings.TrimSpace(item.Username)
	}
	return bitwardenResolvedCredential{
		Bitwarden: true,
		ItemID:    reference.ItemID,
		ItemName:  reference.ItemName,
		Username:  username,
		Domain:    reference.Domain,
		Password:  item.Password,
	}, nil
}

func splitRdpDomainUsername(username string) (string, string) {
	username = strings.TrimSpace(username)
	slash := strings.IndexByte(username, '\\')
	if slash <= 0 || slash == len(username)-1 {
		return username, ""
	}
	return username[slash+1:], username[:slash]
}

func (m *vncManager) resolveBitwardenNodeCredential(
	nodeID string,
	protocol int64,
) (bitwardenResolvedCredential, error) {
	credentialID, err := resolveNodeCredentialID(m.database, nodeID, protocol)
	if err != nil || credentialID == "" {
		return bitwardenResolvedCredential{Bitwarden: false}, err
	}
	resolved, err := m.resolveBitwardenCredentialRaw(credentialID, protocol)
	if err != nil || !resolved.Bitwarden || protocol != 1 {
		return resolved, err
	}
	username, domain, err := resolveNodeRdpIdentity(m.database, nodeID)
	if err != nil {
		return bitwardenResolvedCredential{}, err
	}
	if username != "" {
		resolved.Username = username
	}
	if domain != "" {
		resolved.Domain = domain
	}
	if resolved.Domain == "" {
		resolved.Username, resolved.Domain = splitRdpDomainUsername(resolved.Username)
	}
	return resolved, nil
}

func resolveNodeRdpIdentity(database *sql.DB, nodeID string) (string, string, error) {
	columns, err := tableColumns(database, "Nodes")
	if err != nil {
		return "", "", err
	}
	if len(columns) == 0 {
		return "", "", errors.New("Wormhole database has no connections")
	}
	column := func(name string) string {
		if _, ok := columns[name]; ok {
			return name
		}
		return "NULL"
	}
	currentID := normalizeID(nodeID)
	seen := make(map[string]struct{})
	username := ""
	domain := ""
	usernameSet := false
	domainSet := false
	identityBoundary := false
	leaf := true
	for currentID != "" {
		if _, duplicate := seen[currentID]; duplicate {
			return "", "", errors.New("connection tree contains a cycle")
		}
		seen[currentID] = struct{}{}
		var parentID, storedUsername, storedDomain, storedCredentialID sql.NullString
		var credentialMode, inlinePassword sql.NullInt64
		err := database.QueryRow(
			"SELECT "+column("ParentId")+", "+column("Username")+", "+column("RdpDomain")+", "+
				column("CredentialId")+", "+column("CredentialMode")+", "+column("UseInlinePassword")+
				" FROM Nodes WHERE lower(Id) = ? LIMIT 1;",
			currentID,
		).Scan(
			&parentID,
			&storedUsername,
			&storedDomain,
			&storedCredentialID,
			&credentialMode,
			&inlinePassword,
		)
		if errors.Is(err, sql.ErrNoRows) {
			if leaf {
				return "", "", errors.New("connection was not found")
			}
			break
		}
		if err != nil {
			return "", "", fmt.Errorf("could not resolve the RDP identity: %w", err)
		}
		if !identityBoundary {
			if !usernameSet && storedUsername.Valid {
				username = strings.TrimSpace(nullableString(storedUsername))
				usernameSet = true
			}
			if !domainSet && storedDomain.Valid {
				domain = strings.TrimSpace(nullableString(storedDomain))
				domainSet = true
			}
		}
		if leaf && inlinePassword.Valid && inlinePassword.Int64 != 0 {
			identityBoundary = true
		} else if !identityBoundary {
			resolvesSaved := (credentialMode.Valid && credentialMode.Int64 == 2 &&
				strings.TrimSpace(nullableString(storedCredentialID)) != "") ||
				(!credentialMode.Valid && strings.TrimSpace(nullableString(storedCredentialID)) != "")
			if resolvesSaved {
				identityBoundary = true
			}
		}
		if !parentID.Valid {
			break
		}
		currentID = normalizeID(parentID.String)
		leaf = false
	}
	return username, domain, nil
}

func resolveNodeCredentialID(database *sql.DB, nodeID string, protocol int64) (string, error) {
	if database == nil {
		return "", errors.New("Wormhole database is not available")
	}
	columns, err := tableColumns(database, "Nodes")
	if err != nil {
		return "", err
	}
	if len(columns) == 0 {
		return "", errors.New("Wormhole database has no connections")
	}
	column := func(name string) string {
		if _, ok := columns[name]; ok {
			return name
		}
		return "NULL"
	}
	currentID := normalizeID(nodeID)
	seen := make(map[string]struct{})
	var resolvedProtocol *int64
	credentialResolved := false
	credentialID := ""
	var credentialProtocol *int64
	credentialProtocolPending := false
	leaf := true
	for currentID != "" {
		if _, duplicate := seen[currentID]; duplicate {
			return "", errors.New("connection tree contains a cycle")
		}
		seen[currentID] = struct{}{}
		var parentID, storedCredentialID sql.NullString
		var storedProtocol, credentialMode, inlinePassword sql.NullInt64
		err := database.QueryRow(
			"SELECT "+column("ParentId")+", "+column("Protocol")+", "+column("CredentialId")+", "+
				column("CredentialMode")+", "+column("UseInlinePassword")+
				" FROM Nodes WHERE lower(Id) = ? LIMIT 1;",
			currentID,
		).Scan(&parentID, &storedProtocol, &storedCredentialID, &credentialMode, &inlinePassword)
		if errors.Is(err, sql.ErrNoRows) {
			if leaf {
				return "", errors.New("connection was not found")
			}
			break
		}
		if err != nil {
			return "", fmt.Errorf("could not resolve the connection credential: %w", err)
		}
		if resolvedProtocol == nil && storedProtocol.Valid {
			value := storedProtocol.Int64
			resolvedProtocol = &value
		}
		if leaf && inlinePassword.Valid && inlinePassword.Int64 != 0 && (protocol == 0 || protocol == 1) {
			credentialResolved = true
		}
		if !credentialResolved {
			if credentialMode.Valid {
				if credentialMode.Int64 != 0 {
					credentialResolved = true
					if credentialMode.Int64 == 2 {
						credentialID = normalizeID(nullableString(storedCredentialID))
						credentialProtocolPending = credentialID != ""
					}
				}
			} else if storedCredentialID.Valid && strings.TrimSpace(storedCredentialID.String) != "" {
				credentialResolved = true
				credentialID = normalizeID(storedCredentialID.String)
				credentialProtocolPending = true
			}
		}
		if credentialProtocolPending && credentialProtocol == nil && storedProtocol.Valid {
			value := storedProtocol.Int64
			credentialProtocol = &value
		}
		if !parentID.Valid {
			break
		}
		currentID = normalizeID(parentID.String)
		leaf = false
	}
	if resolvedProtocol != nil && *resolvedProtocol != protocol {
		return "", errors.New("connection protocol does not match the requested credential protocol")
	}
	if credentialProtocol != nil && *credentialProtocol != protocol {
		return "", nil
	}
	return credentialID, nil
}

func bitwardenSyncIsStale(settings bitwardenCliSettings, now time.Time) bool {
	return settings.LastSyncUtc == nil || now.Sub(*settings.LastSyncUtc) >= 5*time.Minute
}
