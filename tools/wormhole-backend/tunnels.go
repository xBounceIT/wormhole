package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Tunnel settings are deliberately accepted as an opaque JSON object at the IPC boundary. The
// renderer can display and edit every provider without learning how secrets are persisted; the
// backend validates the provider's required fields, DPAPI-protects the exact compatible legacy
// shape, and only returns it after the native authentication gate has admitted the request.
type tunnelWriteRequest struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Kind     int64           `json:"kind"`
	Settings json.RawMessage `json:"settings"`
}

type tunnelReadRequest struct {
	ID string `json:"id"`
}

type tunnelDeleteRequest struct {
	ID string `json:"id"`
}

type tunnelDetails struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Kind     int64           `json:"kind"`
	Settings json.RawMessage `json:"settings"`
}

const tunnelSecretPrefix = "tunnel:"
const maxTunnelProtectedBytes = backendMaxTunnelRequestBytes + 64*1024

// A tunnel save spans both SQLite and a protected sidecar file. Serialize mutations so a
// provider that persists newly accepted trust cannot race an editor save or a delete.
var tunnelMutationMu sync.RWMutex

func createTunnel(databasePath string, request tunnelWriteRequest) (tunnelDetails, error) {
	request.ID = newTunnelID()
	return writeTunnel(databasePath, request, true)
}

func updateTunnel(databasePath string, request tunnelWriteRequest) (tunnelDetails, error) {
	return writeTunnel(databasePath, request, false)
}

func writeTunnel(databasePath string, request tunnelWriteRequest, create bool) (tunnelDetails, error) {
	tunnelMutationMu.Lock()
	defer tunnelMutationMu.Unlock()

	if err := validateTunnelWriteRequest(&request, !create); err != nil {
		return tunnelDetails{}, err
	}

	database, err := openDatabase(databasePath, false)
	if err != nil {
		return tunnelDetails{}, err
	}
	defer database.Close()
	if err := ensureMigrationSchema(database); err != nil {
		return tunnelDetails{}, err
	}
	if exists, err := tableExists(database, "TunnelConfigs"); err != nil {
		return tunnelDetails{}, err
	} else if !exists {
		return tunnelDetails{}, errors.New("the Wormhole database schema does not support VPN tunnels")
	}

	secretPath := legacyTunnelSecretPath(databasePath, request.ID)
	previousKind := int64(-1)
	cacheIdentityChanged := true
	if !create {
		_ = database.QueryRow("SELECT Kind FROM TunnelConfigs WHERE lower(Id) = lower(?);", request.ID).Scan(&previousKind)
		if previousSettings, readErr := readTunnelSettings(database, databasePath, request.ID); readErr == nil {
			defer clearBytes(previousSettings)
			var previousObject map[string]json.RawMessage
			var nextObject map[string]json.RawMessage
			previousErr := json.Unmarshal(previousSettings, &previousObject)
			nextErr := json.Unmarshal(request.Settings, &nextObject)
			defer clearTunnelSettingsMap(previousObject)
			defer clearTunnelSettingsMap(nextObject)
			if previousErr == nil && nextErr == nil {
				cacheIdentityChanged = tunnelProviderCacheMustClear(previousKind, request.Kind, previousObject, nextObject)
			}
		}
	}
	previousSecret, previousSecretErr := readTunnelProtectedFile(secretPath)
	defer clearBytes(previousSecret)
	previousSecretExists := previousSecretErr == nil
	if previousSecretErr != nil && !errors.Is(previousSecretErr, os.ErrNotExist) {
		return tunnelDetails{}, errors.New("could not read the existing VPN tunnel settings")
	}
	transaction, err := database.Begin()
	if err != nil {
		return tunnelDetails{}, fmt.Errorf("could not save VPN tunnel: %w", err)
	}
	committed := false
	secretWritten := false
	defer func() {
		if !committed {
			_ = transaction.Rollback()
			if secretWritten {
				if previousSecretExists {
					_ = writePrivateFileAtomic(secretPath, previousSecret)
				} else {
					if err := os.Remove(secretPath); err == nil || errors.Is(err, os.ErrNotExist) {
						deleteFileProtectionKey(secretPath)
					}
				}
			}
		}
	}()

	var conflictingID string
	err = transaction.QueryRow(
		"SELECT Id FROM TunnelConfigs WHERE lower(Name) = lower(?) AND lower(Id) <> lower(?) LIMIT 1;",
		request.Name, request.ID,
	).Scan(&conflictingID)
	if err == nil {
		return tunnelDetails{}, errors.New("a VPN tunnel with this name already exists")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return tunnelDetails{}, fmt.Errorf("could not validate the VPN tunnel name: %w", err)
	}

	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	if create {
		_, err = transaction.Exec(
			"INSERT INTO TunnelConfigs (Id, Name, Kind, CreatedAt, UpdatedAt) VALUES (?, ?, ?, ?, ?);",
			request.ID, request.Name, request.Kind, timestamp, timestamp,
		)
	} else {
		result, updateErr := transaction.Exec(
			"UPDATE TunnelConfigs SET Name = ?, Kind = ?, UpdatedAt = ? WHERE lower(Id) = lower(?);",
			request.Name, request.Kind, timestamp, request.ID,
		)
		if updateErr == nil {
			var affected int64
			affected, updateErr = result.RowsAffected()
			if updateErr == nil && affected == 0 {
				updateErr = errors.New("VPN tunnel was not found")
			}
		}
		err = updateErr
	}
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return tunnelDetails{}, errors.New("a VPN tunnel with this name already exists")
		}
		return tunnelDetails{}, fmt.Errorf("could not save VPN tunnel: %w", err)
	}

	if err := protectFile(secretPath, request.Settings); err != nil {
		return tunnelDetails{}, errors.New("could not protect VPN tunnel settings")
	}
	secretWritten = true
	// Remove payloads produced by early Electron development builds. Tunnel payloads belong in
	// the dedicated DPAPI file store; CredentialSecrets remains reserved for migrated passwords.
	if _, err := transaction.Exec("DELETE FROM CredentialSecrets WHERE Id = ?;", tunnelSecretID(request.ID)); err != nil {
		return tunnelDetails{}, fmt.Errorf("could not clean up legacy VPN tunnel settings: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return tunnelDetails{}, fmt.Errorf("could not save VPN tunnel: %w", err)
	}
	committed = true
	if !create && cacheIdentityChanged {
		clearTunnelProviderCaches(databasePath, request.ID, previousKind, request.Kind)
	}
	return tunnelDetails{ID: request.ID, Name: request.Name, Kind: request.Kind, Settings: request.Settings}, nil
}

func readTunnel(databasePath string, request tunnelReadRequest) (tunnelDetails, error) {
	tunnelMutationMu.RLock()
	defer tunnelMutationMu.RUnlock()
	return readTunnelUnlocked(databasePath, request)
}

func readTunnelUnlocked(databasePath string, request tunnelReadRequest) (tunnelDetails, error) {
	id := normalizeTunnelID(request.ID)
	if id == "" {
		return tunnelDetails{}, errors.New("VPN tunnel id is invalid")
	}
	database, err := openDatabase(databasePath, true)
	if err != nil {
		return tunnelDetails{}, err
	}
	if database == nil {
		return tunnelDetails{}, errors.New("VPN tunnel was not found")
	}
	defer database.Close()

	var result tunnelDetails
	if err := database.QueryRow("SELECT Id, Name, Kind FROM TunnelConfigs WHERE lower(Id) = lower(?);", id).
		Scan(&result.ID, &result.Name, &result.Kind); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return tunnelDetails{}, errors.New("VPN tunnel was not found")
		}
		return tunnelDetails{}, fmt.Errorf("could not read VPN tunnel: %w", err)
	}
	settings, err := readTunnelSettings(database, databasePath, result.ID)
	if err != nil {
		return tunnelDetails{}, err
	}
	result.Settings = settings
	return result, nil
}

func deleteTunnel(databasePath string, request tunnelDeleteRequest) error {
	tunnelMutationMu.Lock()
	defer tunnelMutationMu.Unlock()

	id := normalizeTunnelID(request.ID)
	if id == "" {
		return errors.New("VPN tunnel id is invalid")
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := ensureMigrationSchema(database); err != nil {
		return err
	}
	if exists, err := tableExists(database, "TunnelConfigs"); err != nil {
		return err
	} else if !exists {
		return errors.New("VPN tunnel was not found")
	}
	columns, err := tableColumns(database, "Nodes")
	if err != nil {
		return err
	}

	transaction, err := database.Begin()
	if err != nil {
		return fmt.Errorf("could not delete VPN tunnel: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = transaction.Rollback()
		}
	}()
	if _, hasTunnelID := columns["TunnelConfigId"]; hasTunnelID {
		var used int
		err = transaction.QueryRow(
			"SELECT 1 FROM Nodes WHERE lower(TunnelConfigId) = lower(?) LIMIT 1;", id,
		).Scan(&used)
		if err == nil {
			return errors.New("this VPN tunnel is still assigned to a connection or folder")
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("could not check VPN tunnel references: %w", err)
		}
	}
	result, err := transaction.Exec("DELETE FROM TunnelConfigs WHERE lower(Id) = lower(?);", id)
	if err != nil {
		return fmt.Errorf("could not delete VPN tunnel: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errors.New("VPN tunnel was not found")
	}
	if _, err := transaction.Exec("DELETE FROM CredentialSecrets WHERE Id = ?;", tunnelSecretID(id)); err != nil {
		return fmt.Errorf("could not delete VPN tunnel settings: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("could not delete VPN tunnel: %w", err)
	}
	committed = true
	// The legacy WinUI app already has no row to reach this blob after a delete. Leaving its
	// DPAPI file in place would retain credentials needlessly, so remove only the exact file.
	secretPath := legacyTunnelSecretPath(databasePath, id)
	if err := os.Remove(secretPath); err == nil || errors.Is(err, os.ErrNotExist) {
		deleteFileProtectionKey(secretPath)
	}
	snapshot := tunnelConfigSnapshot{databasePath: databasePath, id: id}
	removeProtectedTunnelFile(stormshieldCachePath(snapshot))
	removeProtectedTunnelFile(winUIStormshieldCachePath(snapshot))
	clearStormshieldOTPGuard(id)
	removeProtectedTunnelFile(watchguardCachePath(snapshot))
	removeProtectedTunnelFile(winUIWatchguardCachePath(snapshot))
	removeProtectedTunnelFile(azureRefreshPath(snapshot))
	removeProtectedTunnelFile(winUIAzureRefreshPath(snapshot))
	return nil
}

func removeProtectedTunnelFile(path string) {
	if err := os.Remove(path); err == nil || errors.Is(err, os.ErrNotExist) {
		deleteFileProtectionKey(path)
	}
}

func removeProtectedTunnelFileIfCurrent(snapshot tunnelConfigSnapshot, path string) {
	tunnelMutationMu.Lock()
	defer tunnelMutationMu.Unlock()
	if snapshot.updatedAt != "" {
		current, err := loadTunnelSnapshot(snapshot.databasePath, snapshot.id)
		if err != nil || current.kind != snapshot.kind || current.updatedAt != snapshot.updatedAt {
			return
		}
	}
	removeProtectedTunnelFile(path)
}

func tunnelProviderCachePath(snapshot tunnelConfigSnapshot, directory, suffix string) string {
	compact := strings.ReplaceAll(normalizeTunnelID(snapshot.id), "-", "")
	return filepath.Join(filepath.Dir(snapshot.databasePath), directory, compact+suffix)
}

func clearTunnelProviderCaches(databasePath, id string, kinds ...int64) {
	snapshot := tunnelConfigSnapshot{databasePath: databasePath, id: id}
	seen := make(map[int64]bool)
	for _, kind := range kinds {
		if seen[kind] {
			continue
		}
		seen[kind] = true
		switch kind {
		case 3:
			removeProtectedTunnelFile(watchguardCachePath(snapshot))
		case 4:
			removeProtectedTunnelFile(stormshieldCachePath(snapshot))
			clearStormshieldOTPGuard(id)
		case 5:
			removeProtectedTunnelFile(azureRefreshPath(snapshot))
		}
	}
}

func tunnelProviderCacheMustClear(
	previousKind int64,
	nextKind int64,
	previous map[string]json.RawMessage,
	next map[string]json.RawMessage,
) bool {
	if previousKind != nextKind {
		return true
	}
	return providerCacheState(previousKind, previous) != providerCacheState(nextKind, next)
}

func providerCacheState(kind int64, settings map[string]json.RawMessage) string {
	state := providerCacheIdentity(kind, settings)
	switch kind {
	case 3:
		return fmt.Sprintf("%s\n%d\n%t\n%t", state, tunnelSettingNumber(settings, "AuthMode"),
			watchguardHasManualMaterial(settings), strings.TrimSpace(tunnelSettingString(settings, "ProfileOvpn")) != "")
	case 4:
		return fmt.Sprintf("%s\n%d\n%t", state, tunnelSettingNumber(settings, "Mode"), tunnelSettingBool(settings, "UseOtp"))
	default:
		return state
	}
}

func persistTunnelCacheIfCurrent(
	snapshot tunnelConfigSnapshot,
	kind int64,
	state string,
	write func() error,
) error {
	if snapshot.updatedAt == "" {
		return write()
	}
	tunnelMutationMu.Lock()
	defer tunnelMutationMu.Unlock()
	details, err := readTunnelUnlocked(snapshot.databasePath, tunnelReadRequest{ID: snapshot.id})
	if err != nil {
		return errors.New("VPN tunnel changed while authentication was in progress")
	}
	defer clearBytes(details.Settings)
	if details.Kind != kind {
		return errors.New("VPN tunnel changed while authentication was in progress")
	}
	var current map[string]json.RawMessage
	unmarshalErr := json.Unmarshal(details.Settings, &current)
	defer clearTunnelSettingsMap(current)
	if unmarshalErr != nil || providerCacheState(kind, current) != state {
		return errors.New("VPN tunnel changed while authentication was in progress")
	}
	return write()
}

func providerCacheIdentity(kind int64, settings map[string]json.RawMessage) string {
	port := tunnelSettingNumber(settings, "Port")
	if port == 0 {
		port = 443
	}
	boolText := func(name string) string {
		if tunnelSettingBool(settings, name) {
			return "1"
		}
		return "0"
	}
	var material []string
	switch kind {
	case 3:
		material = []string{
			tunnelSettingString(settings, "Server"), fmt.Sprint(port), tunnelSettingString(settings, "Username"),
			boolText("TrustServerCertificate"), tunnelSettingString(settings, "CaPem"),
		}
	case 4:
		appToken := strings.TrimSpace(tunnelSettingString(settings, "AppToken"))
		if appToken == "" {
			appToken = "sslclient"
		}
		material = []string{
			tunnelSettingString(settings, "Server"), fmt.Sprint(port), tunnelSettingString(settings, "Username"),
			appToken, boolText("TrustServerCertificate"), tunnelSettingString(settings, "CaPem"),
		}
	case 5:
		applicationID := strings.TrimSpace(tunnelSettingString(settings, "ApplicationId"))
		if applicationID == "" {
			applicationID = strings.TrimSpace(tunnelSettingString(settings, "Audience"))
		}
		material = []string{
			tunnelSettingString(settings, "TenantId"), tunnelSettingString(settings, "Audience"), applicationID,
		}
	default:
		return ""
	}
	digest := sha256.Sum256([]byte(strings.Join(material, "\n")))
	return hex.EncodeToString(digest[:])
}

func readTunnelSettings(database *sql.DB, databasePath, id string) (json.RawMessage, error) {
	secretPath := legacyTunnelSecretPath(databasePath, id)
	if info, statErr := os.Stat(secretPath); statErr == nil && info.Size() > maxTunnelProtectedBytes {
		return nil, errors.New("VPN tunnel settings are invalid")
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return nil, errors.New("VPN tunnel settings could not be read")
	}
	legacy, legacyErr := unprotectFile(secretPath)
	if legacyErr == nil {
		return validateStoredTunnelSettings(legacy)
	}
	if !errors.Is(legacyErr, os.ErrNotExist) {
		return nil, errors.New("VPN tunnel settings could not be decrypted")
	}

	// Compatibility fallback for short-lived Electron development builds that wrote tunnel
	// payloads to CredentialSecrets before the native file-store contract was restored.
	var encoded, encoding string
	err := database.QueryRow("SELECT Secret, Encoding FROM CredentialSecrets WHERE Id = ?;", tunnelSecretID(id)).
		Scan(&encoded, &encoding)
	if err == nil {
		plaintext, unprotectErr := unprotectStoredSecret(tunnelSecretID(id), encoded, encoding)
		if unprotectErr != nil {
			return nil, errors.New("VPN tunnel settings could not be decrypted")
		}
		return validateStoredTunnelSettings(plaintext)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		if strings.Contains(strings.ToLower(err.Error()), "no such table") {
			// A pre-Electron database may not have been through the credential migration yet.
		} else {
			return nil, fmt.Errorf("could not read VPN tunnel settings: %w", err)
		}
	}

	return nil, errors.New("VPN tunnel settings are missing")
}

func validateStoredTunnelSettings(settings []byte) (json.RawMessage, error) {
	if len(settings) == 0 || len(settings) > backendMaxTunnelRequestBytes {
		return nil, errors.New("VPN tunnel settings are invalid")
	}
	var value map[string]json.RawMessage
	err := json.Unmarshal(settings, &value)
	defer clearTunnelSettingsMap(value)
	if err != nil || value == nil {
		return nil, errors.New("VPN tunnel settings are invalid")
	}
	return append(json.RawMessage(nil), settings...), nil
}

func validateTunnelWriteRequest(request *tunnelWriteRequest, requireID bool) error {
	request.ID = normalizeTunnelID(request.ID)
	request.Name = strings.TrimSpace(request.Name)
	if requireID && request.ID == "" {
		return errors.New("VPN tunnel id is invalid")
	}
	if request.Name == "" || len([]rune(request.Name)) > 128 {
		return errors.New("VPN tunnel name is required and must be 128 characters or fewer")
	}
	if request.Kind < 0 || request.Kind > 6 {
		return errors.New("VPN tunnel type is invalid")
	}
	if len(request.Settings) == 0 || len(request.Settings) > backendMaxTunnelRequestBytes {
		return errors.New("VPN tunnel settings are invalid")
	}
	var settings map[string]json.RawMessage
	err := json.Unmarshal(request.Settings, &settings)
	defer clearTunnelSettingsMap(settings)
	if err != nil || settings == nil {
		return errors.New("VPN tunnel settings must be a JSON object")
	}
	if err := validateTunnelSettings(request.Kind, settings); err != nil {
		return err
	}
	canonical, err := json.Marshal(settings)
	if err != nil {
		return errors.New("VPN tunnel settings are invalid")
	}
	request.Settings = canonical
	return nil
}

func validateTunnelSettings(kind int64, settings map[string]json.RawMessage) error {
	required := func(names ...string) error {
		for _, name := range names {
			if strings.TrimSpace(tunnelSettingString(settings, name)) == "" {
				return fmt.Errorf("VPN tunnel setting %q is required", name)
			}
		}
		return nil
	}
	if kind == 2 || kind == 3 || kind == 4 || kind == 6 {
		if err := validateOptionalTunnelPort(settings, "Port"); err != nil {
			return err
		}
	}
	if kind == 2 {
		if err := validateOptionalTunnelPort(settings, "SamlRedirectPort"); err != nil {
			return err
		}
	}
	boolFields := map[int64][]string{
		2: {"UseSingleSignOn", "UseExternalBrowser", "TrustServerCertificate"},
		3: {"TrustServerCertificate"},
		4: {"UseSingleSignOn", "UseOtp", "TrustServerCertificate"},
		6: {"TrustServerCertificate"},
	}
	for _, name := range boolFields[kind] {
		if err := validateOptionalTunnelBool(settings, name); err != nil {
			return err
		}
	}
	if kind == 3 {
		if err := validateOptionalTunnelInteger(settings, "AuthMode", 0, 2); err != nil {
			return err
		}
	}
	if kind == 4 {
		if err := validateOptionalTunnelInteger(settings, "Mode", 0, 1); err != nil {
			return err
		}
		if err := validateOptionalTunnelInteger(settings, "OpenVpnTransportOverride", 0, 2); err != nil {
			return err
		}
		if err := validateOptionalTunnelInteger(settings, "OpenVpnCompressionFramingOverride", 0, 1); err != nil {
			return err
		}
	}
	if kind == 5 {
		if err := validateOptionalTunnelInteger(settings, "Protocol", 0, 1); err != nil {
			return err
		}
	}
	switch kind {
	case 0:
		return required("InterfacePrivateKey", "InterfaceAddress", "PeerPublicKey", "PeerEndpoint")
	case 1:
		return required("ProfileOvpn")
	case 2:
		if err := required("Host"); err != nil {
			return err
		}
		useSSO := tunnelSettingBool(settings, "UseSingleSignOn")
		if !useSSO {
			return required("Username", "Password")
		}
		if tunnelSettingBool(settings, "UseExternalBrowser") {
			if strings.TrimSpace(tunnelSettingString(settings, "Realm")) != "" {
				return errors.New("external-browser Fortinet single sign-on does not support realms")
			}
		} else if strings.TrimSpace(tunnelSettingString(settings, "ServerCertSha256Pin")) != "" {
			return errors.New("embedded-browser Fortinet single sign-on cannot enforce a server certificate pin")
		}
	case 3:
		if err := required("Server"); err != nil {
			return err
		}
		if hasTunnelDirectiveDelimiter(tunnelSettingString(settings, "Server"), false) ||
			hasTunnelDirectiveDelimiter(tunnelSettingString(settings, "VerifyX509Name"), false) {
			return errors.New("WatchGuard server and certificate subject contain a forbidden character")
		}
		for _, name := range []string{"CaPem", "ClientCertPem", "ClientKeyPem"} {
			if strings.ContainsAny(tunnelSettingString(settings, name), "<>") {
				return errors.New("WatchGuard PEM material contains an invalid angle bracket")
			}
		}
		if tunnelSettingNumber(settings, "AuthMode") == 1 {
			return required("Username", "Password")
		}
	case 4:
		if tunnelSettingNumber(settings, "Mode") == 1 {
			return required("ProfileOvpn")
		}
		if err := required("Server"); err != nil {
			return err
		}
		if !tunnelSettingBool(settings, "UseSingleSignOn") {
			return required("Username", "Password")
		}
	case 5:
		if err := required("TenantId", "Audience"); err != nil {
			return err
		}
		servers := stringListSetting(settings, "Servers")
		if len(servers) == 0 || strings.TrimSpace(servers[0]) == "" {
			return errors.New("VPN tunnel setting \"Servers\" requires at least one gateway")
		}
		for _, server := range servers {
			if hasTunnelDirectiveDelimiter(server, true) {
				return errors.New("Azure VPN gateway entries must be bare host names")
			}
		}
		if strings.ContainsAny(tunnelSettingString(settings, "CaPem"), "<>") {
			return errors.New("Azure VPN CA certificate contains an invalid angle bracket")
		}
		if secret := strings.Join(strings.Fields(tunnelSettingString(settings, "ServerSecretHex")), ""); secret != "" {
			if len(secret) != 512 {
				return errors.New("VPN tunnel setting \"ServerSecretHex\" must contain 512 hexadecimal characters")
			}
			if _, err := hex.DecodeString(secret); err != nil {
				return errors.New("VPN tunnel setting \"ServerSecretHex\" must contain 512 hexadecimal characters")
			}
			settings["ServerSecretHex"], _ = json.Marshal(secret)
		}
	case 6:
		return required("Host", "Username", "Password")
	}
	return nil
}

func hasTunnelDirectiveDelimiter(value string, rejectSpace bool) bool {
	return strings.IndexFunc(value, func(character rune) bool {
		return character == '\'' || character == '"' ||
			(rejectSpace && (character == ' ' || character == '\t')) || unicode.IsControl(character)
	}) >= 0
}

func validateOptionalTunnelBool(settings map[string]json.RawMessage, name string) error {
	raw, present := settings[name]
	if !present || strings.TrimSpace(string(raw)) == "null" {
		return nil
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("VPN tunnel setting %q must be true or false", name)
	}
	return nil
}

func validateOptionalTunnelInteger(
	settings map[string]json.RawMessage,
	name string,
	minimum int64,
	maximum int64,
) error {
	raw, present := settings[name]
	if !present || strings.TrimSpace(string(raw)) == "null" {
		return nil
	}
	var value int64
	if err := json.Unmarshal(raw, &value); err != nil || value < minimum || value > maximum {
		return fmt.Errorf("VPN tunnel setting %q is invalid", name)
	}
	return nil
}

func validateOptionalTunnelPort(settings map[string]json.RawMessage, name string) error {
	raw, present := settings[name]
	if !present || strings.TrimSpace(string(raw)) == "null" {
		return nil
	}
	var empty string
	if json.Unmarshal(raw, &empty) == nil && strings.TrimSpace(empty) == "" {
		return nil
	}
	var port int64
	if err := json.Unmarshal(raw, &port); err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("VPN tunnel setting %q must be a port between 1 and 65535", name)
	}
	return nil
}

func tunnelSettingString(settings map[string]json.RawMessage, name string) string {
	value := settings[name]
	var result string
	_ = json.Unmarshal(value, &result)
	return result
}

func tunnelSettingBool(settings map[string]json.RawMessage, name string) bool {
	var result bool
	_ = json.Unmarshal(settings[name], &result)
	return result
}

func tunnelSettingNumber(settings map[string]json.RawMessage, name string) int64 {
	var result int64
	_ = json.Unmarshal(settings[name], &result)
	return result
}

func clearTunnelSettingsMap(settings map[string]json.RawMessage) {
	for key, value := range settings {
		clearBytes(value)
		delete(settings, key)
	}
}

func tunnelSecretID(id string) string {
	return tunnelSecretPrefix + normalizeTunnelID(id)
}

func normalizeTunnelID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return ""
	}
	compact := strings.ReplaceAll(value, "-", "")
	if len(compact) != 32 {
		return ""
	}
	if _, err := hex.DecodeString(compact); err != nil {
		return ""
	}
	return value
}

func newTunnelID() string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		panic("could not generate VPN tunnel id")
	}
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(bytes[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

func legacyTunnelSecretPath(databasePath, id string) string {
	compact := strings.ReplaceAll(normalizeTunnelID(id), "-", "")
	return filepath.Join(filepath.Dir(databasePath), "tunnels", compact+".dpapi")
}

func writePrivateFileAtomic(path string, contents []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".tunnel-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func readTunnelProtectedFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxTunnelProtectedBytes+1))
	if err != nil {
		return nil, err
	}
	if len(contents) > maxTunnelProtectedBytes {
		return nil, errors.New("protected VPN tunnel settings are too large")
	}
	return contents, nil
}
