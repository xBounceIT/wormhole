package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const azureImportKeyMaxAge = 24 * time.Hour

type azureImportKey struct {
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"createdAt"`
	Secret    string    `json:"secret"`
}

// Import references contain only random IDs. The protected records are scoped
// to the owning database and never become part of renderer settings or backups.
func azureImportKeyPath(databasePath, id string) string {
	id = normalizeTunnelID(id)
	absolute, err := filepath.Abs(databasePath)
	if err != nil || id == "" || strings.TrimSpace(databasePath) == "" {
		return ""
	}
	absolute = filepath.Clean(absolute)
	if runtime.GOOS == "windows" {
		absolute = strings.ToLower(absolute)
	}
	digest := sha256.Sum256([]byte(absolute))
	return filepath.Join(filepath.Dir(databasePath), "azure-vpn-imports", hex.EncodeToString(digest[:]), strings.ReplaceAll(id, "-", "")+".dpapi")
}

func storeAzureImportKey(databasePath, secret string) (string, error) {
	secret = strings.Join(strings.Fields(secret), "")
	if len(secret) != azureServerSecretChars {
		return "", errors.New("Azure VPN server secret must contain 512 hexadecimal characters")
	}
	decoded, err := hex.DecodeString(secret)
	defer clearBytes(decoded)
	if err != nil {
		return "", errors.New("Azure VPN server secret must contain 512 hexadecimal characters")
	}
	id := newTunnelID()
	path := azureImportKeyPath(databasePath, id)
	if path == "" {
		return "", errors.New("could not protect the imported Azure VPN server key")
	}
	plaintext, err := json.Marshal(azureImportKey{Version: 1, CreatedAt: time.Now().UTC(), Secret: secret})
	if err != nil {
		return "", errors.New("could not protect the imported Azure VPN server key")
	}
	defer clearBytes(plaintext)
	if err := protectFile(path, plaintext); err != nil {
		removeAzureImportKey(databasePath, id)
		return "", errors.New("could not protect the imported Azure VPN server key")
	}
	cleanupAzureImportKeys(databasePath, id)
	return "import:" + id, nil
}

func removeAzureImportKey(databasePath, id string) {
	path := azureImportKeyPath(databasePath, id)
	if path != "" {
		if err := os.Remove(path); err == nil || errors.Is(err, os.ErrNotExist) {
			deleteFileProtectionKey(path)
		}
	}
}

func cleanupAzureImportKeys(databasePath, currentID string) {
	path := azureImportKeyPath(databasePath, currentID)
	if path == "" {
		return
	}
	directory := filepath.Dir(path)
	entries, _ := os.ReadDir(directory)
	for _, entry := range entries {
		compact := strings.TrimSuffix(entry.Name(), ".dpapi")
		if entry.IsDir() || len(compact) != 32 || !strings.HasSuffix(entry.Name(), ".dpapi") {
			continue
		}
		id := compact[:8] + "-" + compact[8:12] + "-" + compact[12:16] + "-" + compact[16:20] + "-" + compact[20:]
		if normalizeTunnelID(id) == "" || id == currentID {
			continue
		}
		if info, err := entry.Info(); err == nil && time.Since(info.ModTime()) > azureImportKeyMaxAge {
			removeAzureImportKey(databasePath, id)
		}
	}
}

func loadAzureImportKey(databasePath, id string) (string, error) {
	path := azureImportKeyPath(databasePath, id)
	protected, err := readTunnelProtectedFile(path)
	defer clearBytes(protected)
	if err != nil || len(protected) > 8*1024 {
		return "", errors.New("the imported Azure VPN server key is unavailable; import the profile again")
	}
	plaintext, err := unprotectFileContents(path, protected)
	if err != nil {
		return "", errors.New("the imported Azure VPN server key is unavailable; import the profile again")
	}
	defer clearBytes(plaintext)
	var record azureImportKey
	if json.Unmarshal(plaintext, &record) != nil || record.Version != 1 || time.Since(record.CreatedAt) < 0 || time.Since(record.CreatedAt) > azureImportKeyMaxAge {
		return "", errors.New("the imported Azure VPN server key has expired; import the profile again")
	}
	decoded, err := hex.DecodeString(record.Secret)
	defer clearBytes(decoded)
	if err != nil || len(record.Secret) != azureServerSecretChars {
		return "", errors.New("the imported Azure VPN server key is invalid; import the profile again")
	}
	return record.Secret, nil
}

func resolveAzureVPNServerSecret(database *sql.DB, databasePath string, raw json.RawMessage) (json.RawMessage, string, error) {
	var settings map[string]json.RawMessage
	if json.Unmarshal(raw, &settings) != nil || settings == nil {
		return nil, "", errors.New("Azure VPN settings are invalid")
	}
	defer clearTunnelSettingsMap(settings)
	ref := ""
	if value, present := settings["ServerSecretRef"]; present {
		if string(value) == "null" || json.Unmarshal(value, &ref) != nil {
			return nil, "", errors.New("Azure VPN server key reference is invalid")
		}
	}
	delete(settings, "ServerSecretRef")
	importID := ""
	if ref != "" {
		if strings.TrimSpace(tunnelSettingString(settings, "ServerSecretHex")) != "" {
			return nil, "", errors.New("Azure VPN server key settings conflict")
		}
		kind, value, _ := strings.Cut(ref, ":")
		id := normalizeTunnelID(value)
		if id == "" {
			return nil, "", errors.New("Azure VPN server key reference is invalid")
		}
		secret := ""
		var err error
		switch kind {
		case "import":
			secret, err = loadAzureImportKey(databasePath, id)
			importID = id
		case "tunnel":
			var provider int64
			if database.QueryRow("SELECT Kind FROM TunnelConfigs WHERE lower(Id) = lower(?);", id).Scan(&provider) != nil || provider != 5 {
				return nil, "", errors.New("the stored Azure VPN server key is unavailable")
			}
			stored, readErr := readTunnelSettings(database, databasePath, id)
			defer clearBytes(stored)
			var previous map[string]json.RawMessage
			unmarshalErr := json.Unmarshal(stored, &previous)
			defer clearTunnelSettingsMap(previous)
			if readErr != nil || unmarshalErr != nil {
				return nil, "", errors.New("the stored Azure VPN server key is unavailable")
			}
			secret = tunnelSettingString(previous, "ServerSecretHex")
			if secret == "" {
				return nil, "", errors.New("the stored Azure VPN server key is unavailable")
			}
		default:
			return nil, "", errors.New("Azure VPN server key reference is invalid")
		}
		if err != nil {
			return nil, "", err
		}
		settings["ServerSecretHex"], _ = json.Marshal(secret)
		if err := validateTunnelSettings(5, settings); err != nil {
			return nil, "", err
		}
	}
	encoded, err := json.Marshal(settings)
	return encoded, importID, err
}

// Only the public tunnel read/write responses use this projection. Runtime,
// cache ownership checks and backups continue reading the Go-owned payload.
func azureVPNEditorSettings(kind int64, id string, raw json.RawMessage) (json.RawMessage, error) {
	if kind != 5 {
		return raw, nil
	}
	var settings map[string]json.RawMessage
	if json.Unmarshal(raw, &settings) != nil || settings == nil {
		return nil, errors.New("Azure VPN settings are invalid")
	}
	defer clearTunnelSettingsMap(settings)
	ref := ""
	if strings.TrimSpace(tunnelSettingString(settings, "ServerSecretHex")) != "" {
		ref = "tunnel:" + id
	}
	delete(settings, "ServerSecretHex")
	settings["ServerSecretRef"], _ = json.Marshal(ref)
	return json.Marshal(settings)
}
