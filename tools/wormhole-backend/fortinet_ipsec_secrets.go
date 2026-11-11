package main

import (
	"database/sql"
	"encoding/json"
	"errors"
)

// The editor receives a presence marker, never the gateway-wide PSK. Runtime
// and encrypted backup readers retain access to the Go-owned settings.
func tunnelEditorSettings(kind int64, id string, raw json.RawMessage) (json.RawMessage, error) {
	if kind != 9 {
		return azureVPNEditorSettings(kind, id, raw)
	}
	var settings map[string]json.RawMessage
	if json.Unmarshal(raw, &settings) != nil || settings == nil {
		return nil, errors.New("Fortinet IPsec settings are invalid")
	}
	defer clearTunnelSettingsMap(settings)
	for _, key := range fortinetIPsecSecretKeys {
		has := tunnelSettingString(settings, key) != ""
		clearBytes(settings[key])
		delete(settings, key)
		if has || key == "PreSharedKey" && tunnelSettingNumber(settings, "AuthMethod") != 1 {
			settings["Has"+key], _ = json.Marshal(has)
		}
	}
	return json.Marshal(settings)
}

func validateFortinetIPsecWriteSettings(settings map[string]json.RawMessage) error {
	check := make(map[string]json.RawMessage, len(settings))
	for key, value := range settings {
		check[key] = value
	}
	for _, key := range fortinetIPsecSecretKeys {
		if marker, present := check["Has"+key]; present {
			var hasKey *bool
			if json.Unmarshal(marker, &hasKey) != nil || hasKey == nil || !*hasKey || check[key] != nil {
				return errors.New("Fortinet IPsec stored key marker is invalid")
			}
			delete(check, "Has"+key)
			check[key] = json.RawMessage(`"preserved"`)
		}
	}
	return validateFortinetIPsecConfiguration(check, false)
}

func resolveFortinetIPsecWriteSettings(database *sql.DB, databasePath, id string, raw json.RawMessage, create bool) (json.RawMessage, error) {
	var settings map[string]json.RawMessage
	if json.Unmarshal(raw, &settings) != nil || settings == nil {
		return nil, errors.New("Fortinet IPsec settings are invalid")
	}
	defer clearTunnelSettingsMap(settings)
	if err := validateFortinetIPsecWriteSettings(settings); err != nil {
		return nil, err
	}
	if err := validateFortinetFallback(database, tunnelSettingString(settings, "FallbackTunnelId")); err != nil {
		return nil, err
	}

	var stored map[string]json.RawMessage
	defer func() { clearTunnelSettingsMap(stored) }()
	for _, key := range fortinetIPsecSecretKeys {
		if _, preserve := settings["Has"+key]; !preserve {
			continue
		}
		if stored == nil {
			var kind int64
			if create || database == nil || database.QueryRow("SELECT Kind FROM TunnelConfigs WHERE lower(Id) = lower(?);", id).Scan(&kind) != nil || kind != 9 {
				return nil, errors.New("the stored Fortinet IPsec gateway key is unavailable")
			}
			previous, err := readTunnelSettings(database, databasePath, id)
			unmarshalErr := json.Unmarshal(previous, &stored)
			clearBytes(previous)
			if err != nil || unmarshalErr != nil || stored == nil {
				return nil, errors.New("the stored Fortinet IPsec gateway key is unavailable")
			}
		}
		if tunnelSettingString(stored, key) == "" {
			return nil, errors.New("the stored Fortinet IPsec gateway key is unavailable")
		}
		settings[key] = append(json.RawMessage(nil), stored[key]...)
		delete(settings, "Has"+key)
	}

	if err := validateFortinetIPsecSettings(settings); err != nil {
		return nil, err
	}
	return json.Marshal(settings)
}
