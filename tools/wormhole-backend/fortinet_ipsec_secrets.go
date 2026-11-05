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
	hasKey := tunnelSettingString(settings, "PreSharedKey") != ""
	clearBytes(settings["PreSharedKey"])
	delete(settings, "PreSharedKey")
	settings["HasPreSharedKey"], _ = json.Marshal(hasKey)
	return json.Marshal(settings)
}

func validateFortinetIPsecWriteSettings(settings map[string]json.RawMessage) error {
	check := make(map[string]json.RawMessage, len(settings))
	for key, value := range settings {
		check[key] = value
	}
	if marker, present := check["HasPreSharedKey"]; present {
		var hasKey *bool
		if json.Unmarshal(marker, &hasKey) != nil || hasKey == nil || !*hasKey || check["PreSharedKey"] != nil {
			return errors.New("Fortinet IPsec stored key marker is invalid")
		}
		delete(check, "HasPreSharedKey")
		check["PreSharedKey"] = json.RawMessage(`"preserved"`)
	}
	return validateFortinetIPsecSettings(check)
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
	if _, preserve := settings["HasPreSharedKey"]; preserve {
		var kind int64
		if create || database.QueryRow("SELECT Kind FROM TunnelConfigs WHERE lower(Id) = lower(?);", id).Scan(&kind) != nil || kind != 9 {
			return nil, errors.New("the stored Fortinet IPsec gateway key is unavailable")
		}
		previous, err := readTunnelSettings(database, databasePath, id)
		defer clearBytes(previous)
		var stored map[string]json.RawMessage
		unmarshalErr := json.Unmarshal(previous, &stored)
		defer clearTunnelSettingsMap(stored)
		if err != nil || unmarshalErr != nil || tunnelSettingString(stored, "PreSharedKey") == "" {
			return nil, errors.New("the stored Fortinet IPsec gateway key is unavailable")
		}
		settings["PreSharedKey"] = append(json.RawMessage(nil), stored["PreSharedKey"]...)
		delete(settings, "HasPreSharedKey")
	}
	if err := validateFortinetIPsecSettings(settings); err != nil {
		return nil, err
	}
	return json.Marshal(settings)
}
