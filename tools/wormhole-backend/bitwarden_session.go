package main

import (
	"encoding/json"
	"errors"
)

// Session keys are stored only by Go, using the same OS-protected storage as
// other native secrets. The master password is never persisted.
type bitwardenSavedSession struct {
	Key    string `json:"key"`
	Path   string `json:"path"`
	Region int    `json:"region"`
}

func bitwardenSessionPath(databasePath string) string {
	return databasePath + ".bitwarden-session"
}

var (
	protectBitwardenSession   = protectFileContents
	unprotectBitwardenSession = unprotectFileContents
)

func protectSavedBitwardenSession(databasePath, key string) ([]byte, error) {
	if databasePath == "" {
		return nil, errors.New("Wormhole database path is unavailable")
	}
	settings, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(bitwardenSavedSession{key, settings.Path, settings.ServerRegion})
	if err != nil {
		return nil, err
	}
	defer clearBytes(data)
	return protectBitwardenSession(bitwardenSessionPath(databasePath), data)
}

func (m *vncManager) restoreBitwardenSession(expectedGeneration uint64) {
	m.bitwardenMu.RLock()
	needed := m.bitwardenSessionGeneration == expectedGeneration && m.bitwardenSessionKey == "" && m.databasePath != ""
	m.bitwardenMu.RUnlock()
	if !needed {
		return
	}
	settings, err := readBitwardenCliSettings(m.databasePath)
	if err != nil || !settings.Enabled {
		return
	}
	path := bitwardenSessionPath(m.databasePath)
	protected, err := readBoundedRegularFile(path, 64*1024)
	if err != nil {
		return
	}
	defer clearBytes(protected)
	data, err := unprotectBitwardenSession(path, protected)
	if err != nil {
		return
	}
	defer clearBytes(data)
	var saved bitwardenSavedSession
	if json.Unmarshal(data, &saved) != nil || !bitwardenCliPathsEqual(saved.Path, settings.Path) || saved.Region != settings.ServerRegion {
		return
	}
	key, err := bitwardenCliReadSessionKey(saved.Key)
	m.bitwardenMu.Lock()
	defer m.bitwardenMu.Unlock()
	if err == nil && m.bitwardenSessionGeneration == expectedGeneration && m.bitwardenSessionKey == "" {
		m.bitwardenSessionKey = key
	}
}

// Installation may finish after an app lock. Rebind only the existing durable
// session; never install its key back into memory. The caller holds
// bitwardenOperationMu, so login, logout and settings changes cannot race here.
func (m *vncManager) rebindSavedBitwardenSession(sessionKey string) error {
	protected, err := protectSavedBitwardenSession(m.databasePath, sessionKey)
	if err != nil {
		return errors.New("Could not securely update the saved Bitwarden session")
	}
	defer clearBytes(protected)
	if err := writePrivateFileAtomic(bitwardenSessionPath(m.databasePath), protected); err != nil {
		return errors.New("Could not securely update the saved Bitwarden session")
	}
	return nil
}
