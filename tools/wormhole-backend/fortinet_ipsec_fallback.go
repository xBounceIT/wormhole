package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync/atomic"
)

func fortinetFallbackID(raw json.RawMessage) string {
	var settings map[string]json.RawMessage
	if json.Unmarshal(raw, &settings) != nil {
		return ""
	}
	defer clearTunnelSettingsMap(settings)
	return normalizeTunnelID(tunnelSettingString(settings, "FallbackTunnelId"))
}
func validateFortinetFallback(database *sql.DB, id string) error {
	if id == "" {
		return nil
	}
	var kind int64
	if database == nil || database.QueryRow("SELECT Kind FROM TunnelConfigs WHERE lower(Id)=lower(?);", id).Scan(&kind) != nil || kind != 2 {
		return errors.New("SSL fallback must reference an existing Fortinet SSL VPN")
	}
	return nil
}
func loadFortinetFallback(snapshot tunnelConfigSnapshot) (tunnelConfigSnapshot, error) {
	id := fortinetFallbackID(snapshot.settings)
	if id == "" {
		return tunnelConfigSnapshot{}, nil
	}
	fallback, err := loadTunnelSnapshot(snapshot.databasePath, id)
	if err != nil || fallback.kind != 2 {
		return tunnelConfigSnapshot{}, errors.New("Fortinet SSL fallback is unavailable")
	}
	fallback, err = loadTunnelSnapshotSettings(fallback)
	if err != nil {
		return fallback, err
	}
	fallback.identity = sshJumpSnapshotIdentity(fallback, nil, "", true)
	return fallback, nil
}
func pinFortinetFallback(snapshot tunnelConfigSnapshot) (tunnelConfigSnapshot, error) {
	if snapshot.kind != 9 {
		return snapshot, nil
	}
	fallback, err := loadFortinetFallback(snapshot)
	defer clearBytes(fallback.settings)
	if err != nil {
		clearBytes(snapshot.settings)
		return snapshot, err
	}
	snapshot.fallbackIdentity = fallback.identity
	return snapshot, nil
}

// Fallback is a second VPN startup, never a direct route. The SSL profile keeps
// its own protected credentials and native authentication flow. A user-cancelled
// prompt aborts both attempts. The pool's identity includes the fallback's HMAC.
func startTunnelProcess(ctx context.Context, snapshot tunnelConfigSnapshot) (*tunnelProcess, error) {
	return startTunnelWithFallback(ctx, snapshot, startSingleTunnelProcess)
}
func startTunnelWithFallback(ctx context.Context, snapshot tunnelConfigSnapshot, start func(context.Context, tunnelConfigSnapshot) (*tunnelProcess, error)) (*tunnelProcess, error) {
	if snapshot.kind != 9 {
		return start(ctx, snapshot)
	}
	if snapshot.settings == nil {
		var err error
		snapshot, err = loadTunnelSnapshotSettings(snapshot)
		if err != nil {
			return nil, err
		}
	}
	defer clearBytes(snapshot.settings)
	fallback, err := loadFortinetFallback(snapshot)
	if err != nil {
		return nil, err
	}
	defer clearBytes(fallback.settings)
	if snapshot.fallbackIdentity != "" && fallback.identity != snapshot.fallbackIdentity {
		return nil, errors.New("SSL fallback changed during VPN startup")
	}
	var promptFailed atomic.Bool
	handler := snapshot.prompt
	if handler == nil {
		handler = tunnelPromptHandlerFromContext(ctx)
	}
	if handler != nil {
		snapshot.prompt = func(ctx context.Context, p tunnelPrompt) (string, error) {
			value, err := handler(ctx, p)
			if err != nil {
				promptFailed.Store(true)
			}
			return value, err
		}
	}
	process, primaryErr := start(ctx, snapshot)
	if primaryErr == nil || fallback.id == "" || ctx.Err() != nil || promptFailed.Load() {
		return process, primaryErr
	}
	if process != nil {
		process.close()
	}
	if err := reportTunnelProgress(ctx, "starting", "Connecting through Fortinet SSL fallback"); err != nil {
		return nil, err
	}
	latest, err := loadTunnelSnapshot(fallback.databasePath, fallback.id)
	if err == nil {
		latest, err = loadTunnelSnapshotSettings(latest)
	}
	defer clearBytes(latest.settings)
	if err != nil || sshJumpSnapshotIdentity(latest, nil, "", true) != fallback.identity {
		return nil, errors.New("SSL fallback changed during VPN startup")
	}
	fallback.prompt = snapshot.prompt
	fallback.progress = snapshot.progress
	process, err = start(ctx, fallback)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if promptFailed.Load() {
			return nil, err
		}
		return nil, errors.New("Fortinet IPsec and SSL fallback could not connect")
	}
	process.identity = snapshot.identity
	return process, nil
}
