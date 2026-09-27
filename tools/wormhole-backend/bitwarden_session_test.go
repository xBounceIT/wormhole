package main

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func sessionTestManager(t *testing.T) *vncManager {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wormhole.db")
	if err := writeBitwardenCliSettings(path, bitwardenCliSettings{Enabled: true, Path: "cli", ServerRegion: bitwardenCliServerCurrent}); err != nil {
		t.Fatal(err)
	}
	m := newVncManager(nil, newBackendLineWriter(&bytes.Buffer{}))
	m.databasePath = path
	return m
}

func TestBitwardenSessionSurvivesRestartAndAppLock(t *testing.T) {
	m := sessionTestManager(t)
	const key = "private-session-token"
	generation := m.bitwardenGeneration()
	if err := m.setBitwardenSessionForGeneration(key, generation); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(bitwardenSessionPath(m.databasePath))
	if err != nil || bytes.Contains(data, []byte(key)) {
		t.Fatal("session was not protected")
	}
	restarted := &vncManager{databasePath: m.databasePath}
	restarted.restoreBitwardenSession(0)
	if restarted.bitwardenSession() != key {
		t.Fatal("restart lost session")
	}
	m.handleBitwarden(backendCommand{ID: "lock", Action: "bitwarden.clear-session"}, generation)
	if m.bitwardenSession() != "" {
		t.Fatal("lock retained session in memory")
	}
	m.restoreBitwardenSession(generation)
	if m.bitwardenSession() != "" {
		t.Fatal("stale request restored session")
	}
	if err := m.setBitwardenSessionForGeneration("stale", generation); !errors.Is(err, errBitwardenSessionInvalidated) {
		t.Fatal("stale unlock accepted")
	}
	m.handleBitwarden(backendCommand{ID: "stale", Action: "bitwarden.read"}, generation)
	if m.bitwardenSession() != "" {
		t.Fatal("stale dispatch restored session")
	}
	m.handleBitwarden(backendCommand{ID: "authorized", Action: "bitwarden.read"}, m.bitwardenGeneration())
	if m.bitwardenSession() != key {
		t.Fatal("authorized request did not restore session")
	}
	m.restoreBitwardenSession(m.bitwardenGeneration())
	if err := m.resetBitwardenSession(); err != nil {
		t.Fatal(err)
	}
	m.restoreBitwardenSession(m.bitwardenGeneration())
	if m.bitwardenSession() != "" {
		t.Fatal("reset session returned")
	}
	if _, err := os.Stat(bitwardenSessionPath(m.databasePath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reset kept file")
	}
}

func TestBitwardenSessionRejectsInvalidSavedState(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		raw        bool
	}{
		{"corrupt", "not encrypted", true},
		{"oversized", strings.Repeat("x", 64*1024+1), true},
		{"invalid json", "{", false},
		{"empty key", `{"path":"cli","region":2}`, false},
		{"wrong path", `{"key":"secret","path":"other","region":2}`, false},
		{"wrong region", `{"key":"secret","path":"cli","region":0}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := sessionTestManager(t)
			path := bitwardenSessionPath(m.databasePath)
			var err error
			if tc.raw {
				err = os.WriteFile(path, []byte(tc.data), 0600)
			} else {
				err = protectFile(path, []byte(tc.data))
			}
			if err != nil {
				t.Fatal(err)
			}
			m.restoreBitwardenSession(0)
			if m.bitwardenSession() != "" {
				t.Fatal("invalid session restored")
			}
		})
	}
	(&vncManager{}).restoreBitwardenSession(0)
	m := sessionTestManager(t)
	if err := m.setBitwardenSessionForGeneration("", 0); err == nil {
		t.Fatal("empty session accepted")
	}
	if err := m.setBitwardenSessionForGeneration("secret", 0); err != nil {
		t.Fatal(err)
	}
	m.clearBitwardenSession()
	if err := writeBitwardenCliSettings(m.databasePath, bitwardenCliSettings{Enabled: false}); err != nil {
		t.Fatal(err)
	}
	m.restoreBitwardenSession(m.bitwardenGeneration())
	if m.bitwardenSession() != "" {
		t.Fatal("disabled vault restored")
	}
	_, settingsPath := authPaths(m.databasePath)
	if err := os.Remove(settingsPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(settingsPath, 0700); err != nil {
		t.Fatal(err)
	}
	m.restoreBitwardenSession(m.bitwardenGeneration())
	if _, err := protectSavedBitwardenSession(m.databasePath, "secret"); err == nil {
		t.Fatal("settings failure hidden")
	}
}

func TestBitwardenSessionStorageFailureIsReported(t *testing.T) {
	previousDelete := deleteBitwardenSessionProtectionKey
	deleted := false
	deleteBitwardenSessionProtectionKey = func(string) { deleted = true }
	t.Cleanup(func() { deleteBitwardenSessionProtectionKey = previousDelete })
	m := sessionTestManager(t)
	path := bitwardenSessionPath(m.databasePath)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "block"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.setBitwardenSessionForGeneration("secret", 0); err == nil {
		t.Fatal("write failure hidden")
	}
	if m.bitwardenSession() != "" {
		t.Fatal("failed save installed a session")
	}
	if err := m.resetBitwardenSession(); err == nil {
		t.Fatal("removal failure hidden")
	}
	if deleted {
		t.Fatal("failed ciphertext removal deleted its protection key")
	}
}

func TestBitwardenSavedSessionLifecycleThroughCLI(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("CLI fixture is a Windows executable")
	}
	helper := buildBitwardenServiceHelper(t)
	for _, action := range []string{"bitwarden.logout", "bitwarden.set-enabled", "bitwarden.set-config", "invalid-session"} {
		t.Run(action, func(t *testing.T) {
			m := sessionTestManager(t)
			if err := writeBitwardenCliSettings(m.databasePath, bitwardenCliSettings{Enabled: true, Path: helper, ServerRegion: bitwardenCliServerCurrent}); err != nil {
				t.Fatal(err)
			}
			if err := m.setBitwardenSessionForGeneration("session-key", 0); err != nil {
				t.Fatal(err)
			}
			m.clearBitwardenSession()
			m.handleBitwarden(backendCommand{ID: "status", Action: "bitwarden.status"}, m.bitwardenGeneration())
			if m.bitwardenSession() != "session-key" {
				t.Fatal("status did not validate restored session")
			}
			disabled := false
			command := backendCommand{ID: "invalidate", Action: action, Enabled: &disabled, Path: helper, ServerRegion: bitwardenCliServerEurope}
			if action == "invalid-session" {
				if err := m.setBitwardenSessionForGeneration("expired-session", m.bitwardenGeneration()); err != nil {
					t.Fatal(err)
				}
				command.Action = "bitwarden.status"
			}
			m.handleBitwarden(command, m.bitwardenGeneration())
			if m.bitwardenSession() != "" {
				t.Fatal("invalidated session remains in memory")
			}
			if _, err := os.Stat(bitwardenSessionPath(m.databasePath)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalidated session remains on disk")
			}
		})
	}
}

func TestBitwardenSessionIgnoresStaleAuthenticationFailures(t *testing.T) {
	m := sessionTestManager(t)
	if err := m.setBitwardenSessionForGeneration("session-key", 0); err != nil {
		t.Fatal(err)
	}
	m.clearBitwardenSession()
	if err := m.discardBitwardenSession("session-key", 0); err != nil {
		t.Fatal(err)
	}
	m.restoreBitwardenSession(1)
	if m.bitwardenSession() != "session-key" {
		t.Fatal("stale failure revoked durable session")
	}
	if err := m.discardBitwardenSession("", 1); err != nil {
		t.Fatal(err)
	}
	if err := m.discardBitwardenSession("other-key", 1); err != nil {
		t.Fatal(err)
	}
	if err := m.discardBitwardenSession("session-key", 0); err != nil {
		t.Fatal(err)
	}
	if m.bitwardenSession() != "session-key" {
		t.Fatal("unrelated failure revoked current session")
	}
	if err := m.discardBitwardenSession("session-key", 1); err != nil {
		t.Fatal(err)
	}
	m.restoreBitwardenSession(1)
	if m.bitwardenSession() != "" {
		t.Fatal("current authentication failure did not revoke session")
	}
}

func TestBitwardenSessionKeychainWaitDoesNotDelayLock(t *testing.T) {
	for _, operation := range []string{"save", "restore"} {
		t.Run(operation, func(t *testing.T) {
			m := sessionTestManager(t)
			if err := m.setBitwardenSessionForGeneration("session-key", 0); err != nil {
				t.Fatal(err)
			}
			m.clearBitwardenSession()
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			previousProtect, previousUnprotect := protectBitwardenSession, unprotectBitwardenSession
			t.Cleanup(func() { protectBitwardenSession, unprotectBitwardenSession = previousProtect, previousUnprotect })
			block := func(path string, data []byte, run func(string, []byte) ([]byte, error)) ([]byte, error) {
				close(entered)
				<-release
				return run(path, data)
			}
			if operation == "save" {
				protectBitwardenSession = func(path string, data []byte) ([]byte, error) { return block(path, data, previousProtect) }
				go func() { done <- m.setBitwardenSessionForGeneration("new-key", 1) }()
			} else {
				unprotectBitwardenSession = func(path string, data []byte) ([]byte, error) { return block(path, data, previousUnprotect) }
				go func() { m.restoreBitwardenSession(1); done <- nil }()
			}
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				close(release)
				<-done
				t.Fatal("keychain call not reached")
			}
			locked := make(chan struct{})
			go func() { m.clearBitwardenSession(); close(locked) }()
			timely := false
			select {
			case <-locked:
				timely = true
			case <-time.After(time.Second):
			}
			close(release)
			err := <-done
			<-locked
			if !timely {
				t.Fatal("system keychain blocked app lock")
			}
			if operation == "save" && !errors.Is(err, errBitwardenSessionInvalidated) {
				t.Fatal("late save accepted")
			}
			if m.bitwardenSession() != "" {
				t.Fatal("late keychain result restored session after lock")
			}
			protectBitwardenSession, unprotectBitwardenSession = previousProtect, previousUnprotect
			m.restoreBitwardenSession(m.bitwardenGeneration())
			if m.bitwardenSession() != "session-key" {
				t.Fatal("cancelled operation changed saved session")
			}
		})
	}
	if _, err := protectSavedBitwardenSession("", "key"); err == nil {
		t.Fatal("empty workspace path accepted")
	}
}

func TestVncRestoresSavedBitwardenSessionWithoutStartupRequest(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("CLI fixture is a Windows executable")
	}
	m := sessionTestManager(t)
	if err := ensureElectronWorkspaceSchema(m.databasePath); err != nil {
		t.Fatal(err)
	}
	db, err := openDatabase(m.databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m.database = db
	credential := seedLegacyBitwardenCredential(t, m.databasePath, credentialCreateRequest{Name: "VNC", Protocol: "vnc", Provider: "Bitwarden", BitwardenItemID: "item-1"})
	helper := buildBitwardenServiceHelper(t)
	if err := writeBitwardenCliSettings(m.databasePath, bitwardenCliSettings{Enabled: true, Path: helper, ServerRegion: bitwardenCliServerCurrent}); err != nil {
		t.Fatal(err)
	}
	if err := m.setBitwardenSessionForGeneration("session-key", 0); err != nil {
		t.Fatal(err)
	}
	m.clearBitwardenSession()
	stale := newVncSession("stale-vault", m.output, m)
	m.clearBitwardenSession()
	stale.connect(backendCommand{Host: "127.0.0.1", Port: 5900, CredentialID: credential.ID}, db)
	if m.bitwardenSession() != "" {
		t.Fatal("pre-lock VNC request restored a session")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	session := newVncSession("saved-vault", m.output, m)
	session.connect(backendCommand{Host: "127.0.0.1", Port: port, CredentialID: credential.ID}, db)
	if m.bitwardenSession() != "session-key" {
		t.Fatal("direct VNC path skipped session restore")
	}
}

func TestBitwardenStatusAfterConcurrentLockKeepsSavedSession(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("CLI fixture is a Windows executable")
	}
	m := sessionTestManager(t)
	helper := buildBitwardenServiceHelper(t)
	if err := writeBitwardenCliSettings(m.databasePath, bitwardenCliSettings{Enabled: true, Path: helper, ServerRegion: bitwardenCliServerCurrent}); err != nil {
		t.Fatal(err)
	}
	if err := m.setBitwardenSessionForGeneration("session-key", 0); err != nil {
		t.Fatal(err)
	}
	m.clearBitwardenSession()
	previous := unprotectBitwardenSession
	t.Cleanup(func() { unprotectBitwardenSession = previous })
	unprotectBitwardenSession = func(path string, data []byte) ([]byte, error) {
		m.clearBitwardenSession()
		return previous(path, data)
	}
	m.handleBitwarden(backendCommand{ID: "status", Action: "bitwarden.status"}, 1)
	unprotectBitwardenSession = previous
	m.restoreBitwardenSession(m.bitwardenGeneration())
	if m.bitwardenSession() != "session-key" {
		t.Fatal("status completing after lock erased the saved key")
	}
}

func TestBitwardenSessionPathCaseFollowsPlatformConfigurationRules(t *testing.T) {
	m := sessionTestManager(t)
	if err := m.setBitwardenSessionForGeneration("session-key", 0); err != nil {
		t.Fatal(err)
	}
	m.handleBitwarden(backendCommand{ID: "config", Action: "bitwarden.set-config", Path: "CLI", ServerRegion: bitwardenCliServerCurrent}, 0)
	m.clearBitwardenSession()
	m.restoreBitwardenSession(m.bitwardenGeneration())
	want := ""
	if runtime.GOOS == "windows" {
		want = "session-key"
	}
	if m.bitwardenSession() != want {
		t.Fatal("app lock did not follow platform CLI path equality")
	}
	restarted := &vncManager{databasePath: m.databasePath}
	restarted.restoreBitwardenSession(0)
	if restarted.bitwardenSession() != want {
		t.Fatal("restart did not follow platform CLI path equality")
	}
}

func TestBitwardenReenableDiscardsSessionLeftByFailedDisable(t *testing.T) {
	m := sessionTestManager(t)
	var output bytes.Buffer
	m.output = newBackendLineWriter(&output)
	if err := m.setBitwardenSessionForGeneration("old-session", 0); err != nil {
		t.Fatal(err)
	}
	previousRemove, previousEnsure := removeBitwardenSessionFile, ensureBitwardenCliForService
	t.Cleanup(func() { removeBitwardenSessionFile, ensureBitwardenCliForService = previousRemove, previousEnsure })
	removeBitwardenSessionFile = func(string) error { return errors.New("temporary storage failure") }
	ensureBitwardenCliForService = func(string) (any, error) { return nil, nil }
	disabled, enabled := false, true
	m.handleBitwarden(backendCommand{ID: "disable", Action: "bitwarden.set-enabled", Enabled: &disabled}, 0)
	settings, err := readBitwardenCliSettings(m.databasePath)
	if err != nil || settings.Enabled {
		t.Fatal("failed disable did not remain disabled")
	}
	// Model a restart: no in-memory state may be needed to reject the stale key.
	m = &vncManager{databasePath: m.databasePath, output: newBackendLineWriter(&output)}
	m.handleBitwarden(backendCommand{ID: "enable-failed", Action: "bitwarden.set-enabled", Enabled: &enabled}, 0)
	settings, err = readBitwardenCliSettings(m.databasePath)
	if err != nil || settings.Enabled {
		t.Fatal("enabled vault despite failed session cleanup")
	}
	removeBitwardenSessionFile = previousRemove
	m.handleBitwarden(backendCommand{ID: "enable", Action: "bitwarden.set-enabled", Enabled: &enabled}, 0)
	m.restoreBitwardenSession(0)
	if m.bitwardenSession() != "" {
		t.Fatal("re-enabling revived the session from before disable")
	}
	if _, err := os.Stat(bitwardenSessionPath(m.databasePath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("re-enabling left the stale session on disk")
	}
	settings, err = readBitwardenCliSettings(m.databasePath)
	if err != nil || !settings.Enabled {
		t.Fatal("successful cleanup did not enable vault")
	}
	if err := m.setBitwardenSessionForGeneration("new-session", 0); err != nil {
		t.Fatal(err)
	}
	m.handleBitwarden(backendCommand{ID: "enable-again", Action: "bitwarden.set-enabled", Enabled: &enabled}, 0)
	if m.bitwardenSession() != "new-session" {
		t.Fatal("idempotent enabling cleared a current session")
	}
	responses := decodeBackendResponses(t, output.Bytes())
	if len(responses) != 4 || responses[0].OK || responses[1].OK || !responses[2].OK || !responses[3].OK {
		t.Fatal("enable/disable responses did not reflect cleanup failures")
	}
}

func TestBitwardenSessionKeyDeletionDoesNotDelayLock(t *testing.T) {
	for _, discard := range []bool{false, true} {
		m := sessionTestManager(t)
		if err := m.setBitwardenSessionForGeneration("session-key", 0); err != nil {
			t.Fatal(err)
		}
		previous := deleteBitwardenSessionProtectionKey
		entered, release, done := make(chan string, 1), make(chan struct{}), make(chan error, 1)
		deleteBitwardenSessionProtectionKey = func(path string) { entered <- path; <-release; previous(path) }
		t.Cleanup(func() { deleteBitwardenSessionProtectionKey = previous })
		go func() {
			if discard {
				done <- m.discardBitwardenSession("session-key", 0)
			} else {
				done <- m.resetBitwardenSession()
			}
		}()
		var path string
		select {
		case path = <-entered:
		case err := <-done:
			t.Fatal("reset skipped protection key deletion", err)
		case <-time.After(5 * time.Second):
			close(release)
			<-done
			t.Fatal("protection key deletion was not reached")
		}
		_, statErr := os.Stat(path)
		locked := make(chan struct{})
		go func() { m.clearBitwardenSession(); close(locked) }()
		timely := false
		select {
		case <-locked:
			timely = true
		case <-time.After(time.Second):
		}
		close(release)
		err := <-done
		<-locked
		deleteBitwardenSessionProtectionKey = previous
		if err != nil || !timely {
			t.Fatal("key deletion blocked lock or failed", err)
		}
		if path != bitwardenSessionPath(m.databasePath) || !errors.Is(statErr, os.ErrNotExist) {
			t.Fatal("protection key removed before ciphertext")
		}
	}
}

func TestVncDiscardsInvalidRestoredBitwardenSession(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("CLI fixture is a Windows executable")
	}
	m := sessionTestManager(t)
	if err := ensureElectronWorkspaceSchema(m.databasePath); err != nil {
		t.Fatal(err)
	}
	db, err := openDatabase(m.databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m.database = db
	credential := seedLegacyBitwardenCredential(t, m.databasePath, credentialCreateRequest{Name: "VNC", Protocol: "vnc", Provider: "Bitwarden", BitwardenItemID: "item-1"})
	helper := buildBitwardenServiceHelper(t)
	if err := writeBitwardenCliSettings(m.databasePath, bitwardenCliSettings{Enabled: true, Path: helper, ServerRegion: bitwardenCliServerCurrent}); err != nil {
		t.Fatal(err)
	}
	if err := m.setBitwardenSessionForGeneration("expired-session", 0); err != nil {
		t.Fatal(err)
	}
	m.clearBitwardenSession()
	for _, id := range []string{"first-attempt", "retry"} {
		session := newVncSession(id, m.output, m)
		session.connect(backendCommand{Host: "127.0.0.1", Port: 5900, CredentialID: credential.ID}, db)
		if m.bitwardenSession() != "" {
			t.Fatal("VNC retained a rejected session in memory")
		}
		if _, err := os.Stat(bitwardenSessionPath(m.databasePath)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("VNC retained a rejected session on disk")
		}
	}
}

func TestBitwardenInstallationRebindsSessionToManagedPath(t *testing.T) {
	for _, action := range []string{"bitwarden.install", "bitwarden.ensure-installed", "bitwarden.set-enabled"} {
		t.Run(action, func(t *testing.T) {
			m := sessionTestManager(t)
			if err := m.setBitwardenSessionForGeneration("session-key", 0); err != nil {
				t.Fatal(err)
			}
			previousInstall, previousEnsure := installBitwardenCliForService, ensureBitwardenCliForService
			t.Cleanup(func() { installBitwardenCliForService, ensureBitwardenCliForService = previousInstall, previousEnsure })
			installer := func(path string) (any, error) {
				settings, err := readBitwardenCliSettings(path)
				if err != nil {
					return nil, err
				}
				settings.Path = "new-managed-cli"
				return nil, writeBitwardenCliSettings(path, settings)
			}
			installBitwardenCliForService, ensureBitwardenCliForService = installer, installer
			enabled := true
			m.handleBitwarden(backendCommand{ID: "install", Action: action, Enabled: &enabled}, 0)
			m.clearBitwardenSession()
			m.restoreBitwardenSession(m.bitwardenGeneration())
			if m.bitwardenSession() != "session-key" {
				t.Fatal("managed installation lost the saved session")
			}
			before, err := os.ReadFile(bitwardenSessionPath(m.databasePath))
			if err != nil {
				t.Fatal(err)
			}
			m.handleBitwarden(backendCommand{ID: "already-installed", Action: action, Enabled: &enabled}, m.bitwardenGeneration())
			after, err := os.ReadFile(bitwardenSessionPath(m.databasePath))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("unchanged installer path rewrote the session")
			}
		})
	}
}

func TestBitwardenInstallationHonorsFailureAndLock(t *testing.T) {
	m := sessionTestManager(t)
	if err := m.setBitwardenSessionForGeneration("session-key", 0); err != nil {
		t.Fatal(err)
	}
	previous := installBitwardenCliForService
	t.Cleanup(func() { installBitwardenCliForService = previous })
	installBitwardenCliForService = func(string) (any, error) { return nil, errors.New("installation failed") }
	if _, err := m.installBitwardenCliForSession(false); err == nil {
		t.Fatal("installer failure hidden")
	}
	m.clearBitwardenSession()
	m.restoreBitwardenSession(1)
	if m.bitwardenSession() != "session-key" {
		t.Fatal("failed installation lost session")
	}
	installBitwardenCliForService = func(path string) (any, error) {
		settings, err := readBitwardenCliSettings(path)
		if err != nil {
			return nil, err
		}
		settings.Path = "new-managed-cli"
		m.clearBitwardenSession()
		return nil, writeBitwardenCliSettings(path, settings)
	}
	var output bytes.Buffer
	m.output = newBackendLineWriter(&output)
	m.handleBitwarden(backendCommand{ID: "late-install", Action: "bitwarden.install"}, 1)
	responses := decodeBackendResponses(t, output.Bytes())
	if len(responses) != 1 || responses[0].OK {
		t.Fatal("installation request survived an app lock")
	}
	if m.bitwardenSession() != "" {
		t.Fatal("late installation unlocked vault")
	}
	restarted := &vncManager{databasePath: m.databasePath}
	restarted.restoreBitwardenSession(0)
	if restarted.bitwardenSession() != "session-key" {
		t.Fatal("installation across lock lost the durable session")
	}
}

func TestBitwardenInstallCannotBypassFailedDisableCleanup(t *testing.T) {
	m := sessionTestManager(t)
	if err := m.setBitwardenSessionForGeneration("session-key", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := setBitwardenCliEnabled(m.databasePath, false); err != nil {
		t.Fatal(err)
	}
	previousRemove, previousInstall := removeBitwardenSessionFile, installBitwardenCliForService
	t.Cleanup(func() { removeBitwardenSessionFile, installBitwardenCliForService = previousRemove, previousInstall })
	called := false
	installBitwardenCliForService = func(path string) (any, error) { called = true; return setBitwardenCliEnabled(path, true) }
	removeBitwardenSessionFile = func(string) error { return errors.New("removal failed") }
	if _, err := m.installBitwardenCliForSession(false); err == nil || called {
		t.Fatal("installation bypassed failed session cleanup")
	}
	removeBitwardenSessionFile = previousRemove
	if _, err := m.installBitwardenCliForSession(false); err != nil || !called {
		t.Fatal("installation did not resume after cleanup", err)
	}
	m.restoreBitwardenSession(0)
	if m.bitwardenSession() != "" {
		t.Fatal("installation revived a disabled session")
	}
}

func TestBitwardenEnableReportsAutomaticInstallationFailure(t *testing.T) {
	m := sessionTestManager(t)
	var output bytes.Buffer
	m.output = newBackendLineWriter(&output)
	previous := ensureBitwardenCliForService
	t.Cleanup(func() { ensureBitwardenCliForService = previous })
	ensureBitwardenCliForService = func(string) (any, error) { return nil, errors.New("installation failed") }
	enabled := true
	m.handleBitwarden(backendCommand{ID: "enable", Action: "bitwarden.set-enabled", Enabled: &enabled}, 0)
	responses := decodeBackendResponses(t, output.Bytes())
	if len(responses) != 1 || responses[0].OK {
		t.Fatal("automatic installation error was hidden")
	}
}

func TestBitwardenSessionRebindReportsStorageFailures(t *testing.T) {
	for _, failure := range []string{"protection", "write"} {
		t.Run(failure, func(t *testing.T) {
			m := sessionTestManager(t)
			m.clearBitwardenSession()
			if failure == "protection" {
				previous := protectBitwardenSession
				t.Cleanup(func() { protectBitwardenSession = previous })
				protectBitwardenSession = func(string, []byte) ([]byte, error) {
					return nil, errors.New("private error details")
				}
			} else if err := os.Mkdir(bitwardenSessionPath(m.databasePath), 0700); err != nil {
				t.Fatal(err)
			}
			err := m.rebindSavedBitwardenSession("session-key")
			if err == nil || strings.Contains(err.Error(), "private error details") {
				t.Fatal("storage failure was hidden or leaked private details", err)
			}
			if m.bitwardenSession() != "" {
				t.Fatal("failed metadata update unlocked vault")
			}
		})
	}
}

func TestBitwardenConfigRequiresSessionCleanupBeforeCommit(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		m := sessionTestManager(t)
		if err := m.setBitwardenSessionForGeneration("session-key", 0); err != nil {
			t.Fatal(err)
		}
		settings, err := readBitwardenCliSettings(m.databasePath)
		if err != nil {
			t.Fatal(err)
		}
		target := "other-cli"
		if rollback {
			// Simulate a stale file left by an earlier failed configuration change.
			settings.Path, target = target, settings.Path
			if err := writeBitwardenCliSettings(m.databasePath, settings); err != nil {
				t.Fatal(err)
			}
		}
		previous := removeBitwardenSessionFile
		removeBitwardenSessionFile = func(string) error { return errors.New("cannot remove session") }
		_, _, err = m.setBitwardenCliConfig(target, settings.ServerRegion)
		removeBitwardenSessionFile = previous
		if err == nil {
			t.Fatal("configuration accepted failed cleanup")
		}
		after, err := readBitwardenCliSettings(m.databasePath)
		if err != nil || after.Path != settings.Path {
			t.Fatal("failed cleanup changed configuration", err)
		}
		if _, _, err := m.setBitwardenCliConfig(target, settings.ServerRegion); err != nil {
			t.Fatal(err)
		}
		if _, _, err := m.setBitwardenCliConfig("cli", settings.ServerRegion); err != nil {
			t.Fatal(err)
		}
		restarted := &vncManager{databasePath: m.databasePath}
		restarted.restoreBitwardenSession(0)
		if restarted.bitwardenSession() != "" {
			t.Fatal("configuration rollback revived stale session")
		}
	}
}
