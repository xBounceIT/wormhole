package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
	"unicode/utf16"
)

var settingsProcessLocks sync.Map

const (
	authStoreFilename       = "app-auth.dpapi"
	authSettingsFilename    = "settings.json"
	authStoreVersion        = 1
	authSaltLength          = 16
	authHashLength          = 32
	authPbkdf2Iterations    = 600_000
	authMaxPbkdf2Iterations = 5_000_000
	authMaxStoreBytes       = 64 * 1024
	authMaxSettingsBytes    = 1024 * 1024
	authPinMinLength        = 4
	authPinMaxLength        = 12
	authPasswordMinLength   = 8
	authPasswordMaxLength   = 128
)

type authSettings struct {
	Mode               int
	Fallback           int
	IdleTimeoutMinutes *int
}

type authVerifier struct {
	Salt       []byte `json:"Salt"`
	Hash       []byte `json:"Hash"`
	Iterations int    `json:"Iterations"`
}

type authDocument struct {
	Version  int           `json:"Version"`
	Pin      *authVerifier `json:"Pin"`
	Password *authVerifier `json:"Password"`
}

type authHelloStatus struct {
	Available bool   `json:"available"`
	Message   string `json:"message"`
}

type authStateResponse struct {
	Mode               string          `json:"mode"`
	Fallback           string          `json:"fallback"`
	IdleTimeoutMinutes *int            `json:"idleTimeoutMinutes"`
	HasPin             bool            `json:"hasPin"`
	HasPassword        bool            `json:"hasPassword"`
	IsCorrupted        bool            `json:"isCorrupted"`
	Configured         bool            `json:"configured"`
	WindowsHello       authHelloStatus `json:"windowsHello"`
}

type authVerifyRequest struct {
	Method string `json:"method"`
	Secret string `json:"secret"`
}

type authHelloVerifyRequest struct {
	OwnerWindow string `json:"ownerWindow"`
}

type authSetSecretRequest struct {
	Method string `json:"method"`
	Secret string `json:"secret"`
}

type authSettingsRequest struct {
	Mode               string `json:"mode"`
	Fallback           string `json:"fallback"`
	IdleTimeoutMinutes *int   `json:"idleTimeoutMinutes"`
}

type authVerificationResponse struct {
	Succeeded bool   `json:"succeeded"`
	Message   string `json:"message"`
}

func defaultAuthSettings() authSettings {
	minutes := 15
	return authSettings{Fallback: 0, IdleTimeoutMinutes: &minutes}
}

func authPaths(databasePath string) (string, string) {
	dataDirectory := filepath.Dir(databasePath)
	return filepath.Join(dataDirectory, authStoreFilename), filepath.Join(dataDirectory, authSettingsFilename)
}

func readAuthSettingsFile(settingsPath string) ([]byte, error) {
	settingsFile, err := os.Open(settingsPath)
	if err != nil {
		return nil, err
	}
	defer settingsFile.Close()

	contents, err := io.ReadAll(io.LimitReader(settingsFile, authMaxSettingsBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read Wormhole settings: %w", err)
	}
	if len(contents) > authMaxSettingsBytes {
		return nil, errors.New("Wormhole settings file is too large")
	}
	return contents, nil
}

func loadAuthSettings(settingsPath string) (authSettings, error) {
	settings := defaultAuthSettings()
	contents, err := readAuthSettingsFile(settingsPath)
	if errors.Is(err, os.ErrNotExist) {
		return settings, nil
	}
	if err != nil {
		return settings, fmt.Errorf("cannot read Wormhole settings: %w", err)
	}

	var document map[string]json.RawMessage
	if err := json.Unmarshal(contents, &document); err != nil || document == nil {
		// The legacy settings service falls back to defaults when its file is invalid. Keep the
		// same behavior, but allow an auth write to repair the file later.
		return settings, nil
	}
	if value, ok := document["AppAuthenticationMode"]; ok {
		var mode int
		if json.Unmarshal(value, &mode) == nil && mode >= 0 && mode <= 3 {
			settings.Mode = mode
		}
	}
	if value, ok := document["AppAuthenticationHelloFallback"]; ok {
		var fallback int
		if json.Unmarshal(value, &fallback) == nil && fallback >= 0 && fallback <= 1 {
			settings.Fallback = fallback
		}
	}
	if value, ok := document["AppAuthenticationIdleTimeoutMinutes"]; ok {
		if string(bytes.TrimSpace(value)) == "null" {
			settings.IdleTimeoutMinutes = nil
		} else {
			var minutes int
			if json.Unmarshal(value, &minutes) == nil && validIdleTimeout(minutes) {
				settings.IdleTimeoutMinutes = &minutes
			}
		}
	}
	return settings, nil
}

func saveAuthSettings(settingsPath string, settings authSettings) error {
	return updateSettingsDocument(settingsPath, func(document map[string]json.RawMessage) error {
		mode, _ := json.Marshal(settings.Mode)
		fallback, _ := json.Marshal(settings.Fallback)
		document["AppAuthenticationMode"] = mode
		document["AppAuthenticationHelloFallback"] = fallback
		if settings.IdleTimeoutMinutes == nil {
			document["AppAuthenticationIdleTimeoutMinutes"] = json.RawMessage("null")
		} else {
			minutes, _ := json.Marshal(*settings.IdleTimeoutMinutes)
			document["AppAuthenticationIdleTimeoutMinutes"] = minutes
		}
		return nil
	})
}

func updateSettingsDocument(
	settingsPath string,
	mutate func(map[string]json.RawMessage) error,
) error {
	return updateSettingsDocumentWithOptions(
		settingsPath,
		settingsDocumentUpdateOptions{ReplaceMalformed: true},
		func(document map[string]json.RawMessage) (bool, error) {
			if err := mutate(document); err != nil {
				return false, err
			}
			return true, nil
		},
	)
}

var errMalformedSettingsDocument = errors.New("Wormhole settings document is malformed")

type settingsDocumentUpdateOptions struct {
	ReplaceMalformed bool
}

// updateSettingsDocumentWithOptions is the transactional settings primitive used by cautious
// migrations. Existing explicit writes keep their historical repair behavior, while migrations
// can leave a malformed document byte-for-byte untouched for a later recovery attempt.
func updateSettingsDocumentWithOptions(
	settingsPath string,
	options settingsDocumentUpdateOptions,
	mutate func(map[string]json.RawMessage) (bool, error),
) error {
	cleanPath := filepath.Clean(settingsPath)
	lockValue, _ := settingsProcessLocks.LoadOrStore(cleanPath, &sync.Mutex{})
	processLock := lockValue.(*sync.Mutex)
	processLock.Lock()
	defer processLock.Unlock()

	if err := os.MkdirAll(filepath.Dir(cleanPath), 0o700); err != nil {
		return fmt.Errorf("cannot create the Wormhole data directory: %w", err)
	}
	release, err := acquireSettingsFileLock(cleanPath + ".lock")
	if err != nil {
		return err
	}
	defer release()

	document := map[string]json.RawMessage{}
	contents, err := readAuthSettingsFile(cleanPath)
	if err == nil {
		if json.Unmarshal(contents, &document) == nil && document != nil {
			migrateLegacySettingsDocument(document)
		} else {
			if !options.ReplaceMalformed {
				return errMalformedSettingsDocument
			}
			document = map[string]json.RawMessage{}
			currentSchema, _ := json.Marshal(currentSettingsSchemaVersion)
			document[settingsSchemaVersionKey] = currentSchema
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else {
		currentSchema, _ := json.Marshal(currentSettingsSchemaVersion)
		document[settingsSchemaVersionKey] = currentSchema
	}
	if document == nil {
		document = map[string]json.RawMessage{}
	}
	updated, err := mutate(document)
	if err != nil {
		return err
	}
	if !updated {
		return nil
	}
	contents, err = json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot encode Wormhole settings: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(cleanPath), ".wormhole-settings-*.tmp")
	if err != nil {
		return fmt.Errorf("cannot create temporary Wormhole settings: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("cannot protect temporary Wormhole settings: %w", err)
	}
	if _, err := temporary.Write(append(contents, '\n')); err != nil {
		return fmt.Errorf("cannot write Wormhole settings: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("cannot flush Wormhole settings: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("cannot close Wormhole settings: %w", err)
	}
	if err := replaceAuthFile(temporaryPath, cleanPath); err != nil {
		return fmt.Errorf("cannot save Wormhole settings: %w", err)
	}
	return nil
}

func readAuthDocument(storePath string) (authDocument, bool, error) {
	store, err := os.Open(storePath)
	if errors.Is(err, os.ErrNotExist) {
		return authDocument{Version: authStoreVersion}, false, nil
	}
	if err != nil {
		return authDocument{}, false, fmt.Errorf("cannot read the authentication store: %w", err)
	}
	defer store.Close()
	contents, err := io.ReadAll(io.LimitReader(store, authMaxStoreBytes+1))
	if err != nil {
		return authDocument{}, false, fmt.Errorf("cannot read the authentication store: %w", err)
	}
	if len(contents) > authMaxStoreBytes {
		return authDocument{Version: authStoreVersion}, true, nil
	}

	plaintext, err := unprotectAuthDocument(storePath, contents)
	if err != nil {
		return authDocument{Version: authStoreVersion}, true, nil
	}
	defer clearBytes(plaintext)

	var document authDocument
	if err := json.Unmarshal(plaintext, &document); err != nil || document.Version != authStoreVersion ||
		!validAuthVerifier(document.Pin) || !validAuthVerifier(document.Password) {
		return authDocument{Version: authStoreVersion}, true, nil
	}
	return document, false, nil
}

func writeAuthDocument(storePath string, document authDocument) error {
	plaintext, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot encode the authentication store: %w", err)
	}
	defer clearBytes(plaintext)

	protected, err := protectAuthDocument(storePath, plaintext)
	if err != nil {
		return fmt.Errorf("cannot protect the authentication store: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(storePath), 0o700); err != nil {
		return fmt.Errorf("cannot create the Wormhole data directory: %w", err)
	}
	temporaryPath := storePath + ".tmp"
	if err := os.WriteFile(temporaryPath, protected, 0o600); err != nil {
		return fmt.Errorf("cannot write the authentication store: %w", err)
	}
	if err := replaceAuthFile(temporaryPath, storePath); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("cannot replace the authentication store: %w", err)
	}
	return nil
}

func deleteAuthDocument(storePath string) error {
	err := os.Remove(storePath)
	if errors.Is(err, os.ErrNotExist) {
		deleteAuthProtectionKey(storePath)
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot remove the authentication store: %w", err)
	}
	deleteAuthProtectionKey(storePath)
	return nil
}

func authState(databasePath string) (authStateResponse, error) {
	storePath, settingsPath := authPaths(databasePath)
	settings, err := loadAuthSettings(settingsPath)
	if err != nil {
		return authStateResponse{}, err
	}
	document, corrupted, err := readAuthDocument(storePath)
	if err != nil {
		return authStateResponse{}, err
	}
	return buildAuthState(settings, document, corrupted), nil
}

func buildAuthState(settings authSettings, document authDocument, corrupted bool) authStateResponse {
	state := authStateResponse{
		Mode:               authModeName(settings.Mode),
		Fallback:           authFallbackName(settings.Fallback),
		IdleTimeoutMinutes: settings.IdleTimeoutMinutes,
		HasPin:             document.Pin != nil,
		HasPassword:        document.Password != nil,
		IsCorrupted:        corrupted,
		WindowsHello:       unqueriedWindowsHelloStatus(),
	}
	if !corrupted {
		state.Configured = authConfigured(settings, document)
	}
	return state
}

func authConfigured(settings authSettings, document authDocument) bool {
	if settings.Mode == 0 {
		return false
	}
	if settings.Mode == 1 {
		return document.Pin != nil
	}
	if settings.Mode == 2 {
		return document.Password != nil
	}
	return authVerifierForFallback(document, settings.Fallback) != nil
}

func authVerifierForFallback(document authDocument, fallback int) *authVerifier {
	if fallback == 1 {
		return document.Password
	}
	return document.Pin
}

func configuredAuthMethod(settings authSettings) (int, bool) {
	switch settings.Mode {
	case 1:
		return 0, true
	case 2:
		return 1, true
	case 3:
		return settings.Fallback, true
	default:
		return 0, false
	}
}

func authVerify(databasePath string, request authVerifyRequest) (authVerificationResponse, error) {
	method, err := authFallbackValue(request.Method)
	if err != nil {
		return authVerificationResponse{}, err
	}
	storePath, settingsPath := authPaths(databasePath)
	settings, err := loadAuthSettings(settingsPath)
	if err != nil {
		return authVerificationResponse{}, err
	}
	expectedMethod, configured := configuredAuthMethod(settings)
	if !configured {
		return authVerificationResponse{Message: "App lock is off."}, nil
	}
	if method != expectedMethod {
		return authVerificationResponse{Message: invalidAuthSecretMessage(expectedMethod)}, nil
	}
	if validateAuthSecret(method, request.Secret) != "" {
		return authVerificationResponse{Message: invalidAuthSecretMessage(method)}, nil
	}
	document, corrupted, err := readAuthDocument(storePath)
	if err != nil {
		return authVerificationResponse{}, err
	}
	if corrupted {
		return authVerificationResponse{Message: "Wormhole can't read your saved app lock."}, nil
	}
	verifier := authVerifierForFallback(document, method)
	if verifier == nil || !verifyAuthSecret(request.Secret, verifier) {
		return authVerificationResponse{
			Message: invalidAuthSecretMessage(method),
		}, nil
	}
	return authVerificationResponse{Succeeded: true}, nil
}

func authSetSecret(databasePath string, request authSetSecretRequest) (authStateResponse, error) {
	method, err := authFallbackValue(request.Method)
	if err != nil {
		return authStateResponse{}, err
	}
	if validation := validateAuthSecret(method, request.Secret); validation != "" {
		return authStateResponse{}, errors.New(validation)
	}
	storePath, settingsPath := authPaths(databasePath)
	settings, err := loadAuthSettings(settingsPath)
	if err != nil {
		return authStateResponse{}, err
	}
	document, corrupted, err := readAuthDocument(storePath)
	if err != nil {
		return authStateResponse{}, err
	}
	if corrupted {
		document = authDocument{Version: authStoreVersion}
	}
	verifier, err := newAuthVerifier(request.Secret)
	if err != nil {
		return authStateResponse{}, err
	}
	if method == 0 {
		document.Pin = verifier
	} else {
		document.Password = verifier
	}
	if err := writeAuthDocument(storePath, document); err != nil {
		return authStateResponse{}, err
	}
	return buildAuthState(settings, document, false), nil
}

func authUpdateSettings(databasePath string, request authSettingsRequest) (authStateResponse, error) {
	mode, err := authModeValue(request.Mode)
	if err != nil {
		return authStateResponse{}, err
	}
	fallback, err := authFallbackValue(request.Fallback)
	if err != nil {
		return authStateResponse{}, err
	}
	if request.IdleTimeoutMinutes != nil && !validIdleTimeout(*request.IdleTimeoutMinutes) {
		return authStateResponse{}, errors.New("idle timeout must be none, 1, 5, 15, 30, or 60 minutes")
	}

	storePath, settingsPath := authPaths(databasePath)
	document, corrupted, err := readAuthDocument(storePath)
	if err != nil {
		return authStateResponse{}, err
	}
	if corrupted && mode != 0 {
		return authStateResponse{}, errors.New("Wormhole can't read the saved app lock. Set a new PIN or password")
	}
	if mode != 0 {
		candidateSettings := authSettings{Mode: mode, Fallback: fallback, IdleTimeoutMinutes: request.IdleTimeoutMinutes}
		if !authConfigured(candidateSettings, document) {
			return authStateResponse{}, errors.New(requiredAuthSecretMessage(mode, fallback))
		}
	}

	settings := authSettings{Mode: mode, Fallback: fallback, IdleTimeoutMinutes: request.IdleTimeoutMinutes}
	if err := saveAuthSettings(settingsPath, settings); err != nil {
		return authStateResponse{}, err
	}
	if mode == 0 {
		// Publish the disabled setting before removing the verifier. If the settings write fails,
		// the old enabled setting and verifier remain intact instead of creating an unlocked state.
		if err := deleteAuthDocument(storePath); err != nil {
			return authStateResponse{}, err
		}
		document = authDocument{Version: authStoreVersion}
	}
	return buildAuthState(settings, document, false), nil
}

func newAuthVerifier(secret string) (*authVerifier, error) {
	salt := make([]byte, authSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, errors.New("cannot generate an authentication verifier")
	}
	hash := deriveAuthSecret(secret, salt, authPbkdf2Iterations)
	return &authVerifier{Salt: salt, Hash: hash, Iterations: authPbkdf2Iterations}, nil
}

func verifyAuthSecret(secret string, verifier *authVerifier) bool {
	if !validAuthVerifier(verifier) {
		return false
	}
	hash := deriveAuthSecret(secret, verifier.Salt, verifier.Iterations)
	defer clearBytes(hash)
	return hmac.Equal(hash, verifier.Hash)
}

func deriveAuthSecret(secret string, salt []byte, iterations int) []byte {
	result := make([]byte, authHashLength)
	if iterations <= 0 {
		return result
	}
	password := []byte(secret)
	defer clearBytes(password)

	var block [4]byte
	binary.BigEndian.PutUint32(block[:], 1)
	mac := hmac.New(sha256.New, password)
	_, _ = mac.Write(salt)
	_, _ = mac.Write(block[:])
	previous := mac.Sum(nil)
	copy(result, previous)
	for count := 1; count < iterations; count++ {
		mac = hmac.New(sha256.New, password)
		_, _ = mac.Write(previous)
		next := mac.Sum(nil)
		for index := range result {
			result[index] ^= next[index]
		}
		clearBytes(previous)
		previous = next
	}
	clearBytes(previous)
	return result
}

func validAuthVerifier(verifier *authVerifier) bool {
	return verifier == nil ||
		(verifier.Iterations > 0 && verifier.Iterations <= authMaxPbkdf2Iterations &&
			len(verifier.Salt) == authSaltLength && len(verifier.Hash) == authHashLength)
}

func validateAuthSecret(method int, secret string) string {
	length := len(utf16.Encode([]rune(secret)))
	if method == 0 {
		if length < authPinMinLength || length > authPinMaxLength {
			return "PIN must be 4 to 12 digits."
		}
		for _, character := range secret {
			if !unicode.IsDigit(character) {
				return "PIN can contain digits only."
			}
		}
		return ""
	}
	if length < authPasswordMinLength || length > authPasswordMaxLength {
		return "Password must be 8 to 128 characters."
	}
	return ""
}

func validIdleTimeout(minutes int) bool {
	return minutes == 1 || minutes == 5 || minutes == 15 || minutes == 30 || minutes == 60
}

func authModeValue(value string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "disabled":
		return 0, nil
	case "pin":
		return 1, nil
	case "password":
		return 2, nil
	case "windowshello", "windows-hello", "hello":
		return 3, nil
	default:
		return 0, errors.New("unsupported authentication mode")
	}
}

func authModeName(value int) string {
	switch value {
	case 1:
		return "pin"
	case 2:
		return "password"
	case 3:
		return "windowsHello"
	default:
		return "disabled"
	}
}

func authFallbackValue(value string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "pin":
		return 0, nil
	case "password":
		return 1, nil
	default:
		return 0, errors.New("unsupported authentication fallback")
	}
}

func authFallbackName(value int) string {
	if value == 1 {
		return "password"
	}
	return "pin"
}

func invalidAuthSecretMessage(method int) string {
	if method == 0 {
		return "Invalid PIN."
	}
	return "Invalid password."
}

func requiredAuthSecretMessage(mode, fallback int) string {
	if mode == 1 || (mode == 3 && fallback == 0) {
		return "Set a PIN before enabling this unlock method."
	}
	return "Set a password before enabling this unlock method."
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
