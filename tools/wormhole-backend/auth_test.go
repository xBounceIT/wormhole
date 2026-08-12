package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeriveAuthSecretMatchesPbkdf2Sha256Vector(t *testing.T) {
	actual := deriveAuthSecret("password", []byte("salt"), 1)
	expected, err := hex.DecodeString("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != string(expected) {
		t.Fatalf("unexpected PBKDF2 result: %x", actual)
	}
}

func TestValidateAuthSecretMatchesWinUiRules(t *testing.T) {
	for _, test := range []struct {
		name   string
		method int
		secret string
		valid  bool
	}{
		{name: "short pin", method: 0, secret: "123", valid: false},
		{name: "unicode pin digit", method: 0, secret: "１２３４", valid: true},
		{name: "pin letters", method: 0, secret: "12a4", valid: false},
		{name: "short password", method: 1, secret: "1234567", valid: false},
		{name: "unicode password", method: 1, secret: "pässword🔐", valid: true},
		{name: "overlong password", method: 1, secret: strings.Repeat("a", authPasswordMaxLength+1), valid: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if valid := validateAuthSecret(test.method, test.secret) == ""; valid != test.valid {
				t.Fatalf("validation=%v, want %v", valid, test.valid)
			}
		})
	}
}

func TestAuthModeNamesValuesAndMessages(t *testing.T) {
	for _, test := range []struct {
		input string
		value int
	}{
		{input: "disabled", value: 0},
		{input: " PIN ", value: 1},
		{input: "password", value: 2},
		{input: "windowshello", value: 3},
		{input: "windows-hello", value: 3},
		{input: "hello", value: 3},
	} {
		value, err := authModeValue(test.input)
		if err != nil {
			t.Fatalf("authModeValue(%q): %v", test.input, err)
		}
		if value != test.value {
			t.Fatalf("authModeValue(%q) = %d, want %d", test.input, value, test.value)
		}
	}
	if _, err := authModeValue("unsupported"); err == nil {
		t.Fatal("authModeValue accepted an unsupported mode")
	}

	for _, test := range []struct {
		value int
		name  string
	}{
		{value: 0, name: "disabled"},
		{value: 1, name: "pin"},
		{value: 2, name: "password"},
		{value: 3, name: "windowsHello"},
		{value: 99, name: "disabled"},
	} {
		if name := authModeName(test.value); name != test.name {
			t.Fatalf("authModeName(%d) = %q, want %q", test.value, name, test.name)
		}
	}

	for _, test := range []struct {
		input string
		value int
	}{
		{input: " PIN ", value: 0},
		{input: "password", value: 1},
	} {
		value, err := authFallbackValue(test.input)
		if err != nil {
			t.Fatalf("authFallbackValue(%q): %v", test.input, err)
		}
		if value != test.value {
			t.Fatalf("authFallbackValue(%q) = %d, want %d", test.input, value, test.value)
		}
	}
	if _, err := authFallbackValue("unsupported"); err == nil {
		t.Fatal("authFallbackValue accepted an unsupported fallback")
	}
	if name := authFallbackName(0); name != "pin" {
		t.Fatalf("authFallbackName(0) = %q, want pin", name)
	}
	if name := authFallbackName(1); name != "password" {
		t.Fatalf("authFallbackName(1) = %q, want password", name)
	}
	if name := authFallbackName(99); name != "pin" {
		t.Fatalf("authFallbackName(99) = %q, want pin", name)
	}

	if message := invalidAuthSecretMessage(0); message != "Invalid PIN." {
		t.Fatalf("invalidAuthSecretMessage(0) = %q", message)
	}
	if message := invalidAuthSecretMessage(1); message != "Invalid password." {
		t.Fatalf("invalidAuthSecretMessage(1) = %q", message)
	}
	if message := requiredAuthSecretMessage(1, 1); message != "Set a PIN before enabling this unlock method." {
		t.Fatalf("unexpected PIN requirement: %q", message)
	}
	if message := requiredAuthSecretMessage(3, 0); message != "Set a PIN before enabling this unlock method." {
		t.Fatalf("unexpected Windows Hello PIN requirement: %q", message)
	}
	if message := requiredAuthSecretMessage(2, 0); message != "Set a password before enabling this unlock method." {
		t.Fatalf("unexpected password requirement: %q", message)
	}
}

func TestAuthConfiguredRequiresTheVerifierSelectedByTheMode(t *testing.T) {
	pin := &authVerifier{}
	password := &authVerifier{}
	document := authDocument{Pin: pin, Password: password}

	for _, test := range []struct {
		settings authSettings
		want     bool
	}{
		{settings: authSettings{Mode: 0}, want: false},
		{settings: authSettings{Mode: 1}, want: true},
		{settings: authSettings{Mode: 2}, want: true},
		{settings: authSettings{Mode: 3, Fallback: 0}, want: true},
		{settings: authSettings{Mode: 3, Fallback: 1}, want: true},
	} {
		if configured := authConfigured(test.settings, document); configured != test.want {
			t.Fatalf("authConfigured(%+v) = %t, want %t", test.settings, configured, test.want)
		}
	}

	if authConfigured(authSettings{Mode: 1}, authDocument{}) {
		t.Fatal("PIN mode was configured without a PIN verifier")
	}
	if authConfigured(authSettings{Mode: 2}, authDocument{}) {
		t.Fatal("password mode was configured without a password verifier")
	}
	if authConfigured(authSettings{Mode: 3, Fallback: 1}, authDocument{}) {
		t.Fatal("Windows Hello was configured without its fallback verifier")
	}
}

func TestAuthSettingsPreserveLegacySettings(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "settings.json")
	initial := map[string]any{
		"Theme":                               "dark",
		"AppAuthenticationMode":               2,
		"AppAuthenticationHelloFallback":      1,
		"AppAuthenticationIdleTimeoutMinutes": nil,
	}
	contents, err := json.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}

	settings, err := loadAuthSettings(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if settings.Mode != 2 || settings.Fallback != 1 || settings.IdleTimeoutMinutes != nil {
		t.Fatalf("unexpected legacy settings: %#v", settings)
	}

	minutes := 30
	settings.IdleTimeoutMinutes = &minutes
	if err := saveAuthSettings(settingsPath, settings); err != nil {
		t.Fatal(err)
	}
	var saved map[string]json.RawMessage
	savedContents, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(savedContents, &saved); err != nil {
		t.Fatal(err)
	}
	if string(saved["Theme"]) != `"dark"` {
		t.Fatalf("save dropped an unrelated legacy setting: %s", saved["Theme"])
	}
	if string(saved["AppAuthenticationMode"]) != "2" ||
		string(saved["AppAuthenticationHelloFallback"]) != "1" ||
		string(saved["AppAuthenticationIdleTimeoutMinutes"]) != "30" {
		t.Fatalf("unexpected saved authentication settings: %#v", saved)
	}
}

func TestAuthSettingsRejectOversizedFileWithoutOverwritingIt(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), authSettingsFilename)
	original := bytes.Repeat([]byte("x"), authMaxSettingsBytes+1)
	if err := os.WriteFile(settingsPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadAuthSettings(settingsPath); err == nil {
		t.Fatal("oversized settings file was accepted")
	}
	if err := saveAuthSettings(settingsPath, defaultAuthSettings()); err == nil {
		t.Fatal("unreadable settings file was overwritten")
	}
	contents, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contents, original) {
		t.Fatal("failed settings write changed the original settings file")
	}
}

func TestSettingsUpdateRejectsOversizedOutputWithoutOverwritingIt(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), authSettingsFilename)
	original := []byte(`{"Theme":"dark"}`)
	if err := os.WriteFile(settingsPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	oversized, err := json.Marshal(strings.Repeat("x", authMaxSettingsBytes))
	if err != nil {
		t.Fatal(err)
	}
	if err := updateSettingsDocument(settingsPath, func(document map[string]json.RawMessage) error {
		document["oversized"] = oversized
		return nil
	}); err == nil {
		t.Fatal("oversized settings output was accepted")
	}
	contents, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contents, original) {
		t.Fatal("oversized settings update changed the original settings file")
	}
}

func TestSettingsUpdateIncludesTrailingNewlineInSizeLimit(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), authSettingsFilename)
	original := []byte(`{"Theme":"dark"}`)
	if err := os.WriteFile(settingsPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	emptyPadding, err := json.Marshal("")
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := json.MarshalIndent(map[string]json.RawMessage{"padding": emptyPadding}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	padding, err := json.Marshal(strings.Repeat("x", authMaxSettingsBytes-len(baseline)))
	if err != nil {
		t.Fatal(err)
	}
	boundaryDocument := map[string]json.RawMessage{"padding": padding}
	encoded, err := json.MarshalIndent(boundaryDocument, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != authMaxSettingsBytes {
		t.Fatalf("boundary document size = %d, want %d", len(encoded), authMaxSettingsBytes)
	}

	if err := updateSettingsDocument(settingsPath, func(document map[string]json.RawMessage) error {
		clear(document)
		document["padding"] = padding
		return nil
	}); err == nil {
		t.Fatal("settings output with an oversized trailing newline was accepted")
	}
	contents, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contents, original) {
		t.Fatal("boundary settings update changed the original settings file")
	}
}

func TestAuthStateDefaultsWithoutFiles(t *testing.T) {
	state, err := authState(filepath.Join(t.TempDir(), "wormhole.db"))
	if err != nil {
		t.Fatal(err)
	}
	if state.Mode != "disabled" || state.Fallback != "pin" || state.Configured || state.HasPin || state.HasPassword {
		t.Fatalf("unexpected default authentication state: %#v", state)
	}
	if state.IdleTimeoutMinutes == nil || *state.IdleTimeoutMinutes != 15 {
		t.Fatalf("unexpected default idle timeout: %#v", state.IdleTimeoutMinutes)
	}
}

func TestAuthUpdateSettingsRequiresTheSelectedSecret(t *testing.T) {
	minutes := 15
	_, err := authUpdateSettings(filepath.Join(t.TempDir(), "wormhole.db"), authSettingsRequest{
		Mode:               "pin",
		Fallback:           "pin",
		IdleTimeoutMinutes: &minutes,
	})
	if err == nil || err.Error() != "Set a PIN before enabling this unlock method." {
		t.Fatalf("unexpected missing-secret result: %v", err)
	}
}

func TestConfiguredAuthMethodFollowsTheActiveMode(t *testing.T) {
	for _, test := range []struct {
		name       string
		settings   authSettings
		method     int
		configured bool
	}{
		{name: "disabled", settings: authSettings{Mode: 0}, configured: false},
		{name: "pin", settings: authSettings{Mode: 1}, method: 0, configured: true},
		{name: "password", settings: authSettings{Mode: 2}, method: 1, configured: true},
		{name: "hello pin fallback", settings: authSettings{Mode: 3, Fallback: 0}, method: 0, configured: true},
		{name: "hello password fallback", settings: authSettings{Mode: 3, Fallback: 1}, method: 1, configured: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			method, configured := configuredAuthMethod(test.settings)
			if method != test.method || configured != test.configured {
				t.Fatalf("got method=%d configured=%v, want method=%d configured=%v", method, configured, test.method, test.configured)
			}
		})
	}
}

func TestAuthVerifierRejectsUnboundedPbkdf2Work(t *testing.T) {
	verifier := &authVerifier{
		Salt:       make([]byte, authSaltLength),
		Hash:       make([]byte, authHashLength),
		Iterations: authMaxPbkdf2Iterations + 1,
	}
	if validAuthVerifier(verifier) {
		t.Fatal("verifier with excessive PBKDF2 work was accepted")
	}
}

func TestAuthDocumentRejectsOversizedStore(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), authStoreFilename)
	if err := os.WriteFile(storePath, make([]byte, authMaxStoreBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	_, corrupted, err := readAuthDocument(storePath)
	if err != nil || !corrupted {
		t.Fatalf("oversized store result was unexpected: corrupted=%v err=%v", corrupted, err)
	}
}

func TestAuthDocumentEnvelopeRoundTripRejectsTampering(t *testing.T) {
	key := bytes.Repeat([]byte{0x4a}, authProtectionKeyLength)
	plaintext := []byte(`{"Version":1}`)
	protected, err := encryptAuthDocument(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(protected, plaintext) {
		t.Fatal("authentication document was not encrypted")
	}

	decoded, err := decryptAuthDocument(protected, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Fatalf("unexpected decrypted authentication document: %q", decoded)
	}
	clearBytes(decoded)

	tampered := append([]byte(nil), protected...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := decryptAuthDocument(tampered, key); err == nil {
		t.Fatal("tampered authentication document was accepted")
	}

	wrongKey := bytes.Repeat([]byte{0x7c}, authProtectionKeyLength)
	if _, err := decryptAuthDocument(protected, wrongKey); err == nil {
		t.Fatal("authentication document was accepted with a different key")
	}
}

func TestAuthDocumentRoundTripUsesProtectedStore(t *testing.T) {
	if !isWindowsRuntime() {
		t.Skip("Windows DPAPI is Windows-only")
	}

	storePath := filepath.Join(t.TempDir(), "app-auth.dpapi")
	document := authDocument{
		Version: authStoreVersion,
		Pin: &authVerifier{
			Salt:       []byte("1234567890abcdef"),
			Hash:       []byte("12345678901234567890123456789012"),
			Iterations: 1,
		},
	}
	if err := writeAuthDocument(storePath, document); err != nil {
		t.Fatal(err)
	}
	protected, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(protected) == 0 {
		t.Fatal("protected authentication store is empty")
	}
	decoded, err := unprotectAuthDocument(storePath, protected)
	if err != nil {
		t.Fatal(err)
	}
	clearBytes(decoded)

	loaded, corrupted, err := readAuthDocument(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if corrupted || loaded.Version != document.Version || loaded.Pin == nil || loaded.Pin.Iterations != 1 {
		t.Fatalf("unexpected protected document: corrupted=%v document=%#v", corrupted, loaded)
	}
}

func TestAuthSetAndVerifySecretOnWindows(t *testing.T) {
	if !isWindowsRuntime() {
		t.Skip("Windows DPAPI is Windows-only")
	}

	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	state, err := authSetSecret(databasePath, authSetSecretRequest{Method: "pin", Secret: "1234"})
	if err != nil {
		t.Fatal(err)
	}
	if !state.HasPin || state.HasPassword || state.Mode != "disabled" {
		t.Fatalf("unexpected state after setting PIN: %#v", state)
	}

	minutes := 15
	state, err = authUpdateSettings(databasePath, authSettingsRequest{
		Mode:               "pin",
		Fallback:           "pin",
		IdleTimeoutMinutes: &minutes,
	})
	if err != nil || !state.Configured {
		t.Fatalf("could not enable PIN authentication: %#v, %v", state, err)
	}
	verified, err := authVerify(databasePath, authVerifyRequest{Method: "pin", Secret: "1234"})
	if err != nil || !verified.Succeeded {
		t.Fatalf("valid PIN was not accepted: %#v, %v", verified, err)
	}
	invalid, err := authVerify(databasePath, authVerifyRequest{Method: "pin", Secret: "9999"})
	if err != nil || invalid.Succeeded || invalid.Message != "Invalid PIN." {
		t.Fatalf("invalid PIN result was unexpected: %#v, %v", invalid, err)
	}
	overlong, err := authVerify(databasePath, authVerifyRequest{
		Method: "pin",
		Secret: strings.Repeat("1", authPinMaxLength+1),
	})
	if err != nil || overlong.Succeeded || overlong.Message != "Invalid PIN." {
		t.Fatalf("overlong PIN result was unexpected: %#v, %v", overlong, err)
	}
	if _, err := authSetSecret(databasePath, authSetSecretRequest{Method: "password", Secret: "password123"}); err != nil {
		t.Fatal(err)
	}
	wrongMethod, err := authVerify(databasePath, authVerifyRequest{Method: "password", Secret: "password123"})
	if err != nil || wrongMethod.Succeeded || wrongMethod.Message != "Invalid PIN." {
		t.Fatalf("alternate verifier bypassed the configured PIN mode: %#v, %v", wrongMethod, err)
	}
	state, err = authUpdateSettings(databasePath, authSettingsRequest{
		Mode:               "disabled",
		Fallback:           "pin",
		IdleTimeoutMinutes: &minutes,
	})
	if err != nil || state.Configured || state.HasPin {
		t.Fatalf("could not disable and clear PIN authentication: %#v, %v", state, err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(databasePath), authStoreFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("authentication store was not removed: %v", err)
	}
}
