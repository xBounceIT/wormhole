package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	bitwardenCliPasswordEnvVar = "WORMHOLE_BW_PASSWORD"
	bitwardenCliSessionEnvVar  = "BW_SESSION"
	bitwardenCliUSServerURL    = "https://vault.bitwarden.com"
	bitwardenCliEUServerURL    = "https://vault.bitwarden.eu"
	bitwardenCliProcessTimeout = 120 * time.Second
	bitwardenCliMaxOutput      = 16 * 1024 * 1024
	bitwardenCliMaxSessionKey  = 16 * 1024
	bitwardenCliMaxRevision    = 256
)

var (
	bitwardenCliSessionArgRegex  = regexp.MustCompile(`(?i)(--session(\s+|=))\S+`)
	bitwardenCliSessionEnvRegex  = regexp.MustCompile(`(?i)(BW_SESSION(\s*=\s*))\S+`)
	bitwardenCliPasswordEnvRegex = regexp.MustCompile(`(?i)(WORMHOLE_BW_PASSWORD(\s*=\s*))\S+`)
	bitwardenCliCodeArgRegex     = regexp.MustCompile(`(?i)(--code(\s+|=))\S+`)
)

type bitwardenCliLoginItem struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
	RevisionDate string `json:"revisionDate,omitempty"`
}

type bitwardenCliProcessResult struct {
	ExitCode    int
	StandardOut string
	StandardErr string
}

// bitwardenCliOutputBuffer collects command output up to a byte cap. The Bitwarden CLI JSON output
// is small in practice, but the process is spawned with our own stdin/stdout pipes, so a runaway
// writer must not be able to grow memory without bound. Once the cap is reached the buffer stops
// appending; the caller rejects the command after the process exits.
type bitwardenCliOutputBuffer struct {
	builder    strings.Builder
	maxBytes   int64
	overflowed bool
}

func (buffer *bitwardenCliOutputBuffer) Write(contents []byte) (int, error) {
	remaining := buffer.maxBytes - int64(buffer.builder.Len())
	if remaining <= 0 {
		buffer.overflowed = true
		return len(contents), nil
	}
	if int64(len(contents)) > remaining {
		buffer.builder.Write(contents[:remaining])
		buffer.overflowed = true
		return len(contents), nil
	}
	buffer.builder.Write(contents)
	return len(contents), nil
}

func (buffer *bitwardenCliOutputBuffer) String() string {
	return buffer.builder.String()
}

type bitwardenCliVaultError struct {
	Message string
	IsAuth  bool
}

func (e *bitwardenCliVaultError) Error() string {
	if e.Message == "" {
		return "Bitwarden CLI command failed."
	}
	return e.Message
}

func bitwardenCliStatusLongName(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "unauthenticated":
		return "Unauthenticated"
	case "locked":
		return "Locked"
	case "unlocked":
		return "Unlocked"
	default:
		return "Unknown"
	}
}

func bitwardenCliStatusState(databasePath string, settings bitwardenCliSettings) (map[string]any, error) {
	result, err := bitwardenCliRun(databasePath, settings, []string{"status"}, nil)
	if err != nil {
		return nil, err
	}
	var document struct {
		Status    string `json:"status"`
		UserEmail string `json:"userEmail"`
		ServerURL string `json:"serverUrl"`
		LastSync  string `json:"lastSync"`
	}
	if err := json.Unmarshal([]byte(result.StandardOut), &document); err != nil {
		return nil, &bitwardenCliVaultError{Message: "Bitwarden status output was not valid JSON."}
	}
	state := map[string]any{
		"status":    bitwardenCliStatusLongName(document.Status),
		"userEmail": nullableBitwardenString(document.UserEmail),
		"serverUrl": nullableBitwardenString(document.ServerURL),
	}
	if strings.TrimSpace(document.LastSync) != "" {
		state["lastSync"] = strings.TrimSpace(document.LastSync)
	}
	return state, nil
}

func bitwardenCliUnlock(databasePath string, settings bitwardenCliSettings, masterPassword string) (string, error) {
	if masterPassword == "" {
		return "", errors.New("Enter the Bitwarden master password to unlock.")
	}
	result, err := bitwardenCliRun(
		databasePath,
		settings,
		[]string{"unlock", "--passwordenv", bitwardenCliPasswordEnvVar, "--raw"},
		map[string]string{bitwardenCliPasswordEnvVar: masterPassword},
	)
	if err != nil {
		return "", err
	}
	return bitwardenCliReadSessionKey(result.StandardOut)
}

func bitwardenCliLogin(
	databasePath string,
	settings bitwardenCliSettings,
	email, masterPassword, authenticatorCode string,
) (string, error) {
	if strings.TrimSpace(email) == "" {
		return "", errors.New("Enter the Bitwarden account email to log in.")
	}
	if masterPassword == "" {
		return "", errors.New("Enter the Bitwarden master password to log in.")
	}
	if settings.ServerRegion != bitwardenCliServerCurrent {
		if err := bitwardenCliLogoutBeforeConfig(databasePath, settings); err != nil {
			return "", err
		}
		if err := bitwardenCliConfigureServer(databasePath, settings); err != nil {
			return "", err
		}
	}

	args := []string{
		"login",
		strings.TrimSpace(email),
		"--passwordenv",
		bitwardenCliPasswordEnvVar,
		"--raw",
		"--nointeraction",
	}
	if strings.TrimSpace(authenticatorCode) != "" {
		code := strings.ReplaceAll(strings.TrimSpace(authenticatorCode), " ", "")
		args = append(args, "--method", "0", "--code", code)
	}
	result, err := bitwardenCliRun(
		databasePath,
		settings,
		args,
		map[string]string{bitwardenCliPasswordEnvVar: masterPassword},
	)
	if err != nil {
		return "", err
	}
	return bitwardenCliReadSessionKey(result.StandardOut)
}

func bitwardenCliLogout(databasePath string, settings bitwardenCliSettings) error {
	// The Bitwarden CLI prints "You are not logged in" to stdout on some versions; treat a success
	// exit or an already-logged-out message on either channel as a completed logout, matching the
	// WinUI 3 LogoutBeforeServerConfigAsync semantics.
	result, err := bitwardenCliTryRun(databasePath, settings, []string{"logout"}, nil)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 && !bitwardenCliIsAlreadyLoggedOut(result.StandardErr) && !bitwardenCliIsAlreadyLoggedOut(result.StandardOut) {
		return bitwardenCliThrowProcessFailure(result)
	}
	return nil
}

func bitwardenCliLogoutBeforeConfig(databasePath string, settings bitwardenCliSettings) error {
	result, err := bitwardenCliTryRun(databasePath, settings, []string{"logout"}, nil)
	if err != nil {
		return err
	}
	if result.ExitCode == 0 || bitwardenCliIsAlreadyLoggedOut(result.StandardErr) || bitwardenCliIsAlreadyLoggedOut(result.StandardOut) {
		return nil
	}
	return bitwardenCliThrowProcessFailure(result)
}

func bitwardenCliConfigureServer(databasePath string, settings bitwardenCliSettings) error {
	serverURL := bitwardenCliUSServerURL
	if settings.ServerRegion == bitwardenCliServerEurope {
		serverURL = bitwardenCliEUServerURL
	}
	_, err := bitwardenCliRun(databasePath, settings, []string{"config", "server", serverURL}, nil)
	return err
}

func bitwardenCliListItems(databasePath string, settings bitwardenCliSettings, sessionKey, query string) ([]bitwardenCliLoginItem, error) {
	args := []string{"list", "items"}
	if strings.TrimSpace(query) != "" {
		args = append(args, "--search", strings.TrimSpace(query))
	}
	result, err := bitwardenCliRun(databasePath, settings, args, bitwardenCliSessionEnv(sessionKey))
	if err != nil {
		return nil, err
	}
	var rawItems []json.RawMessage
	if err := json.Unmarshal([]byte(result.StandardOut), &rawItems); err != nil {
		return nil, &bitwardenCliVaultError{Message: "Bitwarden item list output was not valid JSON."}
	}
	items := make([]bitwardenCliLoginItem, 0, len(rawItems))
	for _, raw := range rawItems {
		var item map[string]any
		if err := json.Unmarshal(raw, &item); err != nil {
			continue
		}
		if !bitwardenCliIsLoginItem(item) {
			continue
		}
		if mapped, mapErr := bitwardenCliMapLoginItem(item, false); mapErr == nil && mapped != nil {
			items = append(items, *mapped)
		}
	}
	return items, nil
}

func bitwardenCliSearchItems(databasePath string, settings bitwardenCliSettings, sessionKey, query string) ([]bitwardenCliLoginItem, error) {
	if err := bitwardenCliSync(databasePath, settings, sessionKey); err != nil {
		return nil, err
	}
	return bitwardenCliListItems(databasePath, settings, sessionKey, query)
}

func bitwardenCliGetItem(databasePath string, settings bitwardenCliSettings, sessionKey, itemID string) (*bitwardenCliLoginItem, error) {
	if strings.TrimSpace(itemID) == "" {
		return nil, errors.New("Enter a Bitwarden item identifier.")
	}
	result, err := bitwardenCliTryRun(databasePath, settings, []string{"get", "item", itemID}, bitwardenCliSessionEnv(sessionKey))
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		if bitwardenCliIsNotFound(result.StandardErr) {
			return nil, nil
		}
		return nil, bitwardenCliThrowProcessFailure(result, sessionKey)
	}
	var item map[string]any
	if err := json.Unmarshal([]byte(result.StandardOut), &item); err != nil {
		return nil, &bitwardenCliVaultError{Message: "Bitwarden item output was not valid JSON."}
	}
	if !bitwardenCliIsLoginItem(item) {
		return nil, nil
	}
	mapped, err := bitwardenCliMapLoginItem(item, true)
	if err != nil {
		return nil, err
	}
	return mapped, nil
}

func bitwardenCliSync(databasePath string, settings bitwardenCliSettings, sessionKey string) error {
	_, err := bitwardenCliRun(databasePath, settings, []string{"sync"}, bitwardenCliSessionEnv(sessionKey))
	return err
}

func bitwardenCliSessionEnv(sessionKey string) map[string]string {
	if strings.TrimSpace(sessionKey) == "" {
		return nil
	}
	return map[string]string{bitwardenCliSessionEnvVar: strings.TrimSpace(sessionKey)}
}

func bitwardenCliRun(
	databasePath string,
	settings bitwardenCliSettings,
	args []string,
	environment map[string]string,
) (bitwardenCliProcessResult, error) {
	result, err := bitwardenCliTryRun(databasePath, settings, args, environment)
	if err != nil {
		return bitwardenCliProcessResult{}, err
	}
	if result.ExitCode != 0 {
		return bitwardenCliProcessResult{}, bitwardenCliThrowProcessFailure(
			result,
			bitwardenCliSensitiveValues(args, environment)...,
		)
	}
	return result, nil
}

func bitwardenCliTryRun(
	databasePath string,
	settings bitwardenCliSettings,
	args []string,
	environment map[string]string,
) (bitwardenCliProcessResult, error) {
	executable := resolveBitwardenCliExecutable(settings)
	if executable == "" {
		return bitwardenCliProcessResult{}, errors.New("The Bitwarden CLI is not installed. Install it first.")
	}
	ctx, cancel := context.WithTimeout(context.Background(), bitwardenCliProcessTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, executable, args...)
	command.Env = bitwardenCliMergeEnv(os.Environ(), environment)
	var stdout, stderr bitwardenCliOutputBuffer
	stdout.maxBytes = bitwardenCliMaxOutput
	stderr.maxBytes = bitwardenCliMaxOutput
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	exitCode := 0
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return bitwardenCliProcessResult{}, errors.New("The Bitwarden CLI command timed out.")
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return bitwardenCliProcessResult{}, errors.New("Could not start the Bitwarden CLI.")
		}
	}
	if stdout.overflowed || stderr.overflowed {
		return bitwardenCliProcessResult{}, errors.New("Bitwarden CLI output exceeded the safety limit.")
	}
	return bitwardenCliProcessResult{
		ExitCode:    exitCode,
		StandardOut: stdout.String(),
		StandardErr: stderr.String(),
	}, nil
}

// bitwardenCliMergeEnv returns the process environment with the override entries applied, replacing
// any existing entries with the same key. Appending overrides to os.Environ() would leave duplicate
// keys, which the Windows process loader resolves to the first occurrence — so the override could be
// silently ignored if the parent already exported BW_SESSION or WORMHOLE_BW_PASSWORD.
func bitwardenCliMergeEnv(base []string, overrides map[string]string) []string {
	merged := make([]string, 0, len(base)+len(overrides))
	replaced := make(map[string]bool, len(overrides))
	for key := range overrides {
		replaced[key] = false
	}
	for _, entry := range base {
		index := strings.IndexByte(entry, '=')
		if index < 0 {
			merged = append(merged, entry)
			continue
		}
		key := entry[:index]
		if strings.EqualFold(key, bitwardenCliSessionEnvVar) ||
			strings.EqualFold(key, bitwardenCliPasswordEnvVar) {
			continue
		}
		matchedOverride := ""
		for overrideKey := range replaced {
			if strings.EqualFold(key, overrideKey) {
				matchedOverride = overrideKey
				break
			}
		}
		if matchedOverride != "" {
			replaced[matchedOverride] = true
			continue
		}
		merged = append(merged, entry)
	}
	for key, value := range overrides {
		merged = append(merged, key+"="+value)
	}
	return merged
}

func bitwardenCliReadSessionKey(standardOutput string) (string, error) {
	sessionKey := strings.TrimSpace(standardOutput)
	if sessionKey == "" {
		return "", &bitwardenCliVaultError{
			Message: "Bitwarden CLI did not return a session key.",
			IsAuth:  true,
		}
	}
	if len(sessionKey) > bitwardenCliMaxSessionKey {
		return "", &bitwardenCliVaultError{
			Message: "Bitwarden CLI returned an invalid session key.",
			IsAuth:  true,
		}
	}
	return sessionKey, nil
}

func bitwardenCliThrowProcessFailure(result bitwardenCliProcessResult, sensitiveValues ...string) error {
	sanitized := bitwardenCliSanitizeError(result.StandardErr, sensitiveValues...)
	authError := bitwardenCliIsAuthenticationError(result.StandardErr) || bitwardenCliIsAuthenticationError(result.StandardOut)
	message := sanitized
	if strings.TrimSpace(message) == "" {
		if authError {
			message = "Bitwarden vault is locked or the session is invalid."
		} else {
			message = "Bitwarden CLI command failed."
		}
	}
	return &bitwardenCliVaultError{Message: message, IsAuth: authError}
}

func bitwardenCliSanitizeError(value string, sensitiveValues ...string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	redacted := strings.TrimSpace(value)
	// A misbehaving or user-selected bw executable can echo an environment value without its key.
	// Redact actual secrets as well as recognizable CLI/env syntax before errors reach IPC or logs.
	// Longest-first replacement avoids leaving a suffix when one secret contains another.
	values := append([]string(nil), sensitiveValues...)
	sort.SliceStable(values, func(left, right int) bool { return len(values[left]) > len(values[right]) })
	seen := make(map[string]struct{}, len(values))
	for _, secret := range values {
		if secret == "" {
			continue
		}
		if _, exists := seen[secret]; exists {
			continue
		}
		seen[secret] = struct{}{}
		redacted = strings.ReplaceAll(redacted, secret, "[redacted]")
	}
	redacted = bitwardenCliSessionArgRegex.ReplaceAllString(redacted, "${1}[redacted]")
	redacted = bitwardenCliSessionEnvRegex.ReplaceAllString(redacted, "${1}[redacted]")
	redacted = bitwardenCliCodeArgRegex.ReplaceAllString(redacted, "${1}[redacted]")
	redacted = bitwardenCliPasswordEnvRegex.ReplaceAllString(redacted, "${1}[redacted]")
	runes := []rune(redacted)
	if len(runes) <= 500 {
		return redacted
	}
	return string(runes[:500])
}

func bitwardenCliSensitiveValues(args []string, environment map[string]string) []string {
	values := make([]string, 0, len(environment)+2)
	for key, value := range environment {
		if strings.EqualFold(key, bitwardenCliSessionEnvVar) ||
			strings.EqualFold(key, bitwardenCliPasswordEnvVar) {
			values = append(values, value)
		}
	}
	for index, argument := range args {
		lower := strings.ToLower(argument)
		if (lower == "--code" || lower == "--session") && index+1 < len(args) {
			values = append(values, args[index+1])
			continue
		}
		if strings.HasPrefix(lower, "--code=") || strings.HasPrefix(lower, "--session=") {
			if separator := strings.IndexByte(argument, '='); separator >= 0 {
				values = append(values, argument[separator+1:])
			}
		}
	}
	return values
}

func bitwardenCliIsAuthenticationError(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "locked") ||
		strings.Contains(lower, "unauth") ||
		strings.Contains(lower, "log in") ||
		strings.Contains(lower, "login") ||
		strings.Contains(lower, "session") ||
		strings.Contains(lower, "two-step") ||
		strings.Contains(lower, "two factor") ||
		strings.Contains(lower, "two-factor")
}

func bitwardenCliIsAlreadyLoggedOut(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "not logged") || strings.Contains(lower, "not authenticated")
}

func bitwardenCliIsNotFound(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "not found") || strings.Contains(lower, "not exist")
}

func bitwardenCliIsLoginItem(item map[string]any) bool {
	login, ok := item["login"].(map[string]any)
	if !ok {
		return false
	}
	if login == nil {
		return false
	}
	if typeValue, exists := item["type"]; exists {
		if number, ok := typeValue.(float64); ok && number != 1 {
			return false
		}
	}
	return true
}

func bitwardenCliMapLoginItem(item map[string]any, includePassword bool) (*bitwardenCliLoginItem, error) {
	id, _ := item["id"].(string)
	id = strings.TrimSpace(id)
	if id == "" || !validCredentialText(id, maxBitwardenItemIDLength) {
		return nil, errors.New("Bitwarden item contains an invalid identifier.")
	}
	name, _ := item["name"].(string)
	name = strings.TrimSpace(name)
	if name == "" {
		name = id
	}
	if !validCredentialText(name, maxBitwardenItemNameLength) {
		return nil, errors.New("Bitwarden item contains an invalid name.")
	}
	login, _ := item["login"].(map[string]any)
	var username, password, revisionDate string
	if login != nil {
		username, _ = login["username"].(string)
		username = strings.TrimSpace(username)
		if !validCredentialText(username, maxCredentialUsernameLength) {
			return nil, errors.New("Bitwarden item contains an invalid username.")
		}
		if includePassword {
			password, _ = login["password"].(string)
			// Passwords are opaque secret data, not display text. Preserve control characters and
			// whitespace exactly; only bound their size before returning them to a protocol runtime.
			if len([]rune(password)) > maxStoredCredentialPassword {
				return nil, errors.New("Bitwarden item contains an invalid password.")
			}
		}
	}
	if value, ok := item["revisionDate"].(string); ok {
		revisionDate = strings.TrimSpace(value)
		if !validCredentialText(revisionDate, bitwardenCliMaxRevision) {
			return nil, errors.New("Bitwarden item contains an invalid revision date.")
		}
	}
	return &bitwardenCliLoginItem{
		ID:           id,
		Name:         name,
		Username:     username,
		Password:     password,
		RevisionDate: revisionDate,
	}, nil
}
