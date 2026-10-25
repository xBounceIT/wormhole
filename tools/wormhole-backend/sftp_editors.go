package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	posixpath "path"
	"path/filepath"
	"runtime"
	"strings"
)

type sftpEditor struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Executable string   `json:"executable"`
	Arguments  []string `json:"arguments"`
	Patterns   string   `json:"patterns"`
}

type sftpEditorSettings struct {
	Editors       []sftpEditor `json:"editors"`
	DefaultEditor string       `json:"defaultEditor"`
	MaxFileSize   int64        `json:"maxFileSize"`
	SwapPanels    bool         `json:"swapPanels"`
}

func defaultSftpEditorSettings() sftpEditorSettings {
	return sftpEditorSettings{Editors: []sftpEditor{}, DefaultEditor: "auto", MaxFileSize: 50 * 1024 * 1024}
}

func validateSftpEditorSettings(settings sftpEditorSettings) error {
	if len(settings.Editors) > 32 || settings.MaxFileSize < 1 || settings.MaxFileSize > 1024*1024*1024 {
		return errors.New("invalid editor count or maximum file size")
	}
	ids := map[string]bool{"auto": true, "system": true}
	for _, editor := range settings.Editors {
		if editor.ID == "" || len(editor.ID) > 128 || ids[editor.ID] || strings.ContainsAny(editor.ID, "\x00\r\n") || strings.TrimSpace(editor.Name) == "" || len(editor.Name) > 256 || strings.ContainsAny(editor.Name, "\x00\r\n") ||
			editor.Executable == "" || len(editor.Executable) > 4096 || strings.ContainsAny(editor.Executable, "\x00\r\n") || len(editor.Patterns) > 4096 || len(editor.Arguments) > 64 {
			return errors.New("invalid editor configuration")
		}
		// Relative paths with separators are ambiguous; bare command names use PATH.
		if !filepath.IsAbs(editor.Executable) && strings.ContainsAny(editor.Executable, `/\`) {
			return errors.New("editor executable must be an absolute path or a command on PATH")
		}
		placeholders := 0
		for _, arg := range editor.Arguments {
			if len(arg) > 4096 || strings.ContainsRune(arg, 0) || (strings.Contains(arg, "{file}") && arg != "{file}") {
				return errors.New("use {file} as one complete argument")
			}
			if arg == "{file}" {
				placeholders++
			}
		}
		if placeholders > 1 {
			return errors.New("editor arguments contain multiple file placeholders")
		}
		for _, pattern := range strings.Split(editor.Patterns, ";") {
			if pattern != "" {
				if _, err := filepath.Match(pattern, "file"); err != nil {
					return errors.New("invalid editor file pattern")
				}
			}
		}
		ids[editor.ID] = true
	}
	if !ids[settings.DefaultEditor] {
		return errors.New("the default editor does not exist")
	}
	return nil
}

func readSftpEditorSettings(databasePath string) (sftpEditorSettings, error) {
	settings := defaultSftpEditorSettings()
	_, settingsPath := authPaths(databasePath)
	contents, err := readAuthSettingsFile(settingsPath)
	if errors.Is(err, os.ErrNotExist) {
		return settings, nil
	}
	if err != nil {
		return settings, err
	}
	var document map[string]json.RawMessage
	if json.Unmarshal(contents, &document) != nil {
		return settings, nil
	}
	if value, ok := document["fileTransfer"]; ok {
		if json.Unmarshal(value, &settings) != nil || validateSftpEditorSettings(settings) != nil {
			return defaultSftpEditorSettings(), nil
		}
	}
	return settings, nil
}

func writeSftpEditorSettings(databasePath string, settings sftpEditorSettings) error {
	if err := validateSftpEditorSettings(settings); err != nil {
		return err
	}
	return writeSettingsValues(databasePath, map[string]any{"fileTransfer": settings})
}

func automaticSftpEditor(goos string, lookPath func(string) (string, error), exists func(string) bool, programFiles string) sftpEditor {
	if goos == "windows" {
		candidate := filepath.Join(programFiles, "Notepad++", "notepad++.exe")
		if programFiles != "" && exists(candidate) {
			return sftpEditor{ID: "auto", Name: "Notepad++", Executable: candidate}
		}
		return sftpEditor{ID: "auto", Name: "Notepad", Executable: "notepad.exe"}
	}
	if goos == "darwin" {
		return sftpEditor{ID: "auto", Name: "Default text editor", Executable: "/usr/bin/open", Arguments: []string{"-t", "{file}"}}
	}
	for _, name := range []string{"gnome-text-editor", "gedit", "kate", "mousepad", "code"} {
		if path, err := lookPath(name); err == nil {
			return sftpEditor{ID: "auto", Name: name, Executable: path}
		}
	}
	return sftpEditor{ID: "system", Name: "System default application"}
}

func resolveSftpEditor(settings sftpEditorSettings, id, filename string) (sftpEditor, error) {
	if id == "" {
		id = settings.DefaultEditor
		for _, editor := range settings.Editors {
			matched := false
			for _, pattern := range strings.Split(editor.Patterns, ";") {
				if pattern != "" {
					matched, _ = filepath.Match(strings.TrimSpace(pattern), filename)
					if matched {
						break
					}
				}
			}
			if matched {
				id = editor.ID
				break
			}
		}
	}
	if id == "system" {
		return sftpEditor{ID: id, Name: "System default application"}, nil
	}
	if id == "auto" {
		return automaticSftpEditor(runtime.GOOS, func(name string) (string, error) {
			return sftpEditorExecutable(runtime.GOOS, name, sftpEditorEnvironment(runtime.GOOS, os.Environ()), exec.LookPath)
		}, func(path string) bool { info, err := os.Stat(path); return err == nil && !info.IsDir() }, os.Getenv("ProgramFiles")), nil
	}
	for _, editor := range settings.Editors {
		if editor.ID == id {
			return editor, nil
		}
	}
	return sftpEditor{}, errors.New("configured editor was not found")
}

func sftpEditorArgv(goos string, editor sftpEditor, path string) (string, []string, error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) {
		return "", nil, errors.New("editor file path must be absolute")
	}
	if editor.ID == "system" {
		executable, args := externalOpenCommand(goos, path)
		return executable, args, nil
	}
	args := append([]string{}, editor.Arguments...)
	found := false
	for index, arg := range args {
		if arg == "{file}" {
			args[index] = path
			found = true
		} else if strings.Contains(arg, "{file}") {
			return "", nil, errors.New("use {file} as one complete argument")
		}
	}
	if goos == "darwin" && strings.HasSuffix(strings.ToLower(editor.Executable), ".app") {
		openArgs := []string{"-a", editor.Executable, path}
		if len(args) > 0 {
			openArgs = append(append(openArgs, "--args"), args...)
		}
		return "/usr/bin/open", openArgs, nil
	}
	if !found {
		args = append(args, path)
	}
	return editor.Executable, args, nil
}

func sftpEditorEnvironment(goos string, environment []string) []string {
	// As with RDP helpers, an editor must not inherit Bitwarden credentials from
	// the shell that launched Wormhole. Keep the shared case-insensitive filter.
	environment = bitwardenCliMergeEnv(environment, nil)
	if goos != "linux" {
		return append([]string{}, environment...)
	}
	appImage := false
	for _, entry := range environment {
		if strings.HasPrefix(entry, "APPDIR=") || strings.HasPrefix(entry, "APPIMAGE=") {
			appImage = true
		}
	}
	result := make([]string, 0, len(environment))
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		if key == "APPDIR" || key == "APPIMAGE" {
			continue
		}
		if appImage && (key == "LD_LIBRARY_PATH" || key == "LD_PRELOAD" || key == "PATH") {
			continue
		}
		result = append(result, entry)
	}
	if appImage {
		result = append(result, "PATH=/usr/local/bin:/usr/bin:/bin")
	}
	return result
}

// exec.Command resolves bare executables before consulting Cmd.Env. Resolve against
// the sanitized PATH ourselves so AppImage wrappers cannot select bundled binaries.
func sftpEditorExecutable(goos, executable string, environment []string, lookPath func(string) (string, error)) (string, error) {
	if goos != "linux" || strings.Contains(executable, "/") {
		return executable, nil
	}
	for _, entry := range environment {
		if !strings.HasPrefix(entry, "PATH=") {
			continue
		}
		for _, directory := range strings.Split(strings.TrimPrefix(entry, "PATH="), ":") {
			if !strings.HasPrefix(directory, "/") {
				continue
			}
			if found, err := lookPath(posixpath.Join(directory, executable)); err == nil {
				return found, nil
			}
		}
	}
	return "", fmt.Errorf("editor %s was not found on the desktop PATH", executable)
}

var launchSftpEditor = func(editor sftpEditor, path string) error {
	executable, args, err := sftpEditorArgv(runtime.GOOS, editor, path)
	if err != nil {
		return err
	}
	environment := sftpEditorEnvironment(runtime.GOOS, os.Environ())
	executable, err = sftpEditorExecutable(runtime.GOOS, executable, environment, exec.LookPath)
	if err != nil {
		return err
	}
	command := exec.Command(executable, args...)
	command.Env = environment
	if err := command.Start(); err != nil {
		return fmt.Errorf("could not start editor: %w", err)
	}
	go func() { _ = command.Wait() }()
	return nil
}
