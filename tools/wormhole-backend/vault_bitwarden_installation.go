package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type vaultBitwardenPackage struct {
	InstallationID string
	ExtensionID    string
	Version        string
	Popup          string
	Background     string
}

type vaultBitwardenInstallerOwner interface {
	ReadBitwardenInstallation(context.Context, uint64) (localvault.BitwardenInstallation, uint64, error)
	SaveBitwardenInstallation(context.Context, localvault.BitwardenInstallation, uint64) (uint64, error)
}

// Activation accepts only a prepared UUID directory beneath the native install
// root. The caller must authorize the install action and prepare the package.
// The encrypted CAS is the commit point; legacy settings are never consulted.
func activateVaultBitwardenInstallation(ctx context.Context, owner vaultBitwardenInstallerOwner, base *os.Root, id string, expected uint64, expectedDigest string) (uint64, error) {
	if owner == nil || base == nil || !vaultCredentialID(id) || len(expectedDigest) != 64 {
		return 0, errVaultExtensionFiles
	}
	current, revision, err := owner.ReadBitwardenInstallation(ctx, expected)
	if err != nil {
		return 0, err
	}
	if revision != expected || current.InstallationID == id {
		return 0, errVaultExtensionFiles
	}
	root, err := openVaultBitwardenPackage(base, id)
	if err != nil {
		return 0, err
	}
	pkg, packageErr := readVaultBitwardenPackage(root)
	digest, hashErr := hashVaultExtensionFiles(ctx, root.FS())
	closeErr := root.Close()
	if packageErr != nil || hashErr != nil || closeErr != nil || digest != expectedDigest {
		return 0, errVaultExtensionFiles
	}
	return owner.SaveBitwardenInstallation(ctx, localvault.BitwardenInstallation{
		Enabled: true, InstallationID: id, ExtensionID: pkg.ExtensionID, ContentSHA256: digest,
	}, expected)
}

func openVaultBitwardenPackage(base *os.Root, id string) (*os.Root, error) {
	if base == nil || !vaultCredentialID(id) {
		return nil, errVaultExtensionFiles
	}
	info, err := base.Lstat(id)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errVaultExtensionFiles
	}
	root, err := base.OpenRoot(id)
	if err != nil {
		return nil, errVaultExtensionFiles
	}
	return root, nil
}

// Load admission reauthenticates the record and verifies the package, including
// the extension origin. The caller still owns profile/route and lock lifetimes.
func planVaultBitwardenInstallation(ctx context.Context, owner *localvault.Owner, base *os.Root, minimum uint64) (vaultBitwardenPackage, uint64, error) {
	var result vaultBitwardenPackage
	if owner == nil {
		return result, 0, errVaultExtensionFiles
	}
	value, revision, err := owner.ReadBitwardenInstallation(ctx, minimum)
	if err != nil {
		return result, 0, err
	}
	if !value.Enabled {
		return result, revision, nil
	}
	if err = verifyVaultBitwardenInstallation(ctx, base, value); err != nil {
		return result, 0, err
	}
	root, err := openVaultBitwardenPackage(base, value.InstallationID)
	if err != nil {
		return result, 0, err
	}
	pkg, readErr := readVaultBitwardenPackage(root)
	closeErr := root.Close()
	if readErr != nil || closeErr != nil || pkg.ExtensionID != value.ExtensionID {
		return result, 0, errVaultExtensionFiles
	}
	pkg.InstallationID = value.InstallationID
	return pkg, revision, nil
}

func readVaultBitwardenPackage(root *os.Root) (vaultBitwardenPackage, error) {
	var result vaultBitwardenPackage
	file, err := root.Open("manifest.json")
	if err != nil {
		return result, errVaultExtensionFiles
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, bitwardenMaxManifestBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(raw) > bitwardenMaxManifestBytes || !utf8.Valid(raw) {
		return result, errVaultExtensionFiles
	}
	fields, err := vaultExtensionManifestObject(raw)
	if err != nil {
		return result, err
	}
	var manifest struct {
		ManifestVersion int    `json:"manifest_version"`
		Version         string `json:"version"`
		Key             string `json:"key"`
		BrowserAction   struct {
			DefaultPopup string `json:"default_popup"`
		} `json:"browser_action"`
		Background struct {
			Page       string   `json:"page"`
			Scripts    []string `json:"scripts"`
			Persistent *bool    `json:"persistent"`
		} `json:"background"`
	}
	var name string
	if json.Unmarshal(fields["name"], &name) != nil || strings.TrimSpace(name) == "" {
		return result, errVaultExtensionFiles
	}
	if json.Unmarshal(fields["manifest_version"], &manifest.ManifestVersion) != nil || json.Unmarshal(fields["version"], &manifest.Version) != nil {
		return result, errVaultExtensionFiles
	}
	if key, exists := fields["key"]; exists {
		if string(key) == "null" || json.Unmarshal(key, &manifest.Key) != nil || manifest.Key == "" {
			return result, errVaultExtensionFiles
		}
	}
	action, err := vaultExtensionManifestObject(fields["browser_action"])
	if err != nil {
		return result, err
	}
	if json.Unmarshal(action["default_popup"], &manifest.BrowserAction.DefaultPopup) != nil {
		return result, errVaultExtensionFiles
	}
	backgroundFields, err := vaultExtensionManifestObject(fields["background"])
	if err != nil {
		return result, err
	}
	for name, target := range map[string]any{"page": &manifest.Background.Page, "scripts": &manifest.Background.Scripts, "persistent": &manifest.Background.Persistent} {
		if value, exists := backgroundFields[name]; exists {
			if string(value) == "null" || json.Unmarshal(value, target) != nil {
				return result, errVaultExtensionFiles
			}
		}
	}
	if manifest.ManifestVersion != 2 || !validVaultExtensionVersion(manifest.Version) || manifest.Background.Persistent != nil && !*manifest.Background.Persistent {
		return result, errVaultExtensionFiles
	}
	validFile := func(path string) bool {
		if strings.IndexFunc(path, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 || len(path) > 1024 || !fs.ValidPath(path) || path == "." || strings.ContainsAny(path, "\\:%?#") {
			return false
		}
		info, err := root.Lstat(path)
		return err == nil && info.Mode().IsRegular()
	}
	if !validFile(manifest.BrowserAction.DefaultPopup) {
		return result, errVaultExtensionFiles
	}
	background := manifest.Background.Page
	if background != "" {
		if len(manifest.Background.Scripts) != 0 || !validFile(background) {
			return result, errVaultExtensionFiles
		}
	} else {
		if len(manifest.Background.Scripts) == 0 || len(manifest.Background.Scripts) > 128 {
			return result, errVaultExtensionFiles
		}
		for _, script := range manifest.Background.Scripts {
			if !validFile(script) {
				return result, errVaultExtensionFiles
			}
		}
		background = "_generated_background_page.html"
	}
	identity, err := vaultExtensionOriginID(manifest.Key, root.Name())
	if err != nil {
		return result, err
	}
	return vaultBitwardenPackage{ExtensionID: identity, Version: manifest.Version, Popup: manifest.BrowserAction.DefaultPopup, Background: background}, nil
}

// Chromium components/crx_file/id_util.cc: first16 SHA256 bytes, nibbles a-p.
// Unpacked packages without a manifest key hash the normalized native path.
func vaultExtensionOriginID(key, path string) (string, error) {
	var input []byte
	if key != "" {
		if len(key) > 4096 {
			return "", errVaultExtensionFiles
		}
		var err error
		input, err = base64.StdEncoding.Strict().DecodeString(key)
		if err != nil || len(input) == 0 || base64.StdEncoding.EncodeToString(input) != key {
			return "", errVaultExtensionFiles
		}
	} else {
		if !filepath.IsAbs(path) || !utf8.ValidString(path) {
			return "", errVaultExtensionFiles
		}
		path = filepath.Clean(path)
		if runtime.GOOS == "windows" {
			if len(path) > 1 && path[1] == ':' {
				path = strings.ToUpper(path[:1]) + path[1:]
			}
			units := utf16.Encode([]rune(path))
			input = make([]byte, 2*len(units))
			for i, u := range units {
				binary.LittleEndian.PutUint16(input[2*i:], u)
			}
		} else {
			input = []byte(path)
		}
	}
	sum := sha256.Sum256(input)
	id := make([]byte, 32)
	for i, b := range sum[:16] {
		id[2*i] = 'a' + b>>4
		id[2*i+1] = 'a' + b&15
	}
	return string(id), nil
}

func vaultExtensionManifestObject(raw []byte) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if len(raw) > bitwardenMaxManifestBytes || json.Unmarshal(raw, &fields) != nil || len(fields) == 0 || len(fields) > 1024 {
		return nil, errVaultExtensionFiles
	}
	targets := make(map[string]any, len(fields))
	nullable := make(map[string]bool, len(fields))
	for name := range fields {
		targets[name] = new(json.RawMessage)
		nullable[name] = true
	}
	if decodeVaultNullableObject(raw, targets, nullable) != nil {
		return nil, errVaultExtensionFiles
	}
	return fields, nil
}

func validVaultExtensionVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) > 4 {
		return false
	}
	nonzero := false
	for _, part := range parts {
		n, err := strconv.ParseUint(part, 10, 16)
		if err != nil || strconv.FormatUint(n, 10) != part {
			return false
		}
		nonzero = nonzero || n != 0
	}
	return nonzero
}

const vaultBitwardenInstallDirectory = "vault-bitwarden-installations"

// Main-only read operation. A renderer cannot supply a directory or substitute
// installation metadata. Mutating install actions need separate authorization.
func (h *vaultFoundationHandler) bitwardenInstallationPlan(ctx context.Context, raw []byte) (json.RawMessage, error) {
	return h.bitwardenInstallation(ctx, raw, true)
}

// Revision-only preflight authenticates the record without requiring an intact
// old package. It permits repair, never admission or loading of unchecked files.
func (h *vaultFoundationHandler) bitwardenInstallationRevision(ctx context.Context, raw []byte) (json.RawMessage, error) {
	return h.bitwardenInstallation(ctx, raw, false)
}
func (h *vaultFoundationHandler) bitwardenInstallation(ctx context.Context, raw []byte, verifyFiles bool) (json.RawMessage, error) {
	if h.owner == nil || len(raw) > 1024 {
		return nil, vaultwire.ErrProtocol
	}
	var workspace, minimum string
	if decodeVaultObject(raw, map[string]any{"workspaceId": &workspace, "minimumRevision": &minimum}, "workspaceId", "minimumRevision") != nil || !vaultCredentialID(workspace) {
		return nil, vaultwire.ErrProtocol
	}
	revision, err := vaultCredentialRevision(minimum, true)
	if err != nil {
		return nil, vaultwire.ErrProtocol
	}
	actual, err := h.owner.WorkspaceID(ctx)
	if err != nil {
		return nil, err
	}
	if workspace != actual {
		return nil, vaultwire.ErrProtocol
	}
	state, storedRevision, err := h.owner.ReadBitwardenInstallation(ctx, revision)
	if err != nil {
		return nil, err
	}
	if !verifyFiles {
		return json.Marshal(struct {
			WorkspaceID string `json:"workspaceId"`
			Revision    string `json:"revision"`
		}{workspace, strconv.FormatUint(storedRevision, 10)})
	}
	var base *os.Root
	if state.Enabled {
		base, err = openVaultBitwardenInstallRoot(h.databasePath, state.Layout, false)
		if err != nil {
			return nil, errVaultExtensionFiles
		}
	}
	pkg, version, planErr := planVaultBitwardenInstallation(ctx, h.owner, base, revision)
	if base != nil {
		if err = base.Close(); err != nil {
			return nil, errVaultExtensionFiles
		}
	}
	if planErr != nil {
		return nil, planErr
	}
	var installation any
	if pkg.InstallationID != "" {
		installation = struct {
			ID          string `json:"id"`
			ExtensionID string `json:"extensionId"`
			Version     string `json:"version"`
			Popup       string `json:"popup"`
			Background  string `json:"background"`
		}{pkg.InstallationID, pkg.ExtensionID, pkg.Version, pkg.Popup, pkg.Background}
	}
	return json.Marshal(struct {
		WorkspaceID  string `json:"workspaceId"`
		Revision     string `json:"revision"`
		Installation any    `json:"installation"`
	}{workspace, strconv.FormatUint(version, 10), installation})
}
