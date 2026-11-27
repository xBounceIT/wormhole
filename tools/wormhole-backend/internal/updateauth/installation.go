package updateauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

const (
	InstallationProofSuffix = ".wh-installation.json"
	MaxInstallationEntries  = 20_000
	MaxInstallationProof    = 4096
	installationDomain      = "wormhole/installed-release/v1\x00"
)

type InstallationManifest struct {
	FormatVersion int    `json:"formatVersion"`
	Repository    string `json:"repository"`
	ReleaseTag    string `json:"releaseTag"`
	Target        string `json:"target"`
	Entries       int    `json:"entries"`
	TreeSHA256    string `json:"treeSha256"`
}

type installationEnvelope struct {
	Manifest  InstallationManifest `json:"manifest"`
	Signature []byte               `json:"signature"`
}

func InstallationTarget(operatingSystem, architecture string) string {
	if architecture == "amd64" {
		architecture = "x64"
	}
	if architecture != "x64" && architecture != "arm64" {
		return ""
	}
	switch operatingSystem {
	case "darwin":
		return "darwin/universal"
	case "linux", "windows":
		return operatingSystem + "/" + architecture
	default:
		return ""
	}
}

func installationTargetValid(target string) bool {
	for _, known := range targets {
		if target == known {
			return true
		}
	}
	return false
}

func (m InstallationManifest) canonical() ([]byte, error) {
	if m.FormatVersion != 1 || m.Repository != Repository || !tagPattern.MatchString(m.ReleaseTag) ||
		!installationTargetValid(m.Target) || m.Entries < 1 || m.Entries > MaxInstallationEntries || !validHex(m.TreeSHA256, sha256.Size) {
		return nil, ErrManifest
	}
	return json.Marshal(m)
}

// ParseInstallationInventory validates the exact unsigned record emitted by
// the inventory command. A release signer receives only this bounded record.
func ParseInstallationInventory(raw []byte) (InstallationManifest, error) {
	var m InstallationManifest
	if len(raw) > MaxInstallationProof || json.Unmarshal(raw, &m) != nil {
		return m, ErrManifest
	}
	if canonical, err := m.canonical(); err != nil || !bytes.Equal(canonical, raw) {
		return InstallationManifest{}, ErrManifest
	}
	return m, nil
}

func SignInstallation(m InstallationManifest, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrSignature
	}
	raw, err := m.canonical()
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(key, append([]byte(installationDomain), raw...))
	return json.Marshal(installationEnvelope{Manifest: m, Signature: sig})
}

func verifyInstallationManifest(raw []byte, key ed25519.PublicKey) (InstallationManifest, error) {
	var e installationEnvelope
	if len(raw) > MaxInstallationProof || len(key) != ed25519.PublicKeySize || json.Unmarshal(raw, &e) != nil || len(e.Signature) != ed25519.SignatureSize {
		return InstallationManifest{}, ErrManifest
	}
	canonical, err := json.Marshal(e)
	if err != nil || !bytes.Equal(raw, canonical) {
		return InstallationManifest{}, ErrManifest
	}
	m, err := e.Manifest.canonical()
	if err != nil {
		return InstallationManifest{}, err
	}
	if !ed25519.Verify(key, append([]byte(installationDomain), m...), e.Signature) {
		return InstallationManifest{}, ErrSignature
	}
	return e.Manifest, nil
}

// VerifyInstalledTree reads the detached proof next to a package whose native
// location and ownership have already been verified by the caller.
func VerifyInstalledTree(ctx context.Context, packageRoot, target string, key ed25519.PublicKey) (InstallationManifest, error) {
	if err := ctx.Err(); err != nil {
		return InstallationManifest{}, err
	}
	if !filepath.IsAbs(packageRoot) || filepath.Clean(packageRoot) != packageRoot || filepath.Dir(packageRoot) == packageRoot ||
		!installationTargetValid(target) || len(key) != ed25519.PublicKeySize {
		return InstallationManifest{}, ErrManifest
	}
	parent, err := os.OpenRoot(filepath.Dir(packageRoot))
	if err != nil {
		return InstallationManifest{}, ErrManifest
	}
	defer parent.Close()
	file, err := OpenArtifact(parent, filepath.Base(packageRoot)+InstallationProofSuffix)
	if err != nil {
		return InstallationManifest{}, ErrManifest
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, MaxInstallationProof+1))
	if err != nil {
		return InstallationManifest{}, ErrManifest
	}
	m, err := verifyInstallationManifest(raw, key)
	if err != nil {
		return InstallationManifest{}, err
	}
	if m.Target != target {
		return InstallationManifest{}, ErrManifest
	}
	measured, err := InventoryInstallation(ctx, packageRoot, m.ReleaseTag, target)
	if err != nil {
		return InstallationManifest{}, err
	}
	if measured != m {
		return InstallationManifest{}, ErrArtifact
	}
	return m, nil
}
