// Package updateauth defines the signed release format shared by the updater
// and the release signer. It does not trust GitHub asset metadata as a key.
package updateauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
)

const (
	Repository           = "xBounceIT/wormhole"
	ManifestName         = "Wormhole-UpdateManifest-v1.json"
	SystemManifestName   = "Wormhole-UpdateManifest-v2.json"
	MaxManifestBytes     = 8 * 1024
	MaxInstallerBytes    = 2 * 1024 * 1024 * 1024
	domain               = "wormhole/update-manifest/v1\x00"
	systemManifestDomain = "wormhole/update-manifest/v2\x00"
)

var (
	ErrManifest   = errors.New("update manifest is invalid")
	ErrSignature  = errors.New("update manifest signature is invalid")
	tagPattern    = regexp.MustCompile(`^v(0|[1-9][0-9]{0,8})(\.(0|[1-9][0-9]{0,8})){1,3}$`)
	targets       = [...]string{"darwin/universal", "linux/arm64", "linux/x64", "windows/arm64", "windows/x64"}
	systemTargets = slices.Concat(targets[:], []string{"linux/arm64/deb", "linux/arm64/rpm", "linux/x64/deb", "linux/x64/rpm"})
)

type Artifact struct {
	Target string `json:"target"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	FormatVersion int        `json:"formatVersion"`
	Repository    string     `json:"repository"`
	ReleaseTag    string     `json:"releaseTag"`
	Artifacts     []Artifact `json:"artifacts"`
}

type envelope struct {
	Manifest  Manifest `json:"manifest"`
	Signature []byte   `json:"signature"`
}

func releaseName(tag, target string) string {
	if !tagPattern.MatchString(tag) {
		return ""
	}
	prefix := "Wormhole-" + tag[1:]
	switch target {
	case "darwin/universal":
		return prefix + "-mac-universal-setup.dmg"
	case "linux/arm64":
		return prefix + "-arm64.AppImage"
	case "linux/x64":
		return prefix + "-x86_64.AppImage"
	case "linux/arm64/deb":
		return prefix + "-linux-arm64.deb"
	case "linux/arm64/rpm":
		return prefix + "-linux-aarch64.rpm"
	case "linux/x64/deb":
		return prefix + "-linux-amd64.deb"
	case "linux/x64/rpm":
		return prefix + "-linux-x86_64.rpm"
	case "windows/arm64":
		return prefix + "-win-arm64-setup.exe"
	case "windows/x64":
		return prefix + "-win-x64-setup.exe"
	}
	return ""
}

// NewManifest lists the required installer names in their canonical order.
// The release signer fills in the size and digest of each packaged artifact.
func NewManifest(tag string) (Manifest, error) {
	return newManifest(tag, 1)
}

// NewSystemManifest also binds the DEB and RPM for each supported architecture.
// The release continues to publish the original manifest for older clients.
func NewSystemManifest(tag string) (Manifest, error) {
	return newManifest(tag, 2)
}

func manifestTargets(version int) []string {
	switch version {
	case 1:
		return targets[:]
	case 2:
		return systemTargets
	}
	return nil
}

func newManifest(tag string, version int) (Manifest, error) {
	if !tagPattern.MatchString(tag) {
		return Manifest{}, ErrManifest
	}
	expected := manifestTargets(version)
	m := Manifest{FormatVersion: version, Repository: Repository, ReleaseTag: tag, Artifacts: make([]Artifact, len(expected))}
	for i, target := range expected {
		m.Artifacts[i] = Artifact{Target: target, Name: releaseName(tag, target)}
	}
	return m, nil
}

func (m Manifest) ArtifactFor(goos, arch string) (Artifact, bool) {
	if arch != "arm64" && arch != "x64" && !(goos == "darwin" && arch == "universal") {
		return Artifact{}, false
	}
	if goos == "darwin" && (arch == "x64" || arch == "arm64") {
		arch = "universal"
	}
	return m.artifact(goos + "/" + arch)
}

func (m Manifest) LinuxPackage(arch, format string) (Artifact, bool) {
	if format != "deb" && format != "rpm" || arch != "arm64" && arch != "x64" {
		return Artifact{}, false
	}
	return m.artifact("linux/" + arch + "/" + format)
}

func (m Manifest) artifact(target string) (Artifact, bool) {
	for _, artifact := range m.Artifacts {
		if artifact.Target == target {
			return artifact, true
		}
	}
	return Artifact{}, false
}

func (m Manifest) validate() error {
	expected := manifestTargets(m.FormatVersion)
	if len(expected) == 0 || m.Repository != Repository || !tagPattern.MatchString(m.ReleaseTag) || len(m.Artifacts) != len(expected) {
		return ErrManifest
	}
	for i, artifact := range m.Artifacts {
		if artifact.Target != expected[i] || artifact.Name != releaseName(m.ReleaseTag, expected[i]) ||
			artifact.Size <= 0 || artifact.Size > MaxInstallerBytes || !validHex(artifact.SHA256, sha256.Size) {
			return ErrManifest
		}
	}
	return nil
}

func validHex(s string, size int) bool {
	if len(s) != 2*size {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	if !validHex(s, ed25519.PublicKeySize) {
		return nil, errors.New("invalid update manifest public key")
	}
	raw, _ := hex.DecodeString(s)
	if bytes.Equal(raw, make([]byte, ed25519.PublicKeySize)) {
		return nil, errors.New("empty update manifest public key")
	}
	return ed25519.PublicKey(raw), nil
}

func signatureInput(m Manifest) ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	prefix := domain
	if m.FormatVersion == 2 {
		prefix = systemManifestDomain
	}
	return append([]byte(prefix), raw...), nil
}

func Sign(m Manifest, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrSignature
	}
	message, err := signatureInput(m)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{Manifest: m, Signature: ed25519.Sign(key, message)})
}

func Verify(raw []byte, key ed25519.PublicKey) (Manifest, error) {
	if len(raw) == 0 || len(raw) > MaxManifestBytes || len(key) != ed25519.PublicKeySize {
		return Manifest{}, ErrManifest
	}
	var parsed envelope
	if json.Unmarshal(raw, &parsed) != nil || len(parsed.Signature) != ed25519.SignatureSize {
		return Manifest{}, ErrManifest
	}
	// A byte comparison with the encoding shared by the signer also rejects
	// duplicate keys, alternate number/base64 encodings, and unknown fields.
	canonical, err := json.Marshal(parsed)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Manifest{}, ErrManifest
	}
	message, err := signatureInput(parsed.Manifest)
	if err != nil {
		return Manifest{}, err
	}
	if !ed25519.Verify(key, message, parsed.Signature) {
		return Manifest{}, ErrSignature
	}
	return parsed.Manifest, nil
}
