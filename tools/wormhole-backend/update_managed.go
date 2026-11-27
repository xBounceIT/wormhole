package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/updateauth"
)

const managedUpdateURLPrefix = "managed-update:"

var readManagedUpdatePolicy = ospolicy.ReadManagedUpdate
var openManagedSystemPackage = ospolicy.OpenManagedSystemPackage

func isManagedUpdateURL(value string) bool {
	return strings.HasPrefix(value, managedUpdateURLPrefix)
}

func managedPublisherRequired() bool {
	return runtime.GOOS == "darwin" || runtime.GOOS == "windows"
}

func matchesManagedDigest(raw []byte, approval ospolicy.ManagedUpdate) bool {
	sum := sha256.Sum256(raw)
	return approval.Digest == hex.EncodeToString(sum[:])
}

func approvedManagedUpdate(request updateDownloadRequest) (ospolicy.ManagedUpdate, error) {
	approval, err := readManagedUpdatePolicy(context.Background())
	if err != nil {
		return ospolicy.ManagedUpdate{}, updateauth.ErrManifest
	}
	if err := verifyManagedApproval(request, approval, runtime.GOOS, updateTargetArchitecture()); err != nil {
		return ospolicy.ManagedUpdate{}, err
	}
	return approval, nil
}

func verifyManagedApproval(request updateDownloadRequest, approval ospolicy.ManagedUpdate, platform, arch string) error {
	if !matchesManagedDigest(request.SignedManifest, approval) {
		return updateauth.ErrManifest
	}
	if platform != "linux" {
		return nil
	}
	// One approved manifest covers both formats. Recheck the administrator's
	// staged choice even when a previously downloaded file is still cached.
	key, err := updateauth.ParsePublicKey(updateManifestPublicKeyHex)
	if err != nil {
		return err
	}
	manifest, err := updateauth.Verify(request.SignedManifest, key)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(approval.Directory)
	if err != nil {
		return updateauth.ErrArtifact
	}
	defer root.Close()
	asset, err := stagedManagedInstaller(root, manifest, platform, arch)
	if err != nil || asset.Name != request.InstallerFileName {
		return updateauth.ErrArtifact
	}
	return nil
}

func checkVaultUpdateRelease(databasePath string, request updateCheckRequest) (updateCheckResponse, error) {
	switch request.ManagedMode {
	case "":
		return checkUpdateRelease(databasePath, request, true)
	case "preferred", "required":
	default:
		return updateCheckResponse{}, updateauth.ErrManifest
	}
	approval, err := readManagedUpdatePolicy(context.Background())
	if err == nil && approval.Digest == "" && request.ManagedMode == "preferred" {
		return checkUpdateRelease(databasePath, request, true)
	}
	result := updateCheckResponse{CurrentVersion: request.CurrentVersion, Managed: true}
	if err != nil {
		result.CheckFailed = true
		return result, nil
	}
	if approval.Digest == "" {
		return result, nil
	}
	result, err = checkManagedUpdate(result, approval)
	if err != nil {
		return updateCheckResponse{CurrentVersion: request.CurrentVersion, Managed: true, CheckFailed: true}, nil
	}
	return result, nil
}

func checkManagedUpdate(result updateCheckResponse, approval ospolicy.ManagedUpdate) (updateCheckResponse, error) {
	current, valid := parseAppVersion(result.CurrentVersion)
	if !valid {
		return result, updateauth.ErrManifest
	}
	key, err := updateauth.ParsePublicKey(updateManifestPublicKeyHex)
	if err != nil {
		return result, err
	}
	root, err := os.OpenRoot(approval.Directory)
	if err != nil {
		return result, updateauth.ErrManifest
	}
	defer root.Close()
	manifestName := updateauth.ManifestName
	if runtime.GOOS == "linux" {
		manifestName = updateauth.SystemManifestName
	}
	file, err := updateauth.OpenArtifact(root, manifestName)
	if err != nil {
		return result, updateauth.ErrManifest
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, updateauth.MaxManifestBytes+1))
	if err != nil || len(raw) > updateauth.MaxManifestBytes || !matchesManagedDigest(raw, approval) {
		return result, updateauth.ErrManifest
	}
	manifest, err := updateauth.Verify(raw, key)
	if err != nil {
		return result, err
	}
	result.LastUpdateCheck = time.Now().UTC().Format(time.RFC3339)
	latest, _ := parseAppVersion(manifest.ReleaseTag)
	if !current.lessThan(latest) {
		return result, nil
	}
	asset, err := stagedManagedInstaller(root, manifest, runtime.GOOS, updateTargetArchitecture())
	if err != nil {
		return result, err
	}
	if managedPublisherRequired() {
		if err := updateauth.ValidatePublisherIdentity(nativePublisherIdentity()); err != nil {
			return result, err
		}
		result.PublisherVerification = true
	}
	result.LatestVersion = latest.String()
	result.ReleaseTag = manifest.ReleaseTag
	result.IsNewerRelease = true
	result.IsUpdateAvailable = true
	result.InstallerUrl = managedUpdateURLPrefix + asset.Name
	result.InstallerFileName = asset.Name
	result.InstallerSize = &asset.Size
	result.InstallerSha256 = asset.SHA256
	result.SignedManifest = raw
	return result, nil
}

func stagedManagedInstaller(root *os.Root, manifest updateauth.Manifest, platform, arch string) (updateauth.Artifact, error) {
	var selected updateauth.Artifact
	if platform == "linux" {
		for _, format := range []string{"deb", "rpm"} {
			asset, ok := manifest.LinuxPackage(arch, format)
			if !ok {
				return updateauth.Artifact{}, updateauth.ErrArtifact
			}
			info, err := root.Lstat(asset.Name)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil || !info.Mode().IsRegular() || info.Size() != asset.Size || selected.Name != "" {
				return updateauth.Artifact{}, updateauth.ErrArtifact
			}
			selected = asset
		}
	} else if asset, ok := manifest.ArtifactFor(platform, arch); ok {
		info, err := root.Lstat(asset.Name)
		if err == nil && info.Mode().IsRegular() && info.Size() == asset.Size {
			selected = asset
		}
	}
	if selected.Name == "" {
		return updateauth.Artifact{}, updateauth.ErrArtifact
	}
	return selected, nil
}

// The administrator installs from the protected staging directory. Authenticate
// that file independently of the user-owned copy used for download progress.
func managedSystemPackagePath(request updateDownloadRequest, directory string) (string, error) {
	path := filepath.Join(directory, request.InstallerFileName)
	file, err := openManagedSystemPackage(path)
	if err != nil {
		return "", updateauth.ErrArtifact
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return "", updateauth.ErrArtifact
	}
	size, digest, err := updateauth.DigestFile(file)
	if err != nil || size != request.InstallerSize || digest != request.InstallerSha256 {
		return "", updateauth.ErrArtifact
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return "", updateauth.ErrArtifact
	}
	return path, nil
}

func openManagedUpdateInstaller(request updateDownloadRequest) (io.ReadCloser, int64, error) {
	approval, err := approvedManagedUpdate(request)
	if err != nil {
		return nil, 0, err
	}
	root, err := os.OpenRoot(approval.Directory)
	if err != nil {
		return nil, 0, updateauth.ErrArtifact
	}
	defer root.Close()
	file, err := updateauth.OpenArtifact(root, request.InstallerFileName)
	if err != nil {
		return nil, 0, err
	}
	info, err := file.Stat()
	if err != nil || info.Size() != request.InstallerSize {
		file.Close()
		return nil, 0, updateauth.ErrArtifact
	}
	return file, info.Size(), nil
}
