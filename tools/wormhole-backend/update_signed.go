package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/updateauth"
)

// The release workflow supplies the public key to the Go linker. A nonempty
// pin selects the signed protocol exclusively, even if the pin is malformed.
var updateManifestPublicKeyHex string

// Platform identities are injected by the release build and are independent
// of the manifest key.
var updateWindowsPublisherSPKI string
var updateDarwinPublisherTeamID string

func nativePublisherIdentity() string {
	switch runtime.GOOS {
	case "windows":
		return updateWindowsPublisherSPKI
	case "darwin":
		return updateDarwinPublisherTeamID
	default:
		return ""
	}
}

// Overridden by hermetic tests only. Runtime configuration cannot change it.
var updateReleaseOrigin = "https://github.com"

func signedAssetURL(tag, name string) string {
	return updateReleaseOrigin + "/" + updateauth.Repository + "/releases/download/" + url.PathEscape(tag) + "/" + url.PathEscape(name)
}

func signedUpdateClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: func(request *http.Request, previous []*http.Request) error {
		if len(previous) >= 5 || request.URL.Scheme != "https" || request.URL.User != nil || request.URL.Port() != "" {
			return http.ErrUseLastResponse
		}
		switch request.URL.Hostname() {
		case "release-assets.githubusercontent.com", "objects.githubusercontent.com", "github-releases.githubusercontent.com":
			return nil
		default:
			return http.ErrUseLastResponse
		}
	}}
}

func readSignedUpdateAsset(client *http.Client, tag, name string) ([]byte, error) {
	request, err := http.NewRequest(http.MethodGet, signedAssetURL(tag, name), nil)
	if err != nil {
		return nil, updateauth.ErrManifest
	}
	request.Header.Set("User-Agent", "Wormhole-Electron")
	response, err := client.Do(request)
	if err != nil {
		return nil, updateauth.ErrManifest
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, updateauth.ErrManifest
	}
	return io.ReadAll(io.LimitReader(response.Body, updateauth.MaxManifestBytes+1))
}

func checkSignedUpdate(result updateCheckResponse, arch string) updateCheckResponse {
	key, err := updateauth.ParsePublicKey(updateManifestPublicKeyHex)
	if err != nil {
		return result
	}
	publisher := nativePublisherIdentity()
	if publisher != "" && updateauth.ValidatePublisherIdentity(publisher) != nil {
		return result
	}
	// Validate the tag before using it in a release asset path.
	if _, err := updateauth.NewManifest(result.ReleaseTag); err != nil {
		return result
	}
	raw, err := readSignedUpdateAsset(signedUpdateClient(updateCheckTimeout), result.ReleaseTag, updateauth.ManifestName)
	if err != nil {
		return result
	}
	m, err := updateauth.Verify(raw, key)
	if err != nil || m.ReleaseTag != result.ReleaseTag {
		return result
	}
	asset, ok := m.ArtifactFor(runtime.GOOS, arch)
	if !ok {
		return result
	}
	result.IsUpdateAvailable = true
	result.InstallerUrl = signedAssetURL(m.ReleaseTag, asset.Name)
	result.InstallerFileName = asset.Name
	result.InstallerSize = &asset.Size
	result.InstallerSha256 = asset.SHA256
	result.SignedManifest = raw
	result.PublisherVerification = publisher != ""
	return result
}

func validateUpdateDownload(request *updateDownloadRequest) error {
	request.InstallerUrl = strings.TrimSpace(request.InstallerUrl)
	request.InstallerFileName = strings.TrimSpace(request.InstallerFileName)
	request.InstallerSha256 = strings.ToLower(strings.TrimSpace(request.InstallerSha256))
	name := request.InstallerFileName
	if request.InstallerUrl == "" || name == "" {
		return errors.New("update download request is invalid")
	}
	if strings.ContainsAny(name, ":/\\\x00") || filepath.Base(name) != name || name == "." || name == ".." {
		return errors.New("update download file name is invalid")
	}
	if len(request.InstallerSha256) != sha256.Size*2 {
		return errors.New("update download requires a valid SHA-256 digest")
	}
	if _, err := hex.DecodeString(request.InstallerSha256); err != nil {
		return errors.New("update download requires a valid SHA-256 digest")
	}
	if request.InstallerSize <= 0 || request.InstallerSize > updateMaxInstallerBytes {
		return errors.New("update download size is invalid")
	}
	managed := isManagedUpdateURL(request.InstallerUrl)
	if !managed && updateManifestPublicKeyHex == "" && len(request.SignedManifest) == 0 && nativePublisherIdentity() == "" {
		return nil
	}
	key, err := updateauth.ParsePublicKey(updateManifestPublicKeyHex)
	if err != nil {
		return err
	}
	m, err := updateauth.Verify(request.SignedManifest, key)
	if err != nil {
		return err
	}
	asset, ok := m.ArtifactFor(runtime.GOOS, updateTargetArchitecture())
	if managed && runtime.GOOS == "linux" {
		asset, ok = m.LinuxPackage(updateTargetArchitecture(), strings.TrimPrefix(filepath.Ext(name), "."))
	}
	expectedURL := signedAssetURL(m.ReleaseTag, asset.Name)
	if managed {
		expectedURL = managedUpdateURLPrefix + asset.Name
	}
	if !ok || asset.Name != name || asset.SHA256 != request.InstallerSha256 || asset.Size != request.InstallerSize || request.InstallerUrl != expectedURL {
		return updateauth.ErrArtifact
	}
	current, valid := parseAppVersion(request.CurrentVersion)
	latest, _ := parseAppVersion(m.ReleaseTag)
	if !valid || !current.lessThan(latest) {
		return updateauth.ErrManifest
	}
	return nil
}

func verifyCachedUpdate(databasePath string, input io.Reader) (updateVerifyResponse, error) {
	var request updateVerifyRequest
	if err := decodeInputLimit(input, &request, 16*1024); err != nil {
		return updateVerifyResponse{}, err
	}
	return withVerifiedUpdate(databasePath, request, nil)
}

// A Windows launch runs inside this call so the verified object stays locked
// from its first hash until Windows creates the installer process.
func withVerifiedUpdate(databasePath string, request updateVerifyRequest, handoff func(*os.File, updateVerifyResponse) error) (updateVerifyResponse, error) {
	var result updateVerifyResponse
	publisher := nativePublisherIdentity()
	managed := isManagedUpdateURL(strings.TrimSpace(request.InstallerUrl))
	if (request.RequirePublisher || (managed && managedPublisherRequired())) && publisher == "" {
		return result, updateauth.ErrPublisherUnavailable
	}
	if publisher != "" {
		if err := updateauth.ValidatePublisherIdentity(publisher); err != nil {
			return result, err
		}
	}
	if err := validateUpdateDownload(&request.updateDownloadRequest); err != nil {
		return result, err
	}
	var managedDirectory string
	if managed {
		approval, err := approvedManagedUpdate(request.updateDownloadRequest)
		if err != nil {
			return result, err
		}
		managedDirectory = approval.Directory
	}
	root, err := os.OpenRoot(updateCacheDirectory(databasePath))
	if err != nil {
		return result, updateauth.ErrArtifact
	}
	defer root.Close()
	file, err := updateauth.OpenArtifact(root, request.InstallerFileName)
	if err != nil {
		return result, err
	}
	defer file.Close()
	if runtime.GOOS == "windows" && (publisher != "" || handoff != nil) {
		locked, err := updateauth.LockWindowsInstaller(file)
		if err != nil {
			return result, err
		}
		defer locked.Close()
		file = locked
	}
	matchesManifest := func() bool {
		size, hash, err := updateauth.DigestFile(file)
		return err == nil && size == request.InstallerSize && hash == request.InstallerSha256
	}
	if !matchesManifest() {
		return result, updateauth.ErrArtifact
	}
	if publisher != "" {
		if err := updateauth.VerifyPublisher(file, publisher); err != nil {
			return result, err
		}
		// macOS assessment takes a path. Hash the retained file again after
		// the native verifier's identity checks and before issuing a receipt.
		if runtime.GOOS == "darwin" && !matchesManifest() {
			return result, updateauth.ErrArtifact
		}
		result.PublisherVerified = true
	}
	if managed {
		if runtime.GOOS == "linux" {
			result.ManagedPackagePath, err = managedSystemPackagePath(request.updateDownloadRequest, managedDirectory)
			if err != nil {
				return updateVerifyResponse{}, err
			}
		}
		latest, err := approvedManagedUpdate(request.updateDownloadRequest)
		if err != nil {
			return updateVerifyResponse{}, err
		}
		if latest.Directory != managedDirectory {
			return updateVerifyResponse{}, updateauth.ErrManifest
		}
	}
	result.Verified = true
	if handoff != nil {
		if err := handoff(file, result); err != nil {
			return updateVerifyResponse{}, err
		}
	}
	return result, nil
}
