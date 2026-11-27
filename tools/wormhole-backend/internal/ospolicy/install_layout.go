package ospolicy

import (
	"path"
	"strings"
)

func unixInstallationRoot(platform, frontend, backend string) (string, error) {
	for _, image := range []string{frontend, backend} {
		if len(image) > 4096 || strings.ContainsRune(image, 0) || !path.IsAbs(image) || path.Clean(image) != image {
			return "", ErrInstallationLocation
		}
	}
	backendName := path.Base(backend)
	if backendName != "wormhole-backend-x64" && backendName != "wormhole-backend-arm64" &&
		(platform != "darwin" || backendName != "wormhole-backend-universal") {
		return "", ErrInstallationLocation
	}
	root := path.Dir(frontend)
	switch platform {
	case "linux":
		if path.Base(frontend) == "wormhole" && root != "/" && path.Dir(backend) == path.Join(root, "resources") {
			return root, nil
		}
	case "darwin":
		contents := path.Dir(root)
		bundle := path.Dir(contents)
		if path.Base(frontend) == "Wormhole" && path.Base(root) == "MacOS" && path.Base(contents) == "Contents" &&
			strings.HasSuffix(path.Base(bundle), ".app") && path.Dir(backend) == path.Join(contents, "Resources") {
			return bundle, nil
		}
	}
	return "", ErrInstallationLocation
}
