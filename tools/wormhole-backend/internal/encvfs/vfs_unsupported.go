//go:build !((windows || linux || darwin) && (amd64 || arm64))

package encvfs

func registerVFS() error { return ErrUnavailable }

func canonicalPath(string) (string, error) { return "", ErrUnavailable }
