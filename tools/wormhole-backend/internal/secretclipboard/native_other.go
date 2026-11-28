//go:build !windows && (!darwin || !cgo)

package secretclipboard

// Linux requires its main-owned adapter. macOS needs the native AppKit build;
// an accidental no-CGO build must never fall back to unprotected clipboard IO.
func NewNative() (Driver, error) { return nil, ErrUnavailable }
