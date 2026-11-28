//go:build !linux

package ospolicy

import "os"

func OpenManagedSystemPackage(string) (*os.File, error) {
	return nil, ErrInstallationLocation
}
