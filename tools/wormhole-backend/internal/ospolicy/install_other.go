//go:build !windows && !linux && !darwin

package ospolicy

import "context"

func checkNativeInstallation(context.Context) (string, error) {
	return "", ErrInstallationLocation
}
