//go:build !windows

package main

func applyNativeRdpCredentials(reference, password, gatewayPassword []byte, passwordProvided, gatewayProvided bool) error {
	return errRdpNativeReference
}
