package vault

import (
	"net"
	"strconv"
)

// Native route children bind only IPv4 loopback listeners. Reject alternative
// spellings as well as nonloopback endpoints before admitting a credential handoff.
func ValidRouteEndpoint(endpoint string) bool {
	host, text, err := net.SplitHostPort(endpoint)
	if err != nil || host != "127.0.0.1" {
		return false
	}
	port, err := strconv.ParseUint(text, 10, 16)
	return err == nil && port > 0 && strconv.FormatUint(port, 10) == text
}
func routedBundleInfo(binding TunnelBundleBinding, endpoint string) ([]byte, error) {
	if !ValidRouteEndpoint(endpoint) {
		return nil, ErrFormat
	}
	info, err := binding.info()
	if err != nil {
		return nil, err
	}
	return canonical("wormhole/v1/routed-protocol-bundle", info, []byte(endpoint)), nil
}

// A routed protocol bundle authenticates the precise VPN configuration and
// main-owned listener along with the original destination. It cannot be opened
// as a direct credential bundle or as a tunnel configuration.
func SealRoutedBundle(publicKey []byte, binding TunnelBundleBinding, endpoint string, plaintext []byte) (SealedBundle, error) {
	if len(plaintext) > MaxSecretBytes {
		return SealedBundle{}, ErrFormat
	}
	info, err := routedBundleInfo(binding, endpoint)
	if err != nil {
		return SealedBundle{}, err
	}
	return sealBundlePayload(publicKey, info, plaintext)
}
func OpenRoutedBundle(privateKey []byte, binding TunnelBundleBinding, endpoint string, bundle SealedBundle) ([]byte, error) {
	if err := validateSealedBundle(bundle); err != nil {
		return nil, err
	}
	info, err := routedBundleInfo(binding, endpoint)
	if err != nil {
		return nil, err
	}
	return openBundlePayload(privateKey, info, bundle)
}
