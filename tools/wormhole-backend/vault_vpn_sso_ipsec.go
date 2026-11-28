package main

import (
	"crypto/sha256"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func describeNativeVPNSSO(startURL string, ignoreCertificateErrors bool) localvault.VPNSSODescribeProvider {
	return func(kind uint16, configuration []byte) (localvault.VPNSSOProvider, error) {
		if kind == 2 {
			return describeNativeSSLSSO(startURL, ignoreCertificateErrors)(kind, configuration)
		}
		if kind != 9 {
			return localvault.VPNSSOProvider{}, vault.ErrPolicy
		}
		settings, err := decodeVaultTunnelSettings(configuration)
		if err != nil {
			return localvault.VPNSSOProvider{}, err
		}
		defer clearTunnelSettingsMap(settings)
		if validateTunnelSettings(9, settings) != nil || fortinetUserAuth(settings) != 3 {
			return localvault.VPNSSOProvider{}, vault.ErrPolicy
		}
		ignore := tunnelSettingBool(settings, "TrustServerCertificate")
		start, err := url.Parse(startURL)
		if err != nil || len(startURL) > 4096 || strings.IndexFunc(startURL, func(r rune) bool { return r <= 32 || r == 127 }) >= 0 || start.Scheme != "https" || start.User != nil || start.EscapedPath() != "/saml" || start.Fragment != "" || ignore != ignoreCertificateErrors {
			return localvault.VPNSSOProvider{}, vault.ErrAuthentication
		}
		port := int(tunnelSettingNumber(settings, "SamlPort"))
		if port == 0 {
			port = 1001
		}
		gateways := []string{tunnelSettingString(settings, "Host")}
		if additional := tunnelSettingString(settings, "RemoteGateways"); additional != "" {
			gateways = append(gateways, strings.Split(additional, ",")...)
		}
		for _, gateway := range gateways {
			base, err := buildWebURL("https", strings.TrimSpace(gateway), port)
			if err != nil {
				return localvault.VPNSSOProvider{}, vault.ErrFormat
			}
			configured, _ := url.Parse(base)
			if start.Host != configured.Host {
				continue
			}
			// The query belongs to a fresh native SAML attempt. It is bound in the
			// completion envelope, but must not become a new retained SSO scope.
			// Each selected gateway still has its own authenticated origin scope.
			trust, _ := json.Marshal(struct {
				Purpose string
				Ignore  bool
			}{"wormhole/v1/fortinet-ipsec-saml-trust", ignore})
			return localvault.VPNSSOProvider{GatewayOrigin: start.Scheme + "://" + configured.Host, TrustDigest: sha256.Sum256(trust)}, nil
		}
		return localvault.VPNSSOProvider{}, vault.ErrAuthentication
	}
}
