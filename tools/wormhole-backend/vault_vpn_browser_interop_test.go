package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestVPNBrowserInteropProcess(t *testing.T) {
	switch os.Getenv("WORMHOLE_TEST_VPN_BROWSER") {
	case "recipient":
		os.Exit(runBackendCLI([]string{"--operation", "vault-vpn-browser"}, os.Stdin, os.Stdout, os.Stderr))
	case "vault-fallback", "vault-shared-fallback":
		var h *vaultFoundationHandler
		var request map[string]any
		if os.Getenv("WORMHOLE_TEST_VPN_BROWSER") == "vault-shared-fallback" {
			d, body := sharedFallbackSSOFixture(t)
			h, request = d.h, body
		} else {
			f, body := nativeFallbackSSOFixture(t)
			h, request = f.h, body
		}
		pair := request["fallback"].(vault.TunnelFallbackBinding)
		info := map[string]any{"request": request["request"], "binding": pair.Primary, "startURL": request["startURL"]}
		if custody, ok := request["custody"]; ok {
			info["custody"] = custody
		}
		if json.NewEncoder(os.Stdout).Encode(info) != nil {
			os.Exit(1)
		}
		if vaultwire.Serve(context.Background(), os.Stdin, os.Stdout, h, time.Minute) != nil {
			os.Exit(1)
		}
		os.Exit(0)
	case "vault-shared", "vault-shared-ipsec":
		kind := 2
		if os.Getenv("WORMHOLE_TEST_VPN_BROWSER") == "vault-shared-ipsec" {
			kind = 9
		}
		h, _, request, _ := sharedSSOFixture(t, kind)
		vault.Wipe(request["fixturePrivate"].([]byte))
		if json.NewEncoder(os.Stdout).Encode(map[string]any{"request": request["request"], "binding": request["binding"], "custody": request["custody"]}) != nil {
			os.Exit(1)
		}
		if vaultwire.Serve(context.Background(), os.Stdin, os.Stdout, h, time.Minute) != nil {
			os.Exit(1)
		}
		os.Exit(0)
	case "vault", "vault-ipsec":
		kind, configuration := uint16(2), `{"Host":"vpn.test","Port":443,"Realm":"staff","UseSingleSignOn":true}`
		if os.Getenv("WORMHOLE_TEST_VPN_BROWSER") == "vault-ipsec" {
			kind, configuration = 9, `{"Host":"vpn.test","PreSharedKey":"fixture-psk","SamlPort":1001,"UserAuth":3}`
		}
		h, q, binding := nativeSSOProviderFixture(t, kind, configuration)
		if json.NewEncoder(os.Stdout).Encode(map[string]any{"request": q, "binding": binding}) != nil {
			os.Exit(1)
		}
		if vaultwire.Serve(context.Background(), os.Stdin, os.Stdout, h, time.Minute) != nil {
			os.Exit(1)
		}
		os.Exit(0)
	default:
		t.Skip("native private stdio fixture")
	}
}
