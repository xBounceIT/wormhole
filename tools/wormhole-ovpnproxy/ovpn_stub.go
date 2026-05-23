//go:build !ovpn3

// Default build variant: no OpenVPN3 CGO link. Real-mode connect attempts return a
// clear error so the SOCKS5 surface stays exercisable in --mock mode for CI and wire-
// protocol tests. Production builds enable the ovpn3 tag from Fetch-OvpnProxy.ps1.

package main

import (
	"context"
	"errors"

	"github.com/xBounceIT/wormhole/tools/internal/sockstun"
)

func startOpenVpn(_ context.Context, _ config) (sockstun.Dialer, func(), error) {
	return nil, nil, errors.New(
		"OpenVPN3 binding not linked in this build of wormhole-ovpnproxy. " +
			"Build with `go build -tags ovpn3` after populating tools/wormhole-ovpnproxy/ovpn_shim " +
			"with openvpn3-core + mbedtls submodules and a static libovpn_shim (Fetch-OvpnProxy.ps1 -Force).")
}
