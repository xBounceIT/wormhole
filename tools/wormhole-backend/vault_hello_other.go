//go:build !windows || (!amd64 && !arm64)

package main

import (
	"context"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func platformVaultHelloAvailable(context.Context) error     { return errVaultHelloUnavailable }
func platformRemoveVaultHello(context.Context, string) bool { return false }

func withPlatformVaultHello(context.Context, string, uintptr, bool, func(vault.HelloCredential) error) error {
	return errVaultHelloUnavailable
}
