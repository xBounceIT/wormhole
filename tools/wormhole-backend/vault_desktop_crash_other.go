//go:build !windows

package main

import "github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"

func validateDesktopCrashPolicy(vault.Profile) error { return nil }

func validateNativeRdpCrashPolicy(int) error { return vault.ErrPolicy }
