//go:build ovpn3

package main

import "testing"

func TestNativeBuildAdvertisesEngine(t *testing.T) {
	if !openVPNEngineAvailable {
		t.Fatal("native build hides its engine")
	}
}
