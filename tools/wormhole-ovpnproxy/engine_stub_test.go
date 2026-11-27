//go:build !ovpn3

package main

import "testing"

func TestStubHasNoEngine(t *testing.T) {
	if openVPNEngineAvailable {
		t.Fatal("stub advertises a real engine")
	}
}
