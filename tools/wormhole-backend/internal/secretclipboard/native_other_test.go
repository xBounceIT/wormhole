//go:build !windows && (!darwin || !cgo)

package secretclipboard

import "testing"

func TestNativeClipboardUnavailable(t *testing.T) {
	driver, err := NewNative()
	if driver != nil || err != ErrUnavailable {
		t.Fatal("unsupported native clipboard advertised", err)
	}
}
