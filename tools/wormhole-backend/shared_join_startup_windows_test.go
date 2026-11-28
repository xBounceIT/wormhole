package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSharedJoinStartupNativeOSProtection(t *testing.T) {
	_, f, _, initial, _ := sharedJoinStartupFixture(t)
	protection := nativeSharedStartupProtection()
	if err := writeSharedJoinStartup(context.Background(), f.o.TrustPath, initial, protection, false); err != nil {
		t.Fatal(err)
	}
	actual, err := readSharedJoinStartup(f.o.TrustPath, protection)
	if err != nil || !reflect.DeepEqual(actual, initial) {
		t.Fatal("native OS protection", err)
	}
	raw, err := os.ReadFile(sharedJoinStartupPath(f.o.TrustPath))
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "other.trust")
	if err := os.WriteFile(sharedJoinStartupPath(other), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSharedJoinStartup(other, protection); err == nil {
		t.Fatal("native selection copied between paths")
	}
}
