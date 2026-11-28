package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSharedStartupAnchorNativeProtection(t *testing.T) {
	f, owner := sharedStartupFixture(t)
	p := nativeSharedStartupProtection()
	a, err := writeSharedStartupAnchor(context.Background(), f.o, owner, "Native protection", 0, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	actual, err := readSharedStartupAnchor(f.o.TrustPath, p)
	if err != nil || !reflect.DeepEqual(actual, a) {
		t.Fatal("native roundtrip", err)
	}
	raw, err := os.ReadFile(sharedStartupAnchorPath(f.o.TrustPath))
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "other.trust")
	if err := os.WriteFile(sharedStartupAnchorPath(other), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSharedStartupAnchor(other, p); err == nil {
		t.Fatal("DPAPI blob copied between device paths")
	}
	raw[len(raw)-1] ^= 1
	if err := os.WriteFile(sharedStartupAnchorPath(f.o.TrustPath), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSharedStartupAnchor(f.o.TrustPath, p); err == nil {
		t.Fatal("modified DPAPI blob accepted")
	}
}
