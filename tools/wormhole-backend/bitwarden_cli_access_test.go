package main

import (
	"path/filepath"
	"testing"
)

func TestBitwardenContentRequiresExplicitNativeSession(t *testing.T) {
	t.Setenv(bitwardenCliSessionEnvVar, "unrelated-parent-session")
	for _, command := range []string{"list", "get", "sync"} {
		for _, key := range []string{"", " \t\n"} {
			for _, env := range []map[string]string{nil, {bitwardenCliSessionEnvVar: key}} {
				if err := requireBitwardenCliContentSession([]string{command}, env); !isBitwardenCliAuthError(err) {
					t.Fatalf("%s must request native authentication, got %v", command, err)
				}
			}
		}
		if err := requireBitwardenCliContentSession([]string{command}, map[string]string{bitwardenCliSessionEnvVar: "native-session"}); err != nil {
			t.Fatalf("%s rejected the native session: %v", command, err)
		}
	}
	for _, args := range [][]string{nil, {}, {"status"}, {"login"}, {"unlock"}, {"logout"}, {"config", "server"}} {
		if err := requireBitwardenCliContentSession(args, nil); err != nil {
			t.Fatalf("non-content operation %v requires no unlocked vault: %v", args, err)
		}
	}
}

func TestBitwardenContentRequestsAuthenticationBeforeStartingCLI(t *testing.T) {
	t.Setenv(bitwardenCliSessionEnvVar, "unrelated-parent-session")
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	settings := bitwardenCliSettings{Path: filepath.Join(t.TempDir(), "must-not-start")}
	for _, operation := range []struct {
		name string
		run  func() error
	}{
		{"list", func() error { _, err := bitwardenCliListItems(databasePath, settings, "", "router"); return err }},
		{"search", func() error { _, err := bitwardenCliSearchItems(databasePath, settings, "", "router"); return err }},
		{"get", func() error { _, err := bitwardenCliGetItem(databasePath, settings, "", "item-id"); return err }},
		{"sync", func() error { return bitwardenCliSync(databasePath, settings, "") }},
	} {
		t.Run(operation.name, func(t *testing.T) {
			if err := operation.run(); !isBitwardenCliAuthError(err) {
				t.Fatalf("expected authentication before executable lookup, got %v", err)
			}
		})
	}
}
