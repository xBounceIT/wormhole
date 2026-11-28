package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestVaultFileEditSettings(t *testing.T) {
	ctx := context.Background()
	if _, err := (&vaultFoundationHandler{}).Handle(ctx, "file-edit-settings", nil); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	h := vaultCredentialFixture(t)
	read := func() sftpEditorSettings {
		t.Helper()
		raw, err := h.Handle(ctx, "file-edit-settings", nil)
		var got sftpEditorSettings
		if err != nil || json.Unmarshal(raw, &got) != nil || bytes.Contains(raw, []byte("do-not-project")) {
			t.Fatal("invalid settings projection", err)
		}
		return got
	}
	if read().DefaultEditor != "auto" {
		t.Fatal("missing defaults")
	}
	_, path := authPaths(h.databasePath)
	if err := os.WriteFile(path, []byte(`{"Theme":"dark","Password":"do-not-project"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	settings := defaultSftpEditorSettings()
	settings.Editors = []sftpEditor{{ID: "fixture", Name: "Fixture", Executable: "editor", Arguments: []string{"--wait", "{file}"}, Patterns: "*.txt"}}
	settings.DefaultEditor = "fixture"
	settings.MaxFileSize = 4096
	settings.SwapPanels = true
	raw, _ := json.Marshal(settings)
	result, err := h.Handle(ctx, "file-edit-settings", raw)
	if err != nil || !bytes.Equal(raw, result) {
		t.Fatal("settings did not roundtrip", err)
	}
	if read().MaxFileSize != 4096 {
		t.Fatal("settings were not persisted")
	}
	stored, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(stored, []byte("do-not-project")) || !bytes.Contains(stored, []byte("dark")) {
		t.Fatal("unrelated settings overwritten", err)
	}
	for _, input := range [][]byte{
		[]byte(`{}`), []byte(`[]`), bytes.Repeat([]byte(" "), 65537),
		bytes.Replace(raw, []byte(`"swapPanels":true`), []byte(`"swapPanels":true,"unknown":1`), 1),
		bytes.Replace(raw, []byte(`"swapPanels":true`), []byte(`"swapPanels":null`), 1),
		bytes.Replace(raw, []byte(`"id":"fixture"`), []byte(`"id":"fixture","secret":"bad"`), 1),
		bytes.Replace(raw, []byte(`"--wait"`), []byte(`null`), 1),
		bytes.Replace(raw, []byte(`"--wait"`), []byte(`4`), 1),
		bytes.Replace(raw, []byte(`"maxFileSize":4096`), []byte(`"maxFileSize":0`), 1),
		bytes.Replace(raw, []byte(`"defaultEditor":"fixture"`), []byte(`"defaultEditor":"unknown"`), 1),
	} {
		if _, err := h.Handle(ctx, "file-edit-settings", input); err != vaultwire.ErrProtocol {
			t.Fatal("invalid settings accepted", err)
		}
	}
	// HTML escaping can expand a valid inbound document beyond the reply limit.
	// Reject it before persistence, leaving the previous editor configuration usable.
	escaped := settings
	escaped.Editors = append([]sftpEditor(nil), settings.Editors...)
	escaped.Editors[0].Arguments = []string{strings.Repeat("<", 4096), strings.Repeat("<", 4096), strings.Repeat("<", 4096)}
	var input bytes.Buffer
	encoder := json.NewEncoder(&input)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(escaped); err != nil {
		t.Fatal(err)
	}
	if _, err := h.fileEditSettings(ctx, input.Bytes()); err != vaultwire.ErrProtocol {
		t.Fatal("expanded reply budget ignored", err)
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(unchanged, stored) {
		t.Fatal("failed settings write changed the file", err)
	}
	for _, count := range []int{33, 65} {
		copy := settings
		if count == 33 {
			copy.Editors = make([]sftpEditor, count)
		} else {
			copy.Editors = append([]sftpEditor(nil), settings.Editors...)
			copy.Editors[0].Arguments = make([]string, count)
		}
		input, _ := json.Marshal(copy)
		if _, err := h.Handle(ctx, "file-edit-settings", input); err != vaultwire.ErrProtocol {
			t.Fatal("unbounded settings accepted", err)
		}
	}
	for _, after := range []int{1, 2, 3} {
		if _, err := h.fileEditSettings(&editorCancelledContext{Context: ctx, after: after}, raw); err != context.Canceled {
			t.Fatal("cancellation lost", after, err)
		}
	}
	// Legacy empty vectors are projected as arrays, not null.
	if err := os.WriteFile(path, []byte(`{"fileTransfer":{"editors":null,"defaultEditor":"auto","maxFileSize":4096,"swapPanels":false}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if read().Editors == nil {
		t.Fatal("null editors projected")
	}
	settings.Editors[0].Arguments = nil
	raw, _ = json.Marshal(map[string]any{"fileTransfer": settings})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if read().Editors[0].Arguments == nil {
		t.Fatal("null arguments projected")
	}
	// A previously saved legacy document can exceed this endpoint's wire budget.
	settings.Editors[0].Arguments = make([]string, 64)
	for i := range settings.Editors[0].Arguments {
		settings.Editors[0].Arguments[i] = strings.Repeat("x", 4096)
	}
	raw, _ = json.Marshal(map[string]any{"fileTransfer": settings})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.fileEditSettings(ctx, nil); err == nil {
		t.Fatal("oversized settings response escaped")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := h.fileEditSettings(ctx, nil); err == nil {
		t.Fatal("settings read error ignored")
	}
	valid, _ := json.Marshal(defaultSftpEditorSettings())
	if _, err := h.fileEditSettings(ctx, valid); err == nil {
		t.Fatal("settings write error ignored")
	}
	original := h.databasePath
	defer func() { h.databasePath = original }()
	h.databasePath = filepath.Join(path, "missing", "vault.db")
	if _, err := h.fileEditSettings(&editorCancelledContext{Context: ctx, after: 2}, nil); err != context.Canceled {
		t.Fatal("late read cancellation ignored", err)
	}
}

type editorCancelledContext struct {
	context.Context
	after, calls int
}

func (c *editorCancelledContext) Err() error {
	c.calls++
	if c.calls >= c.after {
		return context.Canceled
	}
	return nil
}
