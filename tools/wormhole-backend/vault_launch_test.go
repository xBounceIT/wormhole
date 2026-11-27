package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type vaultBootRejectWriter struct{}

func (vaultBootRejectWriter) Write([]byte) (int, error) {
	return 0, errors.New("own output fixture failure")
}

func TestVaultLaunchProbeDoesNotOpenOrWriteLegacyFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.db")
	if err := os.WriteFile(path, []byte("not SQLite, private sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadDir(filepath.Dir(path))
	var output, diagnostic bytes.Buffer
	if status := runBackendCLI([]string{"--operation", "vault-startup", "--database", path}, strings.NewReader("ignored stdin"), &output, &diagnostic); status != 0 {
		t.Fatal("read-only probe failed", status)
	}
	var metadata vaultStartupMetadata
	if json.Unmarshal(output.Bytes(), &metadata) != nil || metadata.NewWorkspace || metadata.Slots != nil || diagnostic.Len() != 0 {
		t.Fatal("incorrect public probe")
	}
	after, _ := os.ReadDir(filepath.Dir(path))
	if len(before) != len(after) {
		t.Fatal("probe wrote native files")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "not SQLite, private sentinel" || bytes.Contains(output.Bytes(), []byte("sentinel")) {
		t.Fatal("probe opened or exposed legacy data")
	}
	if status := runVaultStartupCLI(path, vaultBootRejectWriter{}, &diagnostic); status != 1 {
		t.Fatal("output failure ignored")
	}
	if status := runVaultStartupCLI("relative.db", &output, &diagnostic); status != 1 {
		t.Fatal("relative selection accepted")
	}
}

func TestVaultLaunchMigrationRequiresSeparateNativeSessionDirectory(t *testing.T) {
	root, isolated := t.TempDir(), t.TempDir()
	if err := (vaultLaunchOptions{userDataPath: root, migrationSessionData: isolated}).validate(); err != nil {
		t.Fatal(err)
	}
	if err := (vaultLaunchOptions{}).validate(); err != nil {
		t.Fatal("ordinary launch changed", err)
	}
	child := filepath.Join(root, "inside")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(isolated, "file")
	if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, launch := range []vaultLaunchOptions{
		{userDataPath: root, migrationSessionData: root},
		{userDataPath: root, migrationSessionData: child},
		{userDataPath: child, migrationSessionData: root},
		{userDataPath: root, migrationSessionData: "relative"},
		{userDataPath: "", migrationSessionData: isolated},
		{userDataPath: root, migrationSessionData: filepath.Join(isolated, "absent")},
		{userDataPath: root, migrationSessionData: file},
	} {
		if err := launch.validate(); err != vault.ErrPolicy {
			t.Fatal("unsafe native launch accepted", err)
		}
	}
	var output, diagnostic bytes.Buffer
	path := filepath.Join(t.TempDir(), "source.db")
	if status := runBackendCLI([]string{"--operation", "vault-migration", "--database", path}, strings.NewReader(""), &output, &diagnostic); status != 1 {
		t.Fatal("missing isolated launch accepted")
	}
	if status := runVaultLaunchStream(path, strings.NewReader(""), &output, &diagnostic, vaultLaunchOptions{userDataPath: root, migrationSessionData: root}); status != 1 {
		t.Fatal("overlapping isolated launch accepted")
	}
}

func TestVaultLaunchMigrationServiceResumesConfirmedCapsule(t *testing.T) {
	setup, key := migrationSetupFixture(t)
	if err := saveLegacyMigrationSetup(context.Background(), setup, key); err != nil {
		t.Fatal(err)
	}
	var diagnostic bytes.Buffer
	request := append([]byte(`{"version":1,"id":1,"operation":"migration-resume","payload":`), migrationResumeInput(t, setup.Initial)...)
	request = append(request, []byte("}\n")...)
	input, sender := io.Pipe()
	reader, receiver := io.Pipe()
	defer sender.Close()
	defer reader.Close()
	done := make(chan int, 1)
	isolated := t.TempDir()
	go func() {
		done <- runVaultLaunchStream(setup.LogicalSource, input, receiver, &diagnostic, vaultLaunchOptions{userDataPath: setup.UserData, migrationSessionData: isolated})
	}()
	if _, err := sender.Write(request); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(reader).ReadBytes('\n')
	if err != nil || !bytes.Contains(line, []byte(`"unlocked":true`)) {
		t.Fatal("native launch did not resume", string(line), err)
	}
	sender.Close()
	if status := <-done; status != 0 || diagnostic.Len() != 0 {
		t.Fatal("native migration launch failed", status)
	}
	if requireLegacyWorkspace(setup.LogicalSource) != errVaultOwnerRequired {
		t.Fatal("completed launch restored legacy mode")
	}
}
