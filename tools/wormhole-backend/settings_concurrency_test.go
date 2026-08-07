package main

import (
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"
)

func TestConcurrentSettingsWritersPreserveIndependentSections(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	_, settingsPath := authPaths(databasePath)
	auth := defaultAuthSettings()
	auth.Mode = 2
	cli := defaultBitwardenCliSettings()
	cli.Enabled = true
	cli.Path = "bw-test"
	extension := defaultBitwardenExtensionSettings()
	extension.Enabled = true
	prompt := false
	mcp := mcpSettings{Enabled: true, Port: 9876}

	writers := []func() error{
		func() error { return saveAuthSettings(settingsPath, auth) },
		func() error { return writeBitwardenCliSettings(databasePath, cli) },
		func() error { return writeBitwardenExtensionSettings(databasePath, extension) },
		func() error { return writePromptBeforeTunnelConnect(databasePath, prompt) },
		func() error { return saveMcpSettings(databasePath, mcp) },
	}
	start := make(chan struct{})
	errors := make(chan error, len(writers))
	var wait sync.WaitGroup
	for _, write := range writers {
		wait.Add(1)
		go func(write func() error) {
			defer wait.Done()
			<-start
			for range 10 {
				if err := write(); err != nil {
					errors <- err
					return
				}
			}
		}(write)
	}
	close(start)
	wait.Wait()
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}

	contents, err := readAuthSettingsFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"AppAuthenticationMode",
		bwCliKeyEnabled,
		bwCliKeyPath,
		bwExtKeyEnabled,
		bwExtKeySource,
		promptBeforeTunnelConnectKey,
		"EnableMcpServer",
		"McpServerPort",
	} {
		if _, ok := document[key]; !ok {
			t.Fatalf("concurrent update lost %s: %s", key, contents)
		}
	}
}
