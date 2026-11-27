package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestCapabilitiesCLI(t *testing.T) {
	if os.Getenv("WORMHOLE_CAPABILITIES_CHILD") == "1" {
		flag.CommandLine = flag.NewFlagSet("ovpnproxy", flag.ExitOnError)
		os.Args = []string{os.Args[0], "--capabilities"}
		main()
		os.Exit(0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCapabilitiesCLI$")
	command.Env = append(os.Environ(), "WORMHOLE_CAPABILITIES_CHILD=1")
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close() // Leave stdin open: a capability query must not wait on it.
	var output bytes.Buffer
	command.Stdout = &output
	if err := command.Run(); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Version int  `json:"version"`
		OpenVPN bool `json:"openVpn"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Version != 1 || result.OpenVPN != openVPNEngineAvailable {
		t.Fatal("incorrect engine capability")
	}
}
