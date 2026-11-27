package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

type failedCapabilityWriter struct{}

func (failedCapabilityWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestCapabilitiesWireContract(t *testing.T) {
	var output bytes.Buffer
	if err := writeCapabilities(&output); err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 || result["version"] != float64(1) || result["openVpn"] != openVPNEngineAvailable {
		t.Fatal("invalid capability contract")
	}
	if writeCapabilities(failedCapabilityWriter{}) == nil {
		t.Fatal("write failure ignored")
	}
}
