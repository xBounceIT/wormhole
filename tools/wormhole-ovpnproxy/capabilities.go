package main

import (
	"encoding/json"
	"io"
)

// This query never reads stdin, starts a listener or contacts a VPN provider.
func writeCapabilities(output io.Writer) error {
	return json.NewEncoder(output).Encode(struct {
		Version int  `json:"version"`
		OpenVPN bool `json:"openVpn"`
	}{1, openVPNEngineAvailable})
}
