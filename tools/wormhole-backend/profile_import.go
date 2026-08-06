package main

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const maxImportedProfileBytes = 4 << 20

type ciscoImportRequest struct {
	Path string `json:"path"`
}

type ciscoImportResult struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Group       string `json:"group,omitempty"`
	ProfileName string `json:"profileName,omitempty"`
}

type ovpnImportRequest struct {
	Path string `json:"path"`
}

type ovpnImportResult struct {
	Contents string `json:"contents"`
}

// importOvpnFile reads a .ovpn/.conf profile verbatim (no trim: inline <ca>/<cert>/<key>
// blocks rely on internal newlines). Mirrors the legacy WinUI editor's import contract.
func importOvpnFile(request ovpnImportRequest) (ovpnImportResult, error) {
	contents, err := readImportFile(request.Path, "OpenVPN profile")
	if err != nil {
		return ovpnImportResult{}, err
	}
	return ovpnImportResult{Contents: string(contents)}, nil
}

// importCiscoProfileFile parses a Cisco Secure Client / AnyConnect XML profile into the
// non-secret fields needed to start a session. Mirrors the legacy CiscoSecureClientProfileParser:
// the first HostEntry with a HostAddress/HostName wins; credentials are never part of the file.
func importCiscoProfileFile(request ciscoImportRequest) (ciscoImportResult, error) {
	contents, err := readImportFile(request.Path, "AnyConnect profile")
	if err != nil {
		return ciscoImportResult{}, err
	}
	return parseCiscoProfile(contents)
}

// readImportFile validates and reads a user-picked profile file with a bounded size. The
// absolute-path + regular-file checks mirror the legacy WinUI pickers; the cap prevents a
// huge file from being held in memory just to populate an editor field.
func readImportFile(path, label string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New(label + " path is invalid")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxImportedProfileBytes {
		return nil, errors.New(label + " is invalid or too large")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("could not read the " + label)
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxImportedProfileBytes+1))
	if err != nil || len(contents) > maxImportedProfileBytes {
		return nil, errors.New(label + " exceeded the safety limit")
	}
	return contents, nil
}

func parseCiscoProfile(contents []byte) (ciscoImportResult, error) {
	var document struct {
		XMLName    xml.Name `xml:"AnyConnectProfile"`
		ServerList struct {
			HostEntries []struct {
				HostAddress string `xml:"HostAddress"`
				HostName    string `xml:"HostName"`
				UserGroup   string `xml:"UserGroup"`
			} `xml:"HostEntry"`
		} `xml:"ServerList"`
	}
	if err := xml.Unmarshal(contents, &document); err != nil {
		return ciscoImportResult{}, errors.New("the file is not a valid AnyConnect profile")
	}
	if !strings.EqualFold(document.XMLName.Local, "AnyConnectProfile") {
		return ciscoImportResult{}, errors.New("the file is not a Cisco Secure Client profile (expected an <AnyConnectProfile> root element)")
	}
	for _, entry := range document.ServerList.HostEntries {
		address := strings.TrimSpace(entry.HostAddress)
		if address == "" {
			address = strings.TrimSpace(entry.HostName)
		}
		if address == "" {
			continue
		}
		host, port, err := parseCiscoHostAddress(address)
		if err != nil {
			return ciscoImportResult{}, err
		}
		group := strings.TrimSpace(entry.UserGroup)
		profileName := strings.TrimSpace(entry.HostName)
		result := ciscoImportResult{Host: host, Port: port}
		if group != "" {
			result.Group = group
		}
		if profileName != "" {
			result.ProfileName = profileName
		}
		return result, nil
	}
	return ciscoImportResult{}, errors.New("the profile does not contain a HostEntry with a HostAddress or HostName value")
}

func parseCiscoHostAddress(value string) (string, int, error) {
	raw := strings.TrimSpace(value)
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Hostname() == "" {
			return "", 0, fmt.Errorf("the profile's HostAddress '%s' is not a valid gateway address", raw)
		}
		if !strings.EqualFold(parsed.Scheme, "https") {
			return "", 0, fmt.Errorf("the profile's HostAddress '%s' must use https when a URL scheme is present", raw)
		}
		if parsed.User != nil {
			return "", 0, fmt.Errorf("the profile's HostAddress '%s' must not include a username", raw)
		}
		port := 443
		if parsed.Port() != "" {
			parsedPort, err := strconv.Atoi(parsed.Port())
			if err != nil || parsedPort < 1 || parsedPort > 65535 {
				return "", 0, fmt.Errorf("the profile's HostAddress '%s' has an invalid port", raw)
			}
			port = parsedPort
		}
		host := strings.Trim(parsed.Hostname(), "[]")
		if _, err := buildWebURL("https", host, port); err != nil {
			return "", 0, fmt.Errorf("the profile's HostAddress '%s' is invalid", raw)
		}
		return host, port, nil
	}
	host, portText, err := net.SplitHostPort(raw)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") && !strings.Contains(raw, ":") {
			if host := strings.TrimSpace(raw); host != "" {
				if _, urlErr := buildWebURL("https", host, 443); urlErr != nil {
					return "", 0, fmt.Errorf("the profile's HostAddress '%s' is invalid", raw)
				}
				return host, 443, nil
			}
		}
		return "", 0, fmt.Errorf("the profile's HostAddress '%s' is invalid", raw)
	}
	if strings.Contains(host, ":") && strings.Trim(host, "[]") != host {
		host = strings.Trim(host, "[]")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("the profile's HostAddress '%s' has an invalid port", raw)
	}
	if _, err := buildWebURL("https", host, port); err != nil {
		return "", 0, fmt.Errorf("the profile's HostAddress '%s' is invalid", raw)
	}
	return host, port, nil
}
