package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCiscoProfileExtractsFirstHostEntry(t *testing.T) {
	result, err := parseCiscoProfile([]byte(`<?xml version="1.0"?>
<AnyConnectProfile>
  <ServerList>
    <HostEntry>
      <HostName>Primary VPN</HostName>
      <HostAddress>https://vpn.example.com:8443/</HostAddress>
      <UserGroup>Contractors</UserGroup>
    </HostEntry>
    <HostEntry>
      <HostAddress>backup.example.com</HostAddress>
    </HostEntry>
  </ServerList>
</AnyConnectProfile>`))
	if err != nil {
		t.Fatal(err)
	}
	if result.Host != "vpn.example.com" || result.Port != 8443 ||
		result.Group != "Contractors" || result.ProfileName != "Primary VPN" {
		t.Fatalf("result = %#v", result)
	}
}

func TestParseCiscoProfilePlainHostPortAndDefaults(t *testing.T) {
	result, err := parseCiscoProfile([]byte(`<AnyConnectProfile><ServerList><HostEntry><HostAddress>vpn.corp.test:443</HostAddress></HostEntry></ServerList></AnyConnectProfile>`))
	if err != nil {
		t.Fatal(err)
	}
	if result.Host != "vpn.corp.test" || result.Port != 443 || result.Group != "" {
		t.Fatalf("result = %#v", result)
	}
}

func TestParseCiscoProfileRejectsInvalidShapes(t *testing.T) {
	for _, xml := range []string{
		``,
		`<Other/>`,
		`<AnyConnectProfile/>`,
		`<AnyConnectProfile><ServerList><HostEntry><HostName></HostName></HostEntry></ServerList></AnyConnectProfile>`,
		`<AnyConnectProfile><ServerList><HostEntry><HostAddress>http://vpn.example.com</HostAddress></HostEntry></ServerList></AnyConnectProfile>`,
		`<AnyConnectProfile><ServerList><HostEntry><HostAddress>https://user@vpn.example.com</HostAddress></HostEntry></ServerList></AnyConnectProfile>`,
		`<AnyConnectProfile><ServerList><HostEntry><HostAddress>vpn.example.com:0</HostAddress></HostEntry></ServerList></AnyConnectProfile>`,
		`<AnyConnectProfile><ServerList><HostEntry><HostAddress>vpn.example.com/path</HostAddress></HostEntry></ServerList></AnyConnectProfile>`,
	} {
		if _, err := parseCiscoProfile([]byte(xml)); err == nil {
			t.Fatalf("accepted invalid profile %q", xml)
		}
	}
}

func TestParseCiscoProfileAcceptsIPv6Literal(t *testing.T) {
	result, err := parseCiscoProfile([]byte(`<AnyConnectProfile><ServerList><HostEntry><HostAddress>[2001:db8::1]:8443</HostAddress></HostEntry></ServerList></AnyConnectProfile>`))
	if err != nil {
		t.Fatal(err)
	}
	if result.Host != "2001:db8::1" || result.Port != 8443 {
		t.Fatalf("result = %#v", result)
	}
}

func TestImportOvpnFilePreservesProfileVerbatim(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.ovpn")
	contents := "client\n<ca>\nline one\nline two\n</ca>\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := importOvpnFile(ovpnImportRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if result.Contents != contents {
		t.Fatalf("contents = %q, want %q", result.Contents, contents)
	}
}

func TestImportOvpnFileRejectsRelativeOrMissingPath(t *testing.T) {
	if _, err := importOvpnFile(ovpnImportRequest{Path: "client.ovpn"}); err == nil {
		t.Fatal("relative path was accepted")
	}
	if _, err := importOvpnFile(ovpnImportRequest{Path: filepath.Join(t.TempDir(), "missing.ovpn")}); err == nil {
		t.Fatal("missing path was accepted")
	}
}

func TestImportOvpnFileRejectsOversizedProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.ovpn")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxImportedProfileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := importOvpnFile(ovpnImportRequest{Path: path}); err == nil {
		t.Fatal("oversized profile was accepted")
	}
}
