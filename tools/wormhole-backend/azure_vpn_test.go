package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPrepareAzureVPNUsesInteractiveCodeThenSilentRefresh(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.URL.Path != "/tenant/oauth2/v2.0/token" {
			t.Fatalf("unexpected token path: %s", request.URL.Path)
		}
		if err := request.ParseForm(); err != nil {
			t.Fatal(err)
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.Form.Get("grant_type") {
		case "authorization_code":
			if request.Form.Get("code") != "auth-code" || request.Form.Get("code_verifier") == "" {
				t.Fatalf("invalid code exchange: %#v", request.Form)
			}
			_, _ = writer.Write([]byte(`{"access_token":"access-one","refresh_token":"refresh-one"}`))
		case "refresh_token":
			if request.Form.Get("refresh_token") != "refresh-one" {
				t.Fatalf("invalid refresh exchange: %#v", request.Form)
			}
			// Entra may rotate only the access token. The existing refresh token must still be
			// re-persisted so its local 90-day inactivity window advances, matching WinUI.
			_, _ = writer.Write([]byte(`{"access_token":"access-two"}`))
		default:
			t.Fatalf("unexpected grant: %#v", request.Form)
		}
	}))
	defer server.Close()
	previousAuthority := azureOAuthAuthority
	azureOAuthAuthority = server.URL
	defer func() { azureOAuthAuthority = previousAuthority }()
	raw, _ := json.Marshal(map[string]any{
		"Servers": []string{"gateway.vpn.azure.com"}, "Protocol": 0,
		"TenantId": "tenant", "Audience": "client-id",
	})
	snapshot := tunnelConfigSnapshot{
		databasePath: filepath.Join(t.TempDir(), "wormhole.db"),
		id:           "11111111-2222-3333-4444-555555555555",
	}
	prompts := 0
	ctx := withTunnelPromptHandler(context.Background(), func(_ context.Context, prompt tunnelPrompt) (string, error) {
		prompts++
		if !prompt.Browser || prompt.Completion != "oauth-code" || prompt.ExpectedState == "" {
			t.Fatalf("unexpected Azure browser prompt: %#v", prompt)
		}
		encoded, _ := json.Marshal(azureBrowserResult{Code: "auth-code", State: prompt.ExpectedState})
		return string(encoded), nil
	})
	prepared, err := prepareAzureVPN(ctx, raw, snapshot)
	if err != nil {
		t.Fatalf("interactive Azure prepare: %v", err)
	}
	var settings map[string]json.RawMessage
	_ = json.Unmarshal(prepared, &settings)
	if tunnelSettingString(settings, "Username") != "AzureAD" || tunnelSettingString(settings, "Password") != "access-one" {
		t.Fatalf("interactive token was not routed: %s", prepared)
	}
	firstCacheBytes, err := unprotectFile(azureRefreshPath(snapshot))
	if err != nil {
		t.Fatal(err)
	}
	var firstCache azureRefreshCache
	if json.Unmarshal(firstCacheBytes, &firstCache) != nil {
		t.Fatalf("invalid first refresh cache: %s", firstCacheBytes)
	}
	prepared, err = prepareAzureVPN(ctx, raw, snapshot)
	if err != nil {
		t.Fatalf("silent Azure prepare: %v", err)
	}
	_ = json.Unmarshal(prepared, &settings)
	if tunnelSettingString(settings, "Password") != "access-two" || prompts != 1 || requests != 2 {
		t.Fatalf("silent refresh failed: prepared=%s prompts=%d requests=%d", prepared, prompts, requests)
	}
	secondCacheBytes, err := unprotectFile(azureRefreshPath(snapshot))
	if err != nil {
		t.Fatal(err)
	}
	var secondCache azureRefreshCache
	if json.Unmarshal(secondCacheBytes, &secondCache) != nil || secondCache.RefreshToken != "refresh-one" ||
		!secondCache.CreatedAt.After(firstCache.CreatedAt) {
		t.Fatalf("silent refresh did not rotate the existing cache record: before=%#v after=%#v", firstCache, secondCache)
	}
}

func TestParseAzureVPNProfile(t *testing.T) {
	secret := strings.Repeat("ab", 256)
	profile := `<AzVpnProfile xmlns="urn:test"><name>Production P2S</name><serverlist>` +
		`<ServerEntry><fqdn>primary.vpn.azure.com</fqdn></ServerEntry>` +
		`<ServerEntry><fqdn>backup.vpn.azure.com</fqdn></ServerEntry></serverlist>` +
		`<protocolconfig><sslprotocolConfig><transportprotocol>udp</transportprotocol></sslprotocolConfig></protocolconfig>` +
		`<clientauth><type>aad</type><aad><tenant>https://login.microsoftonline.com/tenant-id/</tenant>` +
		`<audience>audience-id</audience><issuer>issuer</issuer><applicationid>client-id</applicationid></aad></clientauth>` +
		`<servervalidation><serversecret>` + secret + `</serversecret></servervalidation></AzVpnProfile>`
	result, err := parseAzureVPNProfile([]byte(profile))
	if err != nil {
		t.Fatal(err)
	}
	servers, ok := result.Settings["Servers"].([]string)
	if result.Name != "Production P2S" || !ok || len(servers) != 2 || result.Settings["TenantId"] != "tenant-id" || result.Settings["Protocol"] != 1 {
		t.Fatalf("parsed Azure profile = %#v", result)
	}
	if _, err := url.Parse(azureRedirectURI); err != nil {
		t.Fatal(err)
	}
}

// Match the structure of an Azure VPN Client .AzureVpnProfile.xml export using
// synthetic gateway, identity and key values; never store a user's VPN payload.
func azureVPNClientExportFixture() string {
	return `<?xml version="1.0" encoding="utf-8"?>
<Example_Profile>
  <version>1</version><name>Example_Profile</name>
  <serverlist>
    <serverentry><fqdn> primary.vpn.azure.com </fqdn></serverentry>
    <serverentry><fqdn>backup.vpn.azure.com</fqdn></serverentry>
    <serverentry><fqdn> </fqdn></serverentry>
  </serverlist>
  <protoconfig><sslprotoconfig><transportprotocol>tcp</transportprotocol></sslprotoconfig></protoconfig>
  <servervalidation><type>cert</type><cert><hash>synthetic-thumbprint</hash></cert>
    <serversecret>` + strings.Repeat("ab", 256) + `</serversecret>
  </servervalidation>
  <clientauth><type>aad</type><aad>
    <issuer>https://sts.windows.net/tenant-id/</issuer>
    <tenant>https://login.microsoftonline.com/tenant-id</tenant>
    <audience>audience-id</audience>
    <cachesigninuser>true</cachesigninuser><disablesso>false</disablesso><enablegrouptoken>false</enablegrouptoken>
  </aad></clientauth>
  <clientconfig/><highavailability>true</highavailability>
</Example_Profile>`
}

func TestImportAzureVPNClientExport(t *testing.T) {
	for _, test := range []struct {
		name, transport string
		protocol        int
	}{
		{name: "TCP", transport: "tcp", protocol: 0},
		{name: "UDP", transport: " UDP ", protocol: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile := strings.Replace(azureVPNClientExportFixture(), ">tcp<", ">"+test.transport+"<", 1)
			path := filepath.Join(t.TempDir(), "Example_Profile.AzureVpnProfile.xml")
			if err := os.WriteFile(path, []byte(profile), 0600); err != nil {
				t.Fatal(err)
			}
			result, err := importAzureVPNFile(azureImportRequest{Path: path})
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]any{
				"Servers":  []string{"primary.vpn.azure.com", "backup.vpn.azure.com"},
				"Protocol": test.protocol, "TenantId": "tenant-id", "Audience": "audience-id",
				"Issuer": "https://sts.windows.net/tenant-id/", "ApplicationId": "",
				"ServerSecretHex": strings.Repeat("ab", 256),
			}
			if result.Name != "Example_Profile" || !reflect.DeepEqual(result.Settings, want) {
				t.Fatal("exported profile settings were not preserved")
			}
			encoded, err := json.Marshal(result.Settings)
			if err != nil {
				t.Fatal(err)
			}
			var settings map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &settings); err != nil {
				t.Fatal(err)
			}
			ovpn, err := buildAzureVPNProfile(settings)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ovpn, "remote primary.vpn.azure.com 443\nremote backup.vpn.azure.com 443\n") ||
				!strings.Contains(ovpn, "<tls-auth>\n-----BEGIN OpenVPN Static key V1-----") {
				t.Fatal("imported gateway or server key was not usable by the VPN runtime")
			}
			if tenant, err := azureTenant(settings); err != nil || tenant != "tenant-id" {
				t.Fatal("imported tenant was not usable for Microsoft sign-in")
			}
		})
	}
}

func TestParseAzureVPNProfileVariants(t *testing.T) {
	canonicalProfile := strings.ReplaceAll(azureVPNClientExportFixture(), "Example_Profile", "AzVpnProfile")
	for _, test := range []struct {
		name, profile, applicationID string
	}{
		{name: "namespaced export", profile: strings.Replace(azureVPNClientExportFixture(), "<Example_Profile>", `<Example_Profile xmlns="urn:azure-vpn">`, 1)},
		{name: "lowercase canonical root", profile: strings.ReplaceAll(azureVPNClientExportFixture(), "Example_Profile", "azvpnprofile")},
		{name: "application ID", profile: strings.Replace(azureVPNClientExportFixture(), "</aad>", "<applicationid> client-id </applicationid><appid>other-id</appid></aad>", 1), applicationID: "client-id"},
		{name: "legacy app ID", profile: strings.Replace(azureVPNClientExportFixture(), "</aad>", "<appid> legacy-id </appid></aad>", 1), applicationID: "legacy-id"},
		{name: "bare tenant", profile: strings.Replace(azureVPNClientExportFixture(), "https://login.microsoftonline.com/tenant-id", "tenant-id", 1)},
		{name: "comments and processing instructions", profile: "<!--before--><?profile test?>" + strings.Replace(azureVPNClientExportFixture(), `<?xml version="1.0" encoding="utf-8"?>`, "", 1) + "\n<!--after--><?profile test?>"},
		{name: "UTF-8 BOM", profile: "\ufeff" + azureVPNClientExportFixture()},
		{name: "canonical default TCP", profile: strings.Replace(canonicalProfile, "<protoconfig><sslprotoconfig><transportprotocol>tcp</transportprotocol></sslprotoconfig></protoconfig>", "", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := parseAzureVPNProfile([]byte(test.profile))
			if err != nil {
				t.Fatal(err)
			}
			if result.Settings["ApplicationId"] != test.applicationID || result.Settings["TenantId"] != "tenant-id" || result.Settings["Protocol"] != 0 {
				t.Fatal("Azure identity settings were not preserved")
			}
		})
	}
}

func TestParseAzureVPNProfileRejectsInvalidProfiles(t *testing.T) {
	for _, test := range []struct {
		name, profile, message string
	}{
		{name: "malformed XML", profile: "<AzVpnProfile>", message: "not a valid Azure VPN profile"},
		{name: "empty document", profile: "", message: "not a valid Azure VPN profile"},
		{name: "unrelated XML", profile: "<document/>", message: "not a valid Azure VPN profile"},
		{name: "missing export version", profile: strings.Replace(azureVPNClientExportFixture(), "<version>1</version>", "", 1), message: "not a valid Azure VPN profile"},
		{name: "missing export name", profile: strings.Replace(azureVPNClientExportFixture(), "<name>Example_Profile</name>", "", 1), message: "not a valid Azure VPN profile"},
		{name: "missing export protocol", profile: strings.ReplaceAll(azureVPNClientExportFixture(), "protoconfig", "unknown"), message: "not a valid Azure VPN profile"},
		{name: "certificate auth", profile: strings.Replace(azureVPNClientExportFixture(), "<type>aad</type>", "<type>cert</type>", 1), message: "does not use Microsoft Entra ID"},
		{name: "missing gateways", profile: strings.ReplaceAll(azureVPNClientExportFixture(), "fqdn", "unknown"), message: "missing gateway or audience"},
		{name: "missing audience", profile: strings.Replace(azureVPNClientExportFixture(), "<audience>audience-id</audience>", "<audience> </audience>", 1), message: "missing gateway or audience"},
		{name: "conflicting protocol blocks", profile: strings.Replace(azureVPNClientExportFixture(), "</protoconfig>", "</protoconfig><protocolconfig><sslprotocolConfig><transportprotocol>udp</transportprotocol></sslprotocolConfig></protocolconfig>", 1), message: "conflicting protocol"},
		{name: "duplicate export protocol", profile: strings.Replace(azureVPNClientExportFixture(), "</protoconfig>", "</protoconfig><protoconfig><sslprotoconfig><transportprotocol>udp</transportprotocol></sslprotoconfig></protoconfig>", 1), message: "conflicting protocol"},
		{name: "empty export transport", profile: strings.Replace(azureVPNClientExportFixture(), "<transportprotocol>tcp</transportprotocol>", "", 1), message: "transport"},
		{name: "unsupported transport", profile: strings.Replace(azureVPNClientExportFixture(), ">tcp<", ">icmp<", 1), message: "transport"},
		{name: "second root", profile: azureVPNClientExportFixture() + "<other/>", message: "not a valid Azure VPN profile"},
		{name: "malformed trailing XML", profile: azureVPNClientExportFixture() + "<other>", message: "not a valid Azure VPN profile"},
		{name: "trailing text", profile: azureVPNClientExportFixture() + "junk", message: "not a valid Azure VPN profile"},
		{name: "trailing broken token", profile: azureVPNClientExportFixture() + "<", message: "not a valid Azure VPN profile"},
		{name: "leading text", profile: "junk" + azureVPNClientExportFixture(), message: "not a valid Azure VPN profile"},
		{name: "trailing declaration", profile: azureVPNClientExportFixture() + `<?xml version="1.0"?>`, message: "not a valid Azure VPN profile"},
		{name: "trailing directive", profile: azureVPNClientExportFixture() + `<!DOCTYPE other>`, message: "not a valid Azure VPN profile"},
		{name: "external entity", profile: `<!DOCTYPE Example_Profile [<!ENTITY secret SYSTEM "file:///unread-file">]>` + azureVPNClientExportFixture(), message: "not a valid Azure VPN profile"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseAzureVPNProfile([]byte(test.profile)); err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("expected %q, got %v", test.message, err)
			}
		})
	}
}

func TestImportAzureVPNFileRejectsInvalidFiles(t *testing.T) {
	directory := t.TempDir()
	emptyPath := filepath.Join(directory, "empty.xml")
	if err := os.WriteFile(emptyPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	largePath := filepath.Join(directory, "large.xml")
	file, err := os.Create(largePath)
	if err != nil {
		t.Fatal(err)
	}
	truncateErr := file.Truncate(azureProfileMaxBytes + 1)
	closeErr := file.Close()
	if truncateErr != nil || closeErr != nil {
		t.Fatal("could not create oversized test profile")
	}
	for _, path := range []string{"", "relative.xml", filepath.Join(directory, "missing.xml"), directory, emptyPath, largePath} {
		if result, err := importAzureVPNFile(azureImportRequest{Path: path}); err == nil || result.Settings != nil {
			t.Fatal("invalid import produced settings instead of an error")
		}
	}
}

func TestParseAzureVPNProfilePreservesMixedGatewayOrder(t *testing.T) {
	profile := strings.Replace(azureVPNClientExportFixture(), "<serverentry><fqdn>backup.vpn.azure.com</fqdn></serverentry>",
		"<ServerEntry><fqdn>backup.vpn.azure.com</fqdn></ServerEntry><extension><fqdn>ignored.vpn.azure.com</fqdn></extension>", 1)
	result, err := parseAzureVPNProfile([]byte(profile))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Settings["Servers"], []string{"primary.vpn.azure.com", "backup.vpn.azure.com"}) {
		t.Fatal("import changed gateway priority or accepted an unrelated XML entry")
	}
}
