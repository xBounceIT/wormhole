package main

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAzureAdRdpIdentityUsesOnlyExplicitDomainOrPrefixSignals(t *testing.T) {
	for _, test := range []struct {
		username string
		domain   string
		expected bool
	}{
		{username: " AzureAD\\operator@example.com", expected: true},
		{username: "operator@example.onmicrosoft.com", expected: false},
		{domain: " azuread ", expected: true},
		{domain: "CONTOSO", expected: false},
	} {
		if actual := isAzureAdRdpIdentity(test.username, test.domain); actual != test.expected {
			t.Fatalf("identity (%q, %q) detected=%v, want %v", test.username, test.domain, actual, test.expected)
		}
	}
}

func TestAzureAdRdpRoutingStripsQuickConnectCredentialsAtTheGoBoundary(t *testing.T) {
	profile := rdpProfile{
		Username: "AzureAD\\operator@example.com", Password: "secret",
		GatewayUsername: "gateway-user", GatewayPassword: "gateway-secret",
	}
	if !enforceAzureAdRdpExternalClient(&profile, "windows") {
		t.Fatal("Azure AD Quick Connect profile was not routed externally")
	}
	if !profile.UseExternalClient || profile.Username != "" || profile.Password != "" ||
		profile.GatewayUsername != "" || profile.GatewayPassword != "" {
		t.Fatalf("system-client profile retained credential material: %#v", profile)
	}
	nonWindows := rdpProfile{
		Username: "AzureAD\\operator@example.com", Password: "secret", UseExternalClient: true,
	}
	if normalizeRdpExternalClientForOS(&nonWindows, "linux") || nonWindows.UseExternalClient || nonWindows.Password == "" {
		t.Fatalf("Windows-only system-client preference was not neutralized safely: %#v", nonWindows)
	}
}

func TestExplicitExternalRdpProfileNeverReturnsManualCredentials(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if err := ensureElectronWorkspaceSchema(databasePath); err != nil {
		t.Fatal(err)
	}
	settings := defaultWorkspaceRdpSettings()
	settings.UseExternalClient = true
	nodeID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		Name: "External desktop", Kind: "connection", Protocol: "rdp", Host: "external.example",
		CredentialMode: 1, InlinePasswordAction: "set", InlinePassword: "stored-secret", RDP: &settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	manager := &vncManager{database: database, databasePath: databasePath}
	profile, err := manager.resolveRdpRuntimeProfile(nodeID, &rdpManualCredential{
		Username: "operator", Domain: "CONTOSO", Password: "manual-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if !profile.UseExternalClient || profile.Username != "" || profile.Domain != "" || profile.Password != "" ||
			profile.GatewayUsername != "" || profile.GatewayPassword != "" {
			t.Fatalf("external RDP profile returned credential material: %#v", profile)
		}
	} else if profile.UseExternalClient || profile.Username != "operator" || profile.Domain != "CONTOSO" || profile.Password != "manual-secret" {
		t.Fatalf("non-Windows RDP profile did not fall back to FreeRDP credentials: %#v", profile)
	}
}

func TestAzureAdRdpCredentialForcesSystemClientBeforeSecretResolution(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the Azure AD ActiveX compatibility route is Windows-only")
	}
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if err := ensureElectronWorkspaceSchema(databasePath); err != nil {
		t.Fatal(err)
	}
	credential, err := createCredential(databasePath, credentialCreateRequest{
		Name: "Azure desktop", Protocol: "rdp", Username: "operator@example.com",
		Domain: "AzureAD", Password: "must-not-cross-the-system-client-boundary",
	})
	if err != nil {
		t.Fatal(err)
	}
	settings := defaultWorkspaceRdpSettings()
	nodeID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		Name: "Azure desktop", Kind: "connection", Protocol: "rdp", Host: "aad.example",
		CredentialMode: 2, CredentialID: credential.ID, RDP: &settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	manager := &vncManager{database: database, databasePath: databasePath}
	profile, err := manager.resolveRdpRuntimeProfile(nodeID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !profile.UseExternalClient || profile.Password != "" {
		t.Fatalf("Azure AD profile was not safely routed before secret resolution: %#v", profile)
	}
	var persisted bool
	if err := database.QueryRow(
		"SELECT COALESCE(RdpUseExternalClient, 0) <> 0 FROM Nodes WHERE Id = ?;",
		nodeID,
	).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if !persisted {
		t.Fatal("Azure AD routing requirement was not persisted on the connection")
	}
}

func TestRdpCredentialOverrideUsesSelectedIdentity(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if err := ensureElectronWorkspaceSchema(databasePath); err != nil {
		t.Fatal(err)
	}
	credential, err := createCredential(databasePath, credentialCreateRequest{
		Name: "Selected desktop", Protocol: "rdp", Username: "selected-user",
		Domain: "SELECTED", Password: "selected-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	settings := defaultWorkspaceRdpSettings()
	nodeID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		Name: "Desktop", Kind: "connection", Protocol: "rdp", Host: "rdp.example",
		Username: "connection-user", CredentialMode: 0, RDP: &settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	manager := &vncManager{database: database, databasePath: databasePath}
	profile, err := manager.resolveRdpRuntimeProfileWithCredential(nodeID, nil, credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Username != "selected-user" || profile.Domain != "SELECTED" ||
		profile.Password != "selected-secret" {
		t.Fatalf("selected RDP identity = %#v", profile)
	}
}

func completeRdpSettings() workspaceRdpSettings {
	return workspaceRdpSettings{
		Domain: "CONTOSO", ScreenSize: "1600x900", FullScreen: true, ColorDepth: 24,
		UseAllMonitors: true, AudioMode: 1, AudioCaptureMode: 1, KeyboardHookMode: 1,
		RedirectClipboard: true, RedirectPrinters: true, RedirectSmartCards: true,
		RedirectPorts: true, RedirectDevices: true, RedirectDrives: "c, d",
		ConnectionSpeed: 5, DesktopBackground: true, FontSmoothing: true,
		DesktopComposition: true, WindowDrag: true, MenuAnimation: true, VisualStyles: true,
		BitmapCaching: true, AutoReconnect: true, ServerAuthentication: 1,
		GatewayUsageMethod: 1, GatewayHostname: "gateway.example", GatewayBypassLocal: true,
		UseExternalClient: false,
	}
}

func TestWorkspaceRdpCreateLoadUpdateRoundTripAndSafeProjection(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if err := ensureElectronWorkspaceSchema(databasePath); err != nil {
		t.Fatal(err)
	}
	settings := completeRdpSettings()
	nodeID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		Name: "Production RDP", Kind: "connection", Protocol: "rdp", Host: "rdp.example",
		Port: 3391, Username: "operator", CredentialMode: 0, RDP: &settings,
	})
	if err != nil {
		t.Fatal(err)
	}

	workspace, err := loadWorkspace(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(workspace.Tree) != 1 {
		t.Fatalf("unexpected workspace tree: %#v", workspace.Tree)
	}
	node := workspace.Tree[0]
	if node.ID != nodeID || node.Port != 3391 || node.Username != "operator" || node.RDP == nil {
		t.Fatalf("RDP profile did not round trip: %#v", node)
	}
	if node.RDP.ScreenSize != "1600x900" || node.RDP.ColorDepth != 24 ||
		node.RDP.RedirectDrives != "C,D" || node.RDP.GatewayHostname != "gateway.example" {
		t.Fatalf("RDP settings did not round trip: %#v", node.RDP)
	}
	encoded, err := json.Marshal(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "password") || strings.Contains(string(encoded), "secret") {
		t.Fatalf("workspace projection exposed secret-shaped fields: %s", encoded)
	}

	settings.ScreenSize = "fitToWindow"
	settings.ColorDepth = 32
	if err := updateWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		ID: nodeID, Name: "Production RDP", Kind: "connection", Protocol: "rdp",
		Host: "rdp.example", Port: 3392, Username: "operator", CredentialMode: 0,
		InlinePasswordAction: "clear", RDP: &settings,
	}); err != nil {
		t.Fatal(err)
	}
	workspace, err = loadWorkspace(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Tree[0].Port != 3392 || workspace.Tree[0].RDP.ScreenSize != "fitToWindow" ||
		workspace.Tree[0].RDP.ColorDepth != 32 {
		t.Fatalf("updated RDP profile did not round trip: %#v", workspace.Tree[0])
	}
}

func TestResolveRdpRuntimeProfileUsesInheritedIdentityAndGatewayCredentials(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if err := ensureElectronWorkspaceSchema(databasePath); err != nil {
		t.Fatal(err)
	}
	connectionCredential, err := createCredential(databasePath, credentialCreateRequest{
		Name: "RDP account", Protocol: "rdp", Username: "vault-user", Domain: "VAULT",
		Password: "connection-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	gatewayCredential, err := createCredential(databasePath, credentialCreateRequest{
		Name: "Gateway account", Protocol: "rdp", Username: "gateway-user", Domain: "EDGE",
		Password: "gateway-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	folderID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{Name: "Inherited", Kind: "folder"})
	if err != nil {
		t.Fatal(err)
	}
	settings := completeRdpSettings()
	settings.GatewayCredentialID = gatewayCredential.ID
	leafID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		ParentID: folderID, Name: "Leaf", Kind: "connection", Protocol: "rdp",
		Host: "placeholder.example", CredentialMode: 0, RDP: &settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
UPDATE Nodes SET Protocol = 1, Host = 'inherited.example', Port = 3395, Username = 'node-user',
 CredentialMode = 2, CredentialId = ?, RdpDomain = 'NODE', RdpColorDepth = 16,
 RdpGatewayUsageMethod = 1, RdpGatewayHostname = 'gateway.example',
 RdpGatewayCredentialId = ?, RdpGatewayUseSameCreds = 0
WHERE Id = ?;`, connectionCredential.ID, gatewayCredential.ID, folderID)
	if err == nil {
		_, err = database.Exec(`UPDATE Nodes SET Protocol = NULL, Host = NULL, Port = NULL, Username = NULL,
 CredentialMode = NULL, CredentialId = NULL, RdpDomain = NULL, RdpColorDepth = NULL,
 RdpGatewayUsageMethod = NULL, RdpGatewayHostname = NULL, RdpGatewayCredentialId = NULL,
 RdpGatewayUseSameCreds = NULL
WHERE Id = ?;`, leafID)
	}
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	manager := &vncManager{database: database, databasePath: databasePath}
	profile, err := manager.resolveRdpRuntimeProfile(leafID, nil)
	database.Close()
	if err != nil {
		t.Fatal(err)
	}
	if profile.Host != "inherited.example" || profile.Port != 3395 || profile.Username != "node-user" ||
		profile.Domain != "NODE" || profile.Password != "connection-secret" || profile.ColorDepth != 16 {
		t.Fatalf("inherited connection profile was not resolved: %#v", profile)
	}
	if profile.GatewayHostname != "gateway.example" || profile.GatewayUsername != "EDGE\\gateway-user" ||
		profile.GatewayPassword != "gateway-secret" {
		t.Fatalf("gateway credentials were not resolved: %#v", profile)
	}
	database, err = openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	manager = &vncManager{database: database, databasePath: databasePath}
	manual, err := manager.resolveRdpRuntimeProfile(leafID, &rdpManualCredential{
		Username: "manual-user", Domain: "MANUAL", Password: "manual-secret",
	})
	database.Close()
	if err != nil {
		t.Fatal(err)
	}
	if manual.Username != "manual-user" || manual.Domain != "MANUAL" ||
		manual.Password != "manual-secret" || manual.ColorDepth != 16 || manual.Port != 3395 {
		t.Fatalf("manual retry did not preserve the resolved profile: %#v", manual)
	}
	workspace, err := loadWorkspace(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(workspace.Tree) != 1 || len(workspace.Tree[0].Children) != 1 {
		t.Fatalf("unexpected inherited workspace tree: %#v", workspace.Tree)
	}
	safeLeaf := workspace.Tree[0].Children[0]
	if safeLeaf.Host != "inherited.example" || safeLeaf.Port != 3395 || safeLeaf.Username != "node-user" ||
		safeLeaf.RDP == nil || safeLeaf.RDP.Domain != "NODE" {
		t.Fatalf("safe inherited identity was not projected: %#v", safeLeaf)
	}
}

func TestWorkspaceInlineRdpSecretSetPreserveClearAndNoRendererLeak(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if err := ensureElectronWorkspaceSchema(databasePath); err != nil {
		t.Fatal(err)
	}
	settings := defaultWorkspaceRdpSettings()
	nodeID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		Name: "Inline RDP", Kind: "connection", Protocol: "rdp", Host: "inline.example",
		Username: "inline-user", InlinePasswordAction: "set", InlinePassword: "inline-secret",
		RDP: &settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	manager := &vncManager{database: database, databasePath: databasePath}
	profile, err := manager.resolveRdpRuntimeProfile(nodeID, nil)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	if profile.Password != "inline-secret" || profile.Username != "inline-user" {
		database.Close()
		t.Fatalf("inline credential was not resolved: %#v", profile)
	}
	database.Close()
	externalSettings := settings
	externalSettings.UseExternalClient = true
	if err := updateWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		ID: nodeID, Name: "Inline RDP", Kind: "connection", Protocol: "rdp", Host: "inline.example",
		Username: "inline-user", InlinePasswordAction: "preserve", RDP: &externalSettings,
	}); err != nil {
		t.Fatal(err)
	}
	database, err = openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	manager = &vncManager{database: database, databasePath: databasePath}
	external, err := manager.resolveRdpRuntimeProfile(nodeID, nil)
	database.Close()
	if err != nil {
		t.Fatal(err)
	}
	if external.Password != "" || !external.UseExternalClient {
		t.Fatalf("external RDP profile unnecessarily exposed a password: %#v", external)
	}
	settings = externalSettings
	settings.UseExternalClient = false
	if err := updateWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		ID: nodeID, Name: "Inline RDP", Kind: "connection", Protocol: "rdp", Host: "inline.example",
		Username: "inline-user", InlinePasswordAction: "preserve", RDP: &settings,
	}); err != nil {
		t.Fatal(err)
	}
	database, err = openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	manager = &vncManager{database: database, databasePath: databasePath}
	systemProfile, err := manager.resolveRdpProfile(nodeID, nil, true, "")
	database.Close()
	if err != nil {
		t.Fatal(err)
	}
	if systemProfile.Username != "" || systemProfile.Domain != "" || systemProfile.Password != "" {
		t.Fatalf("system RDP profile crossed the Go boundary with credentials: %#v", systemProfile)
	}

	workspace, err := loadWorkspace(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(workspace)
	if strings.Contains(string(encoded), "inline-secret") || !workspace.Tree[0].HasInlineCredential {
		t.Fatalf("safe workspace projection is invalid: %s", encoded)
	}
	if err := updateWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		ID: nodeID, Name: "Renamed", Kind: "connection", Protocol: "rdp", Host: "inline.example",
		Username: "inline-user", InlinePasswordAction: "preserve", RDP: &settings,
	}); err != nil {
		t.Fatal(err)
	}
	if err := updateWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		ID: nodeID, Name: "Renamed", Kind: "connection", Protocol: "rdp", Host: "inline.example",
		Username: "inline-user", InlinePasswordAction: "clear", RDP: &settings,
	}); err != nil {
		t.Fatal(err)
	}
	database, err = openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM CredentialSecrets WHERE lower(Id) = ?;", nodeID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("cleared inline credential remained in protected storage")
	}
}

func TestWorkspaceRdpValidationAndLegacyFallbacks(t *testing.T) {
	settings := defaultWorkspaceRdpSettings()
	settings.ScreenSize = "639x480"
	if _, err := normalizeWorkspaceRdpSettings(&settings); err == nil {
		t.Fatal("accepted an undersized custom RDP display")
	}
	settings = defaultWorkspaceRdpSettings()
	settings.GatewayUsageMethod = 1
	settings.GatewayHostname = strings.Repeat("g", rdpMaxHostLength+1)
	if _, err := normalizeWorkspaceRdpSettings(&settings); err == nil {
		t.Fatal("accepted an oversized RDP Gateway hostname")
	}
	legacy := defaultWorkspaceRdpSettings()
	legacy.ScreenSize = "broken"
	legacy.ColorDepth = 7
	legacy.ConnectionSpeed = 99
	legacy.GatewayUsageMethod = 1
	legacy.GatewayHostname = ""
	normalized := normalizePersistedWorkspaceRdpSettings(legacy)
	defaults := defaultWorkspaceRdpSettings()
	if normalized.ScreenSize != defaults.ScreenSize || normalized.ColorDepth != defaults.ColorDepth ||
		normalized.ConnectionSpeed != defaults.ConnectionSpeed || normalized.GatewayUsageMethod != 0 {
		t.Fatalf("legacy fallbacks were not applied: %#v", normalized)
	}
}

func TestResolveRdpProfileOperationRejectsMalformedNodeIDs(t *testing.T) {
	if err := validateBackendCommand(backendCommand{
		ID: "request-1", Action: "rdp.resolve-profile", NodeID: "not-a-node-id",
	}); err == nil {
		t.Fatal("accepted a malformed RDP profile operation")
	}
	if err := validateBackendCommand(backendCommand{
		ID: "request-1", Action: "rdp.resolve-profile",
		NodeID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
	}); err != nil {
		t.Fatalf("rejected a valid RDP profile operation: %v", err)
	}
	if err := validateBackendCommand(backendCommand{
		ID: "request-1", Action: "rdp.resolve-profile",
		NodeID:       "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		CredentialID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
	}); err != nil {
		t.Fatalf("rejected a valid RDP credential override: %v", err)
	}
	if err := validateBackendCommand(backendCommand{
		ID: "request-1", Action: "rdp.resolve-profile",
		NodeID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ManualCredentials: true,
		CredentialID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Username: "user",
	}); err == nil {
		t.Fatal("accepted conflicting manual and saved RDP credential overrides")
	}
	if err := validateBackendCommand(backendCommand{
		ID: "request-1", Action: "rdp.resolve-system-profile",
		NodeID:       "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		CredentialID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
	}); err == nil {
		t.Fatal("accepted an ignored credential override for an RDP system-client operation")
	}
	if err := validateBackendCommand(backendCommand{
		ID: "request-1", Action: "rdp.resolve-profile",
		NodeID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ManualCredentials: true,
		Username: "user", Password: "secret\n/injected",
	}); err == nil {
		t.Fatal("accepted an injected manual RDP credential operation")
	}
}

func TestResolveRdpCredentialOperationDoesNotRequireSessionIdentity(t *testing.T) {
	if err := validateBackendCommand(backendCommand{
		ID: "request-1", Action: "rdp.resolve-credential",
		CredentialID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
	}); err != nil {
		t.Fatalf("rejected a valid RDP credential operation: %v", err)
	}
	if err := validateBackendCommand(backendCommand{
		ID: "request-1", Action: "rdp.resolve-credential", CredentialID: "not-a-credential",
	}); err == nil {
		t.Fatal("accepted an invalid RDP credential operation")
	}
}
