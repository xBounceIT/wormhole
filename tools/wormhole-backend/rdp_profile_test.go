package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

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
