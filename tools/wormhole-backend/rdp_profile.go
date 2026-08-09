package main

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"
)

const rdpProtocolValue = int64(1)

var rdpCustomSizePattern = regexp.MustCompile(`^(\d{3,5})[xX](\d{3,5})$`)
var rdpDriveListPattern = regexp.MustCompile(`^[A-Za-z](?:\s*,\s*[A-Za-z])*$`)

// workspaceRdpSettings is safe workspace metadata. Passwords are intentionally absent and are
// resolved only in the Go runtime profile immediately before a connection starts.
type workspaceRdpSettings struct {
	Domain               string `json:"domain"`
	ScreenSize           string `json:"screenSize"`
	FullScreen           bool   `json:"fullScreen"`
	ColorDepth           int    `json:"colorDepth"`
	UseAllMonitors       bool   `json:"useAllMonitors"`
	AudioMode            int    `json:"audioMode"`
	AudioCaptureMode     int    `json:"audioCaptureMode"`
	KeyboardHookMode     int    `json:"keyboardHookMode"`
	RedirectClipboard    bool   `json:"redirectClipboard"`
	RedirectPrinters     bool   `json:"redirectPrinters"`
	RedirectSmartCards   bool   `json:"redirectSmartCards"`
	RedirectPorts        bool   `json:"redirectPorts"`
	RedirectDevices      bool   `json:"redirectDevices"`
	RedirectDrives       string `json:"redirectDrives"`
	ConnectionSpeed      int    `json:"connectionSpeed"`
	DesktopBackground    bool   `json:"desktopBackground"`
	FontSmoothing        bool   `json:"fontSmoothing"`
	DesktopComposition   bool   `json:"desktopComposition"`
	WindowDrag           bool   `json:"windowDrag"`
	MenuAnimation        bool   `json:"menuAnimation"`
	VisualStyles         bool   `json:"visualStyles"`
	BitmapCaching        bool   `json:"bitmapCaching"`
	AutoReconnect        bool   `json:"autoReconnect"`
	ServerAuthentication int    `json:"serverAuthentication"`
	GatewayUsageMethod   int    `json:"gatewayUsageMethod"`
	GatewayHostname      string `json:"gatewayHostname"`
	GatewayCredentialID  string `json:"gatewayCredentialId"`
	GatewayBypassLocal   bool   `json:"gatewayBypassLocal"`
	GatewayUseSameCreds  bool   `json:"gatewayUseSameCreds"`
	UseExternalClient    bool   `json:"useExternalClient"`
}

type rdpManualCredential struct {
	Username string
	Domain   string
	Password string
}

type rdpExternalClientRequirementRequest struct {
	Username            string `json:"username"`
	Domain              string `json:"domain"`
	CredentialID        string `json:"credentialId"`
	InheritedFromNodeID string `json:"inheritedFromNodeId"`
}

type rdpExternalClientRequirementResponse struct {
	Required bool `json:"required"`
}

func isAzureAdRdpIdentity(username, domain string) bool {
	return strings.EqualFold(strings.TrimSpace(domain), "AzureAD") ||
		strings.HasPrefix(strings.ToLower(strings.TrimLeftFunc(username, unicode.IsSpace)), "azuread\\")
}

func enforceAzureAdRdpExternalClient(profile *rdpProfile, operatingSystem string) bool {
	if profile == nil || operatingSystem != "windows" || !isAzureAdRdpIdentity(profile.Username, profile.Domain) {
		return false
	}
	profile.UseExternalClient = true
	clearRdpExternalClientCredentials(profile)
	return true
}

func clearRdpExternalClientCredentials(profile *rdpProfile) {
	if profile == nil {
		return
	}
	profile.Username = ""
	profile.Domain = ""
	profile.Password = ""
	profile.GatewayUsername = ""
	profile.GatewayPassword = ""
}

func rdpExternalClientRequirement(
	databasePath string,
	request rdpExternalClientRequirementRequest,
) (rdpExternalClientRequirementResponse, error) {
	if !validRdpText(request.Username, 512) || !validRdpText(request.Domain, 512) {
		return rdpExternalClientRequirementResponse{}, errors.New("RDP external-client requirement is invalid")
	}
	credentialID := normalizeID(request.CredentialID)
	inheritedFromNodeID := normalizeID(request.InheritedFromNodeID)
	if (credentialID != "" && !validCredentialID(credentialID)) ||
		(inheritedFromNodeID != "" && !validCredentialID(inheritedFromNodeID)) ||
		(credentialID != "" && inheritedFromNodeID != "") {
		return rdpExternalClientRequirementResponse{}, errors.New("RDP external-client requirement is invalid")
	}
	if runtime.GOOS != "windows" {
		return rdpExternalClientRequirementResponse{}, nil
	}
	if isAzureAdRdpIdentity(request.Username, request.Domain) {
		return rdpExternalClientRequirementResponse{Required: true}, nil
	}
	if credentialID == "" && inheritedFromNodeID == "" {
		return rdpExternalClientRequirementResponse{}, nil
	}
	database, err := openDatabase(databasePath, true)
	if err != nil {
		return rdpExternalClientRequirementResponse{}, err
	}
	if database == nil {
		return rdpExternalClientRequirementResponse{}, errors.New("RDP credential storage is unavailable")
	}
	defer database.Close()
	return rdpExternalClientRequirementFromDatabase(database, request)
}

func rdpExternalClientRequirementFromDatabase(
	database *sql.DB,
	request rdpExternalClientRequirementRequest,
) (rdpExternalClientRequirementResponse, error) {
	required := runtime.GOOS == "windows" && isAzureAdRdpIdentity(request.Username, request.Domain)
	if runtime.GOOS != "windows" || required {
		return rdpExternalClientRequirementResponse{Required: required}, nil
	}
	credentialID := normalizeID(request.CredentialID)
	if credentialID == "" && strings.TrimSpace(request.InheritedFromNodeID) != "" {
		var err error
		credentialID, err = resolveNodeCredentialID(database, request.InheritedFromNodeID, rdpProtocolValue)
		if err != nil {
			return rdpExternalClientRequirementResponse{}, err
		}
	}
	if credentialID == "" {
		return rdpExternalClientRequirementResponse{}, nil
	}
	username, domain, found, err := resolveRdpCredentialIdentityMetadata(database, credentialID)
	if err != nil {
		return rdpExternalClientRequirementResponse{}, err
	}
	if !found {
		return rdpExternalClientRequirementResponse{}, nil
	}
	return rdpExternalClientRequirementResponse{Required: isAzureAdRdpIdentity(username, domain)}, nil
}

func resolveRdpCredentialIdentityMetadata(
	database *sql.DB,
	credentialID string,
) (string, string, bool, error) {
	var username, domain sql.NullString
	var protocol sql.NullInt64
	err := database.QueryRow(`
SELECT Username, Domain, Protocol
FROM CredentialProfiles WHERE lower(Id) = ? LIMIT 1;`, normalizeID(credentialID)).
		Scan(&username, &domain, &protocol)
	if err == nil {
		if protocol.Valid && protocol.Int64 != rdpProtocolValue {
			return "", "", false, nil
		}
		return strings.TrimSpace(nullableString(username)), strings.TrimSpace(nullableString(domain)), true, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) && !strings.Contains(strings.ToLower(err.Error()), "no such table") {
		return "", "", false, fmt.Errorf("could not read RDP credential metadata: %w", err)
	}
	reference, found, err := resolveBitwardenCredentialReference(database, credentialID, rdpProtocolValue)
	if err != nil || !found {
		return "", "", found, err
	}
	return reference.Username, reference.Domain, true, nil
}

func defaultWorkspaceRdpSettings() workspaceRdpSettings {
	return workspaceRdpSettings{
		ScreenSize: "fitToWindow", ColorDepth: 32, KeyboardHookMode: 2,
		RedirectClipboard: true, ConnectionSpeed: 7, DesktopBackground: true,
		FontSmoothing: true, DesktopComposition: true, WindowDrag: true,
		MenuAnimation: true, VisualStyles: true, BitmapCaching: true,
		AutoReconnect: true, ServerAuthentication: 2, GatewayBypassLocal: true,
	}
}

func normalizeWorkspaceRdpSettings(value *workspaceRdpSettings) (workspaceRdpSettings, error) {
	if value == nil {
		return defaultWorkspaceRdpSettings(), nil
	}
	settings := *value
	settings.Domain = strings.TrimSpace(settings.Domain)
	settings.ScreenSize = strings.TrimSpace(settings.ScreenSize)
	settings.GatewayHostname = strings.TrimSpace(settings.GatewayHostname)
	settings.GatewayCredentialID = normalizeID(settings.GatewayCredentialID)
	settings.RedirectDrives = normalizeRdpDriveList(settings.RedirectDrives)
	if settings.ScreenSize == "" {
		settings.ScreenSize = "fitToWindow"
	}
	if !validRdpScreenSize(settings.ScreenSize) || !validRdpText(settings.Domain, 512) ||
		(settings.GatewayHostname != "" && !validRdpHostText(settings.GatewayHostname)) {
		return workspaceRdpSettings{}, errors.New("RDP text settings are invalid")
	}
	if settings.GatewayUsageMethod == 1 && settings.GatewayHostname == "" {
		return workspaceRdpSettings{}, errors.New("RDP Gateway hostname is required")
	}
	if settings.GatewayCredentialID != "" && !validCredentialID(settings.GatewayCredentialID) {
		return workspaceRdpSettings{}, errors.New("RDP Gateway credential id is invalid")
	}
	if !containsRdpInt([]int{15, 16, 24, 32}, settings.ColorDepth) ||
		settings.AudioMode < 0 || settings.AudioMode > 2 ||
		settings.AudioCaptureMode < 0 || settings.AudioCaptureMode > 1 ||
		settings.KeyboardHookMode < 0 || settings.KeyboardHookMode > 2 ||
		settings.ConnectionSpeed < 1 || settings.ConnectionSpeed > 7 ||
		settings.ServerAuthentication < 0 || settings.ServerAuthentication > 2 ||
		settings.GatewayUsageMethod < 0 || settings.GatewayUsageMethod > 3 {
		return workspaceRdpSettings{}, errors.New("RDP numeric settings are invalid")
	}
	if settings.RedirectDrives != "" && settings.RedirectDrives != "all" &&
		(!rdpDriveListPattern.MatchString(settings.RedirectDrives) || len(settings.RedirectDrives) > 128) {
		return workspaceRdpSettings{}, errors.New("RDP drive redirection is invalid")
	}
	return settings, nil
}

func validRdpText(value string, maximum int) bool {
	return utf8.RuneCountInString(value) <= maximum && !strings.ContainsAny(value, "\r\n\x00")
}

func validRdpHostText(value string) bool {
	return validRdpText(value, rdpMaxHostLength) && !strings.ContainsFunc(value, func(character rune) bool {
		return unicode.IsControl(character) || unicode.IsSpace(character)
	})
}

func validRdpScreenSize(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "fittowindow", "full connection content", "full screen":
		return true
	}
	match := rdpCustomSizePattern.FindStringSubmatch(value)
	if len(match) != 3 {
		return false
	}
	var width, height int
	_, widthErr := fmt.Sscan(match[1], &width)
	_, heightErr := fmt.Sscan(match[2], &height)
	return widthErr == nil && heightErr == nil && width >= 640 && width <= 16384 && height >= 480 && height <= 16384
}

func normalizeRdpDriveList(value string) string {
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, "all") {
		return "all"
	}
	if value == "" {
		return ""
	}
	parts := strings.Split(value, ",")
	for index := range parts {
		parts[index] = strings.ToUpper(strings.TrimSpace(parts[index]))
	}
	return strings.Join(parts, ",")
}

func containsRdpInt(values []int, candidate int) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

var rdpInheritedColumns = []string{
	"Id", "ParentId", "Name", "Kind", "Protocol", "Host", "Port", "Username",
	"CredentialId", "CredentialMode", "UseInlinePassword", "TunnelEnabled", "TunnelConfigId",
	"RdpDomain", "RdpScreenSize", "RdpFullScreen", "RdpColorDepth", "RdpUseAllMonitors",
	"RdpAudioMode", "RdpAudioCaptureMode", "RdpKeyboardHookMode", "RdpRedirectClipboard",
	"RdpRedirectPrinters", "RdpRedirectSmartCards", "RdpRedirectPorts", "RdpRedirectDevices",
	"RdpRedirectDrives", "RdpConnectionSpeed", "RdpDesktopBackground", "RdpFontSmoothing",
	"RdpDesktopComposition", "RdpWindowDrag", "RdpMenuAnimation", "RdpVisualStyles",
	"RdpBitmapCaching", "RdpAutoReconnect", "RdpServerAuthentication", "RdpGatewayUsageMethod",
	"RdpGatewayHostname", "RdpGatewayCredentialId", "RdpGatewayBypassLocal",
	"RdpGatewayUseSameCreds", "RdpUseExternalClient",
}

func loadRdpNodeChain(database *sql.DB, nodeID string) ([]map[string]any, error) {
	columns, err := tableColumns(database, "Nodes")
	if err != nil {
		return nil, err
	}
	if len(columns) == 0 {
		return nil, errors.New("Wormhole database has no connections")
	}
	expressions := make([]string, len(rdpInheritedColumns))
	for index, name := range rdpInheritedColumns {
		expressions[index] = workspaceColumnExpression(columns, name)
	}
	query := "SELECT " + strings.Join(expressions, ", ") + " FROM Nodes WHERE lower(Id) = ? LIMIT 1;"
	current := normalizeID(nodeID)
	seen := map[string]struct{}{}
	chain := make([]map[string]any, 0, 4)
	for current != "" {
		if _, duplicate := seen[current]; duplicate {
			return nil, errors.New("RDP connection tree contains a cycle")
		}
		seen[current] = struct{}{}
		values := make([]any, len(rdpInheritedColumns))
		destinations := make([]any, len(values))
		for index := range values {
			destinations[index] = &values[index]
		}
		if err := database.QueryRow(query, current).Scan(destinations...); err != nil {
			if errors.Is(err, sql.ErrNoRows) && len(chain) == 0 {
				return nil, errors.New("RDP connection was not found")
			}
			if errors.Is(err, sql.ErrNoRows) {
				break
			}
			return nil, fmt.Errorf("could not resolve RDP connection: %w", err)
		}
		row := make(map[string]any, len(values))
		for index, name := range rdpInheritedColumns {
			row[name] = values[index]
		}
		chain = append(chain, row)
		current = normalizeID(workspaceNodeValueString(row["ParentId"]))
	}
	return chain, nil
}

func workspaceRdpSettingsFromChain(chain []map[string]any) workspaceRdpSettings {
	settings := defaultWorkspaceRdpSettings()
	resolved := map[string]bool{}
	resolveString := func(row map[string]any, column string, target *string) {
		if resolved[column] || row[column] == nil {
			return
		}
		*target = strings.TrimSpace(workspaceNodeValueString(row[column]))
		resolved[column] = true
	}
	resolveInt := func(row map[string]any, column string, target *int) {
		if resolved[column] || row[column] == nil {
			return
		}
		if value, ok := workspaceNodeValueInt64(row[column]); ok {
			*target = int(value)
			resolved[column] = true
		}
	}
	resolveBool := func(row map[string]any, column string, target *bool) {
		if resolved[column] {
			return
		}
		var value int
		resolveInt(row, column, &value)
		if resolved[column] {
			*target = value != 0
		}
	}
	for _, row := range chain {
		resolveString(row, "RdpDomain", &settings.Domain)
		resolveString(row, "RdpScreenSize", &settings.ScreenSize)
		resolveBool(row, "RdpFullScreen", &settings.FullScreen)
		resolveInt(row, "RdpColorDepth", &settings.ColorDepth)
		resolveBool(row, "RdpUseAllMonitors", &settings.UseAllMonitors)
		resolveInt(row, "RdpAudioMode", &settings.AudioMode)
		resolveInt(row, "RdpAudioCaptureMode", &settings.AudioCaptureMode)
		resolveInt(row, "RdpKeyboardHookMode", &settings.KeyboardHookMode)
		resolveBool(row, "RdpRedirectClipboard", &settings.RedirectClipboard)
		resolveBool(row, "RdpRedirectPrinters", &settings.RedirectPrinters)
		resolveBool(row, "RdpRedirectSmartCards", &settings.RedirectSmartCards)
		resolveBool(row, "RdpRedirectPorts", &settings.RedirectPorts)
		resolveBool(row, "RdpRedirectDevices", &settings.RedirectDevices)
		resolveString(row, "RdpRedirectDrives", &settings.RedirectDrives)
		resolveInt(row, "RdpConnectionSpeed", &settings.ConnectionSpeed)
		resolveBool(row, "RdpDesktopBackground", &settings.DesktopBackground)
		resolveBool(row, "RdpFontSmoothing", &settings.FontSmoothing)
		resolveBool(row, "RdpDesktopComposition", &settings.DesktopComposition)
		resolveBool(row, "RdpWindowDrag", &settings.WindowDrag)
		resolveBool(row, "RdpMenuAnimation", &settings.MenuAnimation)
		resolveBool(row, "RdpVisualStyles", &settings.VisualStyles)
		resolveBool(row, "RdpBitmapCaching", &settings.BitmapCaching)
		resolveBool(row, "RdpAutoReconnect", &settings.AutoReconnect)
		resolveInt(row, "RdpServerAuthentication", &settings.ServerAuthentication)
		resolveInt(row, "RdpGatewayUsageMethod", &settings.GatewayUsageMethod)
		resolveString(row, "RdpGatewayHostname", &settings.GatewayHostname)
		resolveString(row, "RdpGatewayCredentialId", &settings.GatewayCredentialID)
		resolveBool(row, "RdpGatewayBypassLocal", &settings.GatewayBypassLocal)
		resolveBool(row, "RdpGatewayUseSameCreds", &settings.GatewayUseSameCreds)
		resolveBool(row, "RdpUseExternalClient", &settings.UseExternalClient)
	}
	settings.RedirectDrives = normalizeRdpDriveList(settings.RedirectDrives)
	return normalizePersistedWorkspaceRdpSettings(settings)
}

// Older rows can contain values written by versions that did not validate RDP settings. Reads
// preserve every valid value while applying the documented defaults to malformed legacy fields;
// new writes remain strict through normalizeWorkspaceRdpSettings.
func normalizePersistedWorkspaceRdpSettings(settings workspaceRdpSettings) workspaceRdpSettings {
	defaults := defaultWorkspaceRdpSettings()
	if !validRdpText(settings.Domain, 512) {
		settings.Domain = defaults.Domain
	}
	if !validRdpScreenSize(settings.ScreenSize) {
		settings.ScreenSize = defaults.ScreenSize
	}
	if !containsRdpInt([]int{15, 16, 24, 32}, settings.ColorDepth) {
		settings.ColorDepth = defaults.ColorDepth
	}
	if settings.AudioMode < 0 || settings.AudioMode > 2 {
		settings.AudioMode = defaults.AudioMode
	}
	if settings.AudioCaptureMode < 0 || settings.AudioCaptureMode > 1 {
		settings.AudioCaptureMode = defaults.AudioCaptureMode
	}
	if settings.KeyboardHookMode < 0 || settings.KeyboardHookMode > 2 {
		settings.KeyboardHookMode = defaults.KeyboardHookMode
	}
	if settings.ConnectionSpeed < 1 || settings.ConnectionSpeed > 7 {
		settings.ConnectionSpeed = defaults.ConnectionSpeed
	}
	if settings.ServerAuthentication < 0 || settings.ServerAuthentication > 2 {
		settings.ServerAuthentication = defaults.ServerAuthentication
	}
	if settings.GatewayUsageMethod < 0 || settings.GatewayUsageMethod > 3 ||
		(settings.GatewayUsageMethod == 1 && strings.TrimSpace(settings.GatewayHostname) == "") {
		settings.GatewayUsageMethod = defaults.GatewayUsageMethod
	}
	if settings.GatewayHostname != "" && !validRdpHostText(settings.GatewayHostname) {
		settings.GatewayHostname = defaults.GatewayHostname
		settings.GatewayUsageMethod = defaults.GatewayUsageMethod
	}
	if settings.GatewayCredentialID != "" && !validCredentialID(settings.GatewayCredentialID) {
		settings.GatewayCredentialID = defaults.GatewayCredentialID
	}
	if settings.RedirectDrives != "" && settings.RedirectDrives != "all" &&
		(!rdpDriveListPattern.MatchString(settings.RedirectDrives) || len(settings.RedirectDrives) > 128) {
		settings.RedirectDrives = defaults.RedirectDrives
	}
	return settings
}

func workspaceRdpTargetFromChain(chain []map[string]any) (string, int) {
	host := ""
	port := 0
	for _, row := range chain {
		if host == "" && row["Host"] != nil {
			host = strings.TrimSpace(workspaceNodeValueString(row["Host"]))
		}
		if port == 0 && row["Port"] != nil {
			if value, ok := workspaceNodeValueInt64(row["Port"]); ok {
				port = int(value)
			}
		}
	}
	return host, port
}

func (m *vncManager) resolveRdpRuntimeProfile(nodeID string, manual *rdpManualCredential) (rdpProfile, error) {
	return m.resolveRdpProfile(nodeID, manual, false, "")
}

func (m *vncManager) resolveRdpRuntimeProfileWithCredential(
	nodeID string,
	manual *rdpManualCredential,
	credentialID string,
) (rdpProfile, error) {
	return m.resolveRdpProfile(nodeID, manual, false, credentialID)
}

func (m *vncManager) resolveRdpSystemClientProfile(nodeID string) (rdpProfile, rdpSystemClientCapability, error) {
	profile, err := m.resolveRdpProfile(nodeID, nil, true, "")
	if err != nil {
		return rdpProfile{}, rdpSystemClientCapability{}, err
	}
	_, tunnelEnabled, err := resolveNodeTunnel(m.databasePath, nodeID)
	if err != nil {
		return rdpProfile{}, rdpSystemClientCapability{}, err
	}
	capability := evaluateRdpSystemClientCapability(profile, tunnelEnabled, runtime.GOOS, systemRdpClientExecutable)
	if capability.Supported {
		profile.UseExternalClient = true
	}
	return profile, capability, nil
}

func resolveRdpSystemClientProfileFromDatabase(
	databasePath string,
	nodeID string,
) (rdpProfile, rdpSystemClientCapability, error) {
	database, err := openDatabase(databasePath, true)
	if err != nil {
		return rdpProfile{}, rdpSystemClientCapability{}, err
	}
	if database == nil {
		return rdpProfile{}, rdpSystemClientCapability{}, errors.New("RDP connection was not found")
	}
	defer database.Close()
	manager := &vncManager{database: database, databasePath: databasePath}
	return manager.resolveRdpSystemClientProfile(nodeID)
}

func (m *vncManager) resolveRdpProfile(
	nodeID string,
	manual *rdpManualCredential,
	forSystemClient bool,
	credentialIDOverride string,
) (rdpProfile, error) {
	chain, err := loadRdpNodeChain(m.database, nodeID)
	if err != nil {
		return rdpProfile{}, err
	}
	if kind, ok := workspaceNodeValueInt64(chain[0]["Kind"]); !ok || kind != workspaceNodeConnection {
		return rdpProfile{}, errors.New("RDP target is not a connection")
	}
	firstString := func(column string) string {
		for _, row := range chain {
			if row[column] != nil {
				return strings.TrimSpace(workspaceNodeValueString(row[column]))
			}
		}
		return ""
	}
	firstInt := func(column string) (int, bool) {
		for _, row := range chain {
			if row[column] == nil {
				continue
			}
			value, ok := workspaceNodeValueInt64(row[column])
			return int(value), ok
		}
		return 0, false
	}
	protocol, protocolFound := firstInt("Protocol")
	if !protocolFound || int64(protocol) != rdpProtocolValue {
		return rdpProfile{}, errors.New("connection is not an RDP profile")
	}
	host, port := workspaceRdpTargetFromChain(chain)
	host, port, err = normalizeRdpTarget(host, port)
	if err != nil {
		return rdpProfile{}, err
	}
	settings := workspaceRdpSettingsFromChain(chain)
	username, domain, err := resolveNodeRdpIdentity(m.database, nodeID)
	if err != nil {
		return rdpProfile{}, err
	}
	profile := rdpProfile{
		NodeID: nodeID, Name: firstString("Name"), Host: host, Port: port,
		Username: username, Domain: domain, ScreenSize: settings.ScreenSize,
		FullScreen: settings.FullScreen, ColorDepth: settings.ColorDepth,
		UseAllMonitors: settings.UseAllMonitors, AudioMode: settings.AudioMode,
		AudioCaptureMode: settings.AudioCaptureMode, KeyboardHookMode: settings.KeyboardHookMode,
		RedirectClipboard: settings.RedirectClipboard, RedirectPrinters: settings.RedirectPrinters,
		RedirectSmartCards: settings.RedirectSmartCards, RedirectPorts: settings.RedirectPorts,
		RedirectDevices: settings.RedirectDevices, RedirectDrives: settings.RedirectDrives,
		ConnectionSpeed: settings.ConnectionSpeed, DesktopBackground: settings.DesktopBackground,
		FontSmoothing: settings.FontSmoothing, DesktopComposition: settings.DesktopComposition,
		WindowDrag: settings.WindowDrag, MenuAnimation: settings.MenuAnimation,
		VisualStyles: settings.VisualStyles, BitmapCaching: settings.BitmapCaching,
		AutoReconnect: settings.AutoReconnect, ServerAuthentication: rdpIntPointer(settings.ServerAuthentication),
		GatewayUsageMethod: settings.GatewayUsageMethod, GatewayHostname: settings.GatewayHostname,
		GatewayBypassLocal: settings.GatewayBypassLocal, GatewayUseSameCreds: settings.GatewayUseSameCreds,
		UseExternalClient: settings.UseExternalClient,
	}
	if enabled, ok := firstInt("TunnelEnabled"); ok {
		value := enabled != 0
		profile.TunnelEnabled = &value
	}
	profile.TunnelConfigID = normalizeTunnelID(firstString("TunnelConfigId"))
	var credentialID string
	credentialID = normalizeID(credentialIDOverride)
	credentialOverride := credentialID != ""
	if manual != nil {
		profile.Username = strings.TrimSpace(manual.Username)
		profile.Domain = strings.TrimSpace(manual.Domain)
		profile.Password = manual.Password
	} else if credentialID == "" && !profile.UseExternalClient && !forSystemClient {
		credentialID, err = resolveNodeCredentialID(m.database, nodeID, rdpProtocolValue)
		if err != nil {
			return rdpProfile{}, err
		}
	}
	if !profile.UseExternalClient && !forSystemClient {
		requirement, requirementErr := rdpExternalClientRequirementFromDatabase(m.database, rdpExternalClientRequirementRequest{
			Username: profile.Username, Domain: profile.Domain, CredentialID: credentialID,
		})
		if requirementErr != nil {
			return rdpProfile{}, requirementErr
		}
		profile.UseExternalClient = requirement.Required
	}
	if profile.UseExternalClient || forSystemClient {
		// The system client has no supported secret-bearing launch contract. Do not resolve or
		// return credentials that mstsc cannot consume; Windows will use its own credential UI.
		clearRdpExternalClientCredentials(&profile)
		return profile, nil
	}

	if manual == nil {
		inline, _ := workspaceNodeValueInt64(chain[0]["UseInlinePassword"])
		if inline != 0 {
			if secret, found, secretErr := readStoredSecret(m.database, nodeID, m.electronUserDataPath); secretErr != nil {
				return rdpProfile{}, fmt.Errorf("inline RDP credential is unavailable: %w", secretErr)
			} else if found {
				profile.Password = secret
			}
		} else if credentialID != "" {
			credential, credentialErr := m.resolveRdpCredential(credentialID)
			if credentialErr != nil {
				return rdpProfile{}, credentialErr
			}
			if credentialOverride || profile.Username == "" {
				profile.Username = credential.Username
			}
			if credentialOverride || profile.Domain == "" {
				profile.Domain = credential.Domain
			}
			profile.Password = credential.Password
		}
	}
	if profile.Domain == "" {
		profile.Username, profile.Domain = splitRdpDomainUsername(profile.Username)
	}

	if settings.GatewayUsageMethod != 0 {
		if settings.GatewayUseSameCreds {
			profile.GatewayUsername = profile.Username
			profile.GatewayPassword = profile.Password
		} else if settings.GatewayCredentialID != "" {
			gateway, gatewayErr := m.resolveRdpCredential(settings.GatewayCredentialID)
			if gatewayErr != nil {
				return rdpProfile{}, fmt.Errorf("RDP Gateway credential is unavailable: %w", gatewayErr)
			}
			profile.GatewayUsername = gateway.Username
			if gateway.Domain != "" && !strings.Contains(gateway.Username, "\\") {
				profile.GatewayUsername = gateway.Domain + "\\" + gateway.Username
			}
			profile.GatewayPassword = gateway.Password
		}
	}
	return profile, nil
}

func rdpIntPointer(value int) *int { return &value }

func (m *vncManager) resolveRdpCredential(credentialID string) (bitwardenResolvedCredential, error) {
	resolved, err := m.resolveBitwardenCredentialRaw(credentialID, rdpProtocolValue)
	if err != nil || resolved.Bitwarden {
		return resolved, err
	}
	var username, domain sql.NullString
	var protocol, kind, provider sql.NullInt64
	err = m.database.QueryRow(`
SELECT Username, Domain, Protocol, Kind, COALESCE(SecretProvider, 0)
FROM CredentialProfiles WHERE lower(Id) = ? LIMIT 1;`, normalizeID(credentialID)).
		Scan(&username, &domain, &protocol, &kind, &provider)
	if errors.Is(err, sql.ErrNoRows) {
		return bitwardenResolvedCredential{}, errors.New("RDP credential was not found")
	}
	if err != nil {
		return bitwardenResolvedCredential{}, fmt.Errorf("could not read RDP credential: %w", err)
	}
	if !protocol.Valid || protocol.Int64 != rdpProtocolValue || (kind.Valid && kind.Int64 != 0) ||
		(provider.Valid && provider.Int64 != 0) {
		return bitwardenResolvedCredential{}, errors.New("RDP credential type is invalid")
	}
	secret, found, err := readStoredSecret(m.database, credentialID, m.electronUserDataPath)
	if err != nil {
		return bitwardenResolvedCredential{}, fmt.Errorf("stored RDP credential is unavailable: %w", err)
	}
	if !found {
		return bitwardenResolvedCredential{}, errors.New("stored RDP credential password is missing")
	}
	return bitwardenResolvedCredential{
		Username: strings.TrimSpace(nullableString(username)),
		Domain:   strings.TrimSpace(nullableString(domain)), Password: secret,
	}, nil
}

func workspaceRdpDatabaseValues(settings *workspaceRdpSettings) []any {
	if settings == nil {
		return make([]any, 30)
	}
	return []any{
		nullableWorkspaceNodeString(settings.Domain), settings.ScreenSize,
		workspaceNodeBoolean(&settings.FullScreen), settings.ColorDepth,
		workspaceNodeBoolean(&settings.UseAllMonitors), settings.AudioMode,
		settings.AudioCaptureMode, settings.KeyboardHookMode,
		workspaceNodeBoolean(&settings.RedirectClipboard), workspaceNodeBoolean(&settings.RedirectPrinters),
		workspaceNodeBoolean(&settings.RedirectSmartCards), workspaceNodeBoolean(&settings.RedirectPorts),
		workspaceNodeBoolean(&settings.RedirectDevices), settings.RedirectDrives, settings.ConnectionSpeed,
		workspaceNodeBoolean(&settings.DesktopBackground), workspaceNodeBoolean(&settings.FontSmoothing),
		workspaceNodeBoolean(&settings.DesktopComposition), workspaceNodeBoolean(&settings.WindowDrag),
		workspaceNodeBoolean(&settings.MenuAnimation), workspaceNodeBoolean(&settings.VisualStyles),
		workspaceNodeBoolean(&settings.BitmapCaching), workspaceNodeBoolean(&settings.AutoReconnect),
		settings.ServerAuthentication, settings.GatewayUsageMethod,
		nullableWorkspaceNodeString(settings.GatewayHostname), nullableWorkspaceNodeString(settings.GatewayCredentialID),
		workspaceNodeBoolean(&settings.GatewayBypassLocal), workspaceNodeBoolean(&settings.GatewayUseSameCreds),
		workspaceNodeBoolean(&settings.UseExternalClient),
	}
}

type workspaceInlineSecretChange struct {
	id               string
	newEncoded       string
	newEncoding      string
	previousEncoded  string
	previousEncoding string
	committed        bool
}

func prepareWorkspaceInlineSecret(tx *sql.Tx, node normalizedWorkspaceNode, updating bool) (*workspaceInlineSecretChange, error) {
	change := &workspaceInlineSecretChange{id: node.id}
	if node.inlinePasswordAction == "preserve" {
		var enabled sql.NullInt64
		if !updating {
			return change, errors.New("a new connection cannot preserve an inline password")
		}
		if err := tx.QueryRow("SELECT UseInlinePassword FROM Nodes WHERE lower(Id) = ?;", node.id).Scan(&enabled); err != nil {
			return change, fmt.Errorf("could not inspect inline password state: %w", err)
		}
		if !enabled.Valid || enabled.Int64 == 0 {
			return change, errors.New("the connection has no inline password to preserve")
		}
		return change, nil
	}
	var previousEncoded, previousEncoding sql.NullString
	err := tx.QueryRow("SELECT Secret, Encoding FROM CredentialSecrets WHERE lower(Id) = ? LIMIT 1;", node.id).
		Scan(&previousEncoded, &previousEncoding)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return change, fmt.Errorf("could not inspect the previous inline password: %w", err)
	}
	change.previousEncoded = nullableString(previousEncoded)
	change.previousEncoding = nullableString(previousEncoding)
	if node.inlinePasswordAction == "clear" {
		if _, err := tx.Exec("DELETE FROM CredentialSecrets WHERE lower(Id) = ?;", node.id); err != nil {
			return change, fmt.Errorf("could not clear inline password: %w", err)
		}
		return change, nil
	}
	encoded, encoding, err := credentialSecretStore(node.id, node.inlinePassword)
	if err != nil {
		return change, errors.New("could not protect the inline password")
	}
	change.newEncoded, change.newEncoding = encoded, encoding
	if err := upsertCredentialSecret(tx, node.id, encoded, encoding); err != nil {
		_ = credentialSecretDelete(node.id, encoded, encoding)
		return change, err
	}
	return change, nil
}

func (change *workspaceInlineSecretChange) rollback() {
	if change == nil || change.committed || change.newEncoded == "" {
		return
	}
	_ = credentialSecretDelete(change.id, change.newEncoded, change.newEncoding)
}

func (change *workspaceInlineSecretChange) commit() {
	if change == nil {
		return
	}
	change.committed = true
	if change.previousEncoded != "" &&
		(change.previousEncoded != change.newEncoded || change.previousEncoding != change.newEncoding) {
		_ = credentialSecretDelete(change.id, change.previousEncoded, change.previousEncoding)
	}
}
