package main

import (
	"database/sql"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unicode"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const rdpProtocolValue = int64(1)

// workspaceRdpSettings is safe workspace metadata. Passwords are intentionally absent and are
// resolved only in the Go runtime profile immediately before a connection starts.
type workspaceRdpSettings = vault.RDPSettings

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

func normalizeRdpExternalClientForOS(profile *rdpProfile, operatingSystem string) bool {
	if profile == nil {
		return false
	}
	if operatingSystem != "windows" {
		// RdpUseExternalClient means mstsc, not the FreeRDP process used by non-Windows builds.
		// Ignore a preference that may have roamed with the shared workspace database.
		profile.UseExternalClient = false
		return false
	}
	return enforceAzureAdRdpExternalClient(profile, operatingSystem)
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
	database sqlMetadataReader,
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
	database sqlMetadataReader,
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

func defaultWorkspaceRdpSettings() workspaceRdpSettings { return vault.DefaultRDPSettings() }
func normalizeWorkspaceRdpSettings(value *workspaceRdpSettings) (workspaceRdpSettings, error) {
	return vault.NormalizeRDPSettings(value)
}
func validRdpText(value string, maximum int) bool { return vault.ValidRDPText(value, maximum) }
func validRdpHostText(value string) bool          { return vault.ValidRDPHost(value) }
func validRdpScreenSize(value string) bool        { return vault.ValidRDPScreenSize(value) }
func normalizeRdpDriveList(value string) string   { return vault.NormalizeRDPDriveList(value) }

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

func loadRdpNodeChain(database sqlMetadataReader, nodeID string) ([]map[string]any, error) {
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
	return vault.NormalizePersistedRDPSettings(settings)
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

func resolveRdpTargetFromChain(chain []map[string]any) (string, int, error) {
	if len(chain) == 0 {
		return "", 0, errors.New("RDP connection was not found")
	}
	if kind, ok := workspaceNodeValueInt64(chain[0]["Kind"]); !ok || kind != workspaceNodeConnection {
		return "", 0, errors.New("RDP target is not a connection")
	}
	var protocol int64
	protocolFound := false
	for _, row := range chain {
		if protocol, protocolFound = workspaceNodeValueInt64(row["Protocol"]); protocolFound {
			break
		}
	}
	if !protocolFound || protocol != rdpProtocolValue {
		return "", 0, errors.New("connection is not an RDP profile")
	}
	host, port := workspaceRdpTargetFromChain(chain)
	return normalizeRdpTarget(host, port)
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
	return resolveLegacyRDPProfile(m.database, nodeID, manual, forSystemClient, credentialIDOverride,
		m.resolveRdpCredential,
		func(id string) (string, bool, error) { return readStoredSecret(m.database, id, m.electronUserDataPath) },
		func(id, credential string, inline bool, profile rdpProfile, settings workspaceRdpSettings) {
			observeLegacyRDP(m.database, id, credential, inline, profile, settings)
		})
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
	encoded, encoding, err := credentialSecretStore(node.id, "", node.inlinePassword)
	if err != nil {
		return change, fmt.Errorf("could not protect the inline password: %w", err)
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
