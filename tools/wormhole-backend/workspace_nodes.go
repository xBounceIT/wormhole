package main

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	workspaceNodeFolder     = int64(0)
	workspaceNodeConnection = int64(1)
)

type workspaceNodeWriteRequest struct {
	ID                   string                `json:"id"`
	ParentID             string                `json:"parentId"`
	Name                 string                `json:"name"`
	Kind                 string                `json:"kind"`
	Protocol             string                `json:"protocol"`
	Host                 string                `json:"host"`
	Port                 int                   `json:"port"`
	Username             string                `json:"username"`
	InlinePasswordAction string                `json:"inlinePasswordAction"`
	InlinePassword       string                `json:"inlinePassword"`
	SshAutoSudo          *bool                 `json:"sshAutoSudo"`
	HTTPIgnoreCertErrors *bool                 `json:"httpIgnoreCertErrors"`
	TunnelEnabled        *bool                 `json:"tunnelEnabled"`
	TunnelConfigID       string                `json:"tunnelConfigId"`
	CredentialMode       int                   `json:"credentialMode"`
	CredentialID         string                `json:"credentialId"`
	SerialBaudRate       int                   `json:"serialBaudRate"`
	SerialDataBits       int                   `json:"serialDataBits"`
	SerialStopBits       int                   `json:"serialStopBits"`
	SerialParity         int                   `json:"serialParity"`
	SerialFlowControl    int                   `json:"serialFlowControl"`
	RDP                  *workspaceRdpSettings `json:"rdp"`
}

type normalizedWorkspaceNode struct {
	id                   string
	parentID             string
	name                 string
	kind                 int64
	protocol             sql.NullInt64
	host                 sql.NullString
	port                 sql.NullInt64
	username             any
	useInlinePassword    any
	inlinePasswordAction string
	inlinePassword       string
	sshAutoSudo          any
	httpIgnoreCertErrors any
	tunnelEnabled        any
	tunnelConfigID       any
	credentialMode       int
	credentialID         any
	serialBaudRate       any
	serialDataBits       any
	serialStopBits       any
	serialParity         any
	serialFlowControl    any
	rdp                  *workspaceRdpSettings
}

func createWorkspaceNode(databasePath string, request workspaceNodeWriteRequest) (string, error) {
	request.ID = ""
	database, err := openDatabase(databasePath, false)
	if err != nil {
		return "", err
	}
	defer database.Close()
	if err := requireWorkspaceNodeWriteSchema(database); err != nil {
		return "", err
	}

	id, err := newCredentialID()
	if err != nil {
		return "", errors.New("could not generate a workspace node id")
	}
	request.ID = id
	node, err := normalizeWorkspaceNodeWrite(database, request, false)
	if err != nil {
		return "", err
	}
	tx, err := database.Begin()
	if err != nil {
		return "", fmt.Errorf("could not start workspace node creation: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err := validateWorkspaceNodeReferences(tx, node, false); err != nil {
		return "", err
	}
	secretChange, err := prepareWorkspaceInlineSecret(tx, node, false)
	if err != nil {
		return "", err
	}
	defer secretChange.rollback()
	sortOrder, err := nextWorkspaceNodeSortOrder(tx, node.parentID)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertArgs := []any{
		node.id, nullableWorkspaceNodeString(node.parentID), node.name, node.kind, sortOrder,
		nullableWorkspaceNodeInt(node.protocol), nullableWorkspaceNodeSQLString(node.host), nullableWorkspaceNodeInt(node.port),
		node.username, node.credentialID, node.credentialMode, node.useInlinePassword, node.sshAutoSudo, node.httpIgnoreCertErrors,
		node.tunnelEnabled, node.tunnelConfigID,
		node.serialBaudRate, node.serialDataBits, node.serialStopBits, node.serialParity, node.serialFlowControl,
	}
	insertArgs = append(insertArgs, workspaceRdpDatabaseValues(node.rdp)...)
	insertArgs = append(insertArgs, now, now)
	_, err = tx.Exec(`
INSERT INTO Nodes (
    Id, ParentId, Name, Kind, SortOrder, Protocol, Host, Port,
    Username, CredentialId, CredentialMode, UseInlinePassword, SshAutoSudo, HttpIgnoreCertErrors,
    TunnelEnabled, TunnelConfigId,
    SerialBaudRate, SerialDataBits, SerialStopBits, SerialParity, SerialFlowControl,
    RdpDomain, RdpScreenSize, RdpFullScreen, RdpColorDepth, RdpUseAllMonitors,
    RdpAudioMode, RdpAudioCaptureMode, RdpKeyboardHookMode, RdpRedirectClipboard,
    RdpRedirectPrinters, RdpRedirectSmartCards, RdpRedirectPorts, RdpRedirectDevices,
    RdpRedirectDrives, RdpConnectionSpeed, RdpDesktopBackground, RdpFontSmoothing,
    RdpDesktopComposition, RdpWindowDrag, RdpMenuAnimation, RdpVisualStyles,
    RdpBitmapCaching, RdpAutoReconnect, RdpServerAuthentication, RdpGatewayUsageMethod,
    RdpGatewayHostname, RdpGatewayCredentialId, RdpGatewayBypassLocal,
    RdpGatewayUseSameCreds, RdpUseExternalClient, CreatedAt, UpdatedAt)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`, insertArgs...)
	if err != nil {
		return "", fmt.Errorf("could not create workspace node: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("could not create workspace node: %w", err)
	}
	committed = true
	secretChange.commit()
	return node.id, nil
}

func updateWorkspaceNode(databasePath string, request workspaceNodeWriteRequest) error {
	database, err := openDatabase(databasePath, false)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := requireWorkspaceNodeWriteSchema(database); err != nil {
		return err
	}
	node, err := normalizeWorkspaceNodeWrite(database, request, true)
	if err != nil {
		return err
	}
	tx, err := database.Begin()
	if err != nil {
		return fmt.Errorf("could not start workspace node update: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err := validateWorkspaceNodeReferences(tx, node, true); err != nil {
		return err
	}
	secretChange, err := prepareWorkspaceInlineSecret(tx, node, true)
	if err != nil {
		return err
	}
	defer secretChange.rollback()
	var result sql.Result
	if node.kind == workspaceNodeFolder {
		// Electron's folder editor exposes only identity, credential, SSH auto-sudo, and tunnel
		// inheritance. Preserve every legacy/WinUI folder default that is not visible in that editor;
		// writing the blank request fields would silently erase protocol, host, port, and serial
		// inheritance when a user merely changed a Bitwarden binding.
		result, err = tx.Exec(`
UPDATE Nodes SET
    ParentId = ?, Name = ?, CredentialId = ?, CredentialMode = ?, SshAutoSudo = ?,
    TunnelEnabled = ?, TunnelConfigId = ?, UpdatedAt = ?
WHERE lower(Id) = ? AND Kind = ?;`,
			nullableWorkspaceNodeString(node.parentID), node.name, node.credentialID,
			node.credentialMode, node.sshAutoSudo, node.tunnelEnabled, node.tunnelConfigID,
			time.Now().UTC().Format(time.RFC3339Nano), node.id, node.kind,
		)
	} else {
		if node.protocol.Int64 == 1 {
			updateArgs := []any{
				nullableWorkspaceNodeString(node.parentID), node.name,
				nullableWorkspaceNodeInt(node.protocol), nullableWorkspaceNodeSQLString(node.host), nullableWorkspaceNodeInt(node.port),
				node.username, node.credentialID, node.credentialMode, node.useInlinePassword,
				node.sshAutoSudo, node.httpIgnoreCertErrors, node.tunnelEnabled, node.tunnelConfigID,
				node.serialBaudRate, node.serialDataBits, node.serialStopBits, node.serialParity, node.serialFlowControl,
			}
			updateArgs = append(updateArgs, workspaceRdpDatabaseValues(node.rdp)...)
			updateArgs = append(updateArgs, time.Now().UTC().Format(time.RFC3339Nano), node.id, node.kind)
			result, err = tx.Exec(`
UPDATE Nodes SET
    ParentId = ?, Name = ?, Protocol = ?, Host = ?, Port = ?,
    Username = ?, CredentialId = ?, CredentialMode = ?, UseInlinePassword = ?,
    SshAutoSudo = ?, HttpIgnoreCertErrors = ?,
    TunnelEnabled = ?, TunnelConfigId = ?,
    SerialBaudRate = ?, SerialDataBits = ?, SerialStopBits = ?, SerialParity = ?, SerialFlowControl = ?,
    RdpDomain = ?, RdpScreenSize = ?, RdpFullScreen = ?, RdpColorDepth = ?, RdpUseAllMonitors = ?,
    RdpAudioMode = ?, RdpAudioCaptureMode = ?, RdpKeyboardHookMode = ?, RdpRedirectClipboard = ?,
    RdpRedirectPrinters = ?, RdpRedirectSmartCards = ?, RdpRedirectPorts = ?, RdpRedirectDevices = ?,
    RdpRedirectDrives = ?, RdpConnectionSpeed = ?, RdpDesktopBackground = ?, RdpFontSmoothing = ?,
    RdpDesktopComposition = ?, RdpWindowDrag = ?, RdpMenuAnimation = ?, RdpVisualStyles = ?,
    RdpBitmapCaching = ?, RdpAutoReconnect = ?, RdpServerAuthentication = ?, RdpGatewayUsageMethod = ?,
    RdpGatewayHostname = ?, RdpGatewayCredentialId = ?, RdpGatewayBypassLocal = ?,
    RdpGatewayUseSameCreds = ?, RdpUseExternalClient = ?,
    UpdatedAt = ?
WHERE lower(Id) = ? AND Kind = ?;`, updateArgs...)
		} else {
			// Protocol-specific values that are not visible remain untouched when a connection is
			// edited as another protocol. This preserves imported/legacy fields for later switches.
			result, err = tx.Exec(`
UPDATE Nodes SET
    ParentId = ?, Name = ?, Protocol = ?, Host = ?, Port = ?, Username = ?,
    CredentialId = ?, CredentialMode = ?, UseInlinePassword = ?, SshAutoSudo = ?,
    HttpIgnoreCertErrors = ?, TunnelEnabled = ?, TunnelConfigId = ?,
    SerialBaudRate = ?, SerialDataBits = ?, SerialStopBits = ?, SerialParity = ?, SerialFlowControl = ?,
    UpdatedAt = ?
WHERE lower(Id) = ? AND Kind = ?;`,
				nullableWorkspaceNodeString(node.parentID), node.name,
				nullableWorkspaceNodeInt(node.protocol), nullableWorkspaceNodeSQLString(node.host), nullableWorkspaceNodeInt(node.port),
				node.username, node.credentialID, node.credentialMode, node.useInlinePassword,
				node.sshAutoSudo, node.httpIgnoreCertErrors, node.tunnelEnabled, node.tunnelConfigID,
				node.serialBaudRate, node.serialDataBits, node.serialStopBits, node.serialParity, node.serialFlowControl,
				time.Now().UTC().Format(time.RFC3339Nano), node.id, node.kind,
			)
		}
	}
	if err != nil {
		return fmt.Errorf("could not update workspace node: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errors.New("workspace node was not found")
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("could not update workspace node: %w", err)
	}
	committed = true
	secretChange.commit()
	return nil
}

func normalizeWorkspaceNodeWrite(
	database *sql.DB,
	request workspaceNodeWriteRequest,
	requireID bool,
) (normalizedWorkspaceNode, error) {
	id := normalizeID(request.ID)
	if (requireID && !validCredentialID(id)) || (!requireID && id == "") {
		return normalizedWorkspaceNode{}, errors.New("workspace node id is invalid")
	}
	parentID := normalizeID(request.ParentID)
	if parentID != "" && !validCredentialID(parentID) {
		return normalizedWorkspaceNode{}, errors.New("workspace parent folder id is invalid")
	}
	name := strings.TrimSpace(request.Name)
	if name == "" || utf8.RuneCountInString(name) > 256 || strings.ContainsFunc(name, unicode.IsControl) {
		return normalizedWorkspaceNode{}, errors.New("workspace node name is invalid")
	}
	if request.CredentialMode < 0 || request.CredentialMode > 2 {
		return normalizedWorkspaceNode{}, errors.New("workspace credential setting is invalid")
	}
	credentialID := normalizeID(request.CredentialID)
	if request.CredentialMode == 2 {
		if !validCredentialID(credentialID) {
			return normalizedWorkspaceNode{}, errors.New("selected credential id is invalid")
		}
	} else {
		credentialID = ""
	}
	tunnelConfigID := normalizeTunnelID(request.TunnelConfigID)
	if request.TunnelConfigID != "" && tunnelConfigID == "" {
		return normalizedWorkspaceNode{}, errors.New("VPN tunnel id is invalid")
	}

	node := normalizedWorkspaceNode{
		id:                   id,
		parentID:             parentID,
		name:                 name,
		sshAutoSudo:          workspaceNodeBoolean(request.SshAutoSudo),
		httpIgnoreCertErrors: workspaceNodeBoolean(request.HTTPIgnoreCertErrors),
		tunnelEnabled:        workspaceNodeBoolean(request.TunnelEnabled),
		tunnelConfigID:       nullableWorkspaceNodeString(tunnelConfigID),
		credentialMode:       request.CredentialMode,
		credentialID:         nullableWorkspaceNodeString(credentialID),
		inlinePasswordAction: strings.ToLower(strings.TrimSpace(request.InlinePasswordAction)),
		inlinePassword:       request.InlinePassword,
	}
	if node.inlinePasswordAction == "" {
		node.inlinePasswordAction = "clear"
	}
	if node.inlinePasswordAction != "preserve" && node.inlinePasswordAction != "set" && node.inlinePasswordAction != "clear" {
		return normalizedWorkspaceNode{}, errors.New("workspace inline password action is invalid")
	}
	if node.inlinePasswordAction == "set" && (request.InlinePassword == "" || utf8.RuneCountInString(request.InlinePassword) > 4096) {
		return normalizedWorkspaceNode{}, errors.New("workspace inline password is invalid")
	}
	if node.inlinePasswordAction != "set" && request.InlinePassword != "" {
		return normalizedWorkspaceNode{}, errors.New("workspace inline password is invalid")
	}

	switch strings.ToLower(strings.TrimSpace(request.Kind)) {
	case "folder":
		node.kind = workspaceNodeFolder
		node.httpIgnoreCertErrors = nil
		node.inlinePasswordAction = "clear"
		node.inlinePassword = ""
	case "connection":
		node.kind = workspaceNodeConnection
		protocol, ok := workspaceProtocolValue(request.Protocol)
		if !ok {
			return normalizedWorkspaceNode{}, errors.New("workspace connection protocol is invalid")
		}
		node.protocol = sql.NullInt64{Int64: protocol, Valid: true}
		host := strings.TrimSpace(request.Host)
		if host == "" || utf8.RuneCountInString(host) > 4096 || strings.ContainsAny(host, "\r\n\x00") {
			return normalizedWorkspaceNode{}, errors.New("workspace connection host is invalid")
		}
		if request.Port < 0 || request.Port > 65535 {
			return normalizedWorkspaceNode{}, errors.New("workspace connection port is invalid")
		}
		switch protocol {
		case 3, 4:
			parsedHost, parsedPort, err := parseWebAddress(host)
			if err != nil {
				return normalizedWorkspaceNode{}, err
			}
			host = parsedHost
			port := request.Port
			if port == 0 {
				port = parsedPort
			}
			if port != 0 {
				node.port = sql.NullInt64{Int64: int64(port), Valid: true}
			}
		case 5:
			if request.Port != 0 {
				return normalizedWorkspaceNode{}, errors.New("serial connections do not use a network port")
			}
			target, err := normalizeSerialTarget(serialTarget{
				PortName: request.Host, BaudRate: request.SerialBaudRate, DataBits: request.SerialDataBits,
				StopBits: request.SerialStopBits, Parity: request.SerialParity, FlowControl: request.SerialFlowControl,
			})
			if err != nil {
				return normalizedWorkspaceNode{}, err
			}
			host = target.PortName
			node.serialBaudRate = target.BaudRate
			node.serialDataBits = target.DataBits
			node.serialStopBits = target.StopBits
			node.serialParity = target.Parity
			node.serialFlowControl = target.FlowControl
			node.tunnelEnabled = int64(0)
			node.tunnelConfigID = nil
			node.credentialMode = 1
			node.credentialID = nil
			node.inlinePasswordAction = "clear"
		case 0:
			if request.Port != 0 {
				node.port = sql.NullInt64{Int64: int64(request.Port), Valid: true}
			}
			if request.HTTPIgnoreCertErrors != nil {
				node.httpIgnoreCertErrors = nil
			}
		default:
			if request.Port != 0 {
				node.port = sql.NullInt64{Int64: int64(request.Port), Valid: true}
			}
			node.sshAutoSudo = nil
			node.httpIgnoreCertErrors = nil
		}
		username := strings.TrimSpace(request.Username)
		if utf8.RuneCountInString(username) > maxCredentialUsernameLength || strings.ContainsAny(username, "\r\n\x00") {
			return normalizedWorkspaceNode{}, errors.New("workspace connection username is invalid")
		}
		if protocol == 0 || protocol == 1 {
			node.username = nullableWorkspaceNodeString(username)
		} else {
			node.username = nil
			node.inlinePasswordAction = "clear"
		}
		if node.inlinePasswordAction == "set" || node.inlinePasswordAction == "preserve" {
			if protocol != 0 && protocol != 1 {
				return normalizedWorkspaceNode{}, errors.New("inline passwords are supported only for SSH and RDP")
			}
			node.useInlinePassword = int64(1)
			node.credentialMode = 1
			node.credentialID = nil
		} else {
			node.useInlinePassword = int64(0)
		}
		if protocol == 1 {
			rdp, err := normalizeWorkspaceRdpSettings(request.RDP)
			if err != nil {
				return normalizedWorkspaceNode{}, err
			}
			node.rdp = &rdp
		}
		if protocol != 4 {
			node.httpIgnoreCertErrors = nil
		}
		node.host = sql.NullString{String: host, Valid: true}
	default:
		return normalizedWorkspaceNode{}, errors.New("workspace node kind is invalid")
	}
	if node.rdp != nil {
		credentialID, _ := node.credentialID.(string)
		inheritedFromNodeID := ""
		if node.credentialMode == 0 {
			inheritedFromNodeID = node.parentID
		}
		requirement, err := rdpExternalClientRequirementFromDatabase(database, rdpExternalClientRequirementRequest{
			Username: request.Username, Domain: node.rdp.Domain,
			CredentialID: credentialID, InheritedFromNodeID: inheritedFromNodeID,
		})
		if err != nil {
			return normalizedWorkspaceNode{}, err
		}
		if requirement.Required {
			node.rdp.UseExternalClient = true
		}
	}
	return node, nil
}

func requireWorkspaceNodeWriteSchema(database *sql.DB) error {
	exists, err := tableExists(database, "Nodes")
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("Wormhole database has no connection storage")
	}
	columns, err := tableColumns(database, "Nodes")
	if err != nil {
		return err
	}
	for _, required := range []string{
		"Id", "ParentId", "Name", "Kind", "SortOrder", "Protocol", "Host", "Port",
		"Username", "CredentialId", "CredentialMode", "UseInlinePassword", "SshAutoSudo", "HttpIgnoreCertErrors",
		"TunnelEnabled", "TunnelConfigId", "SerialBaudRate", "SerialDataBits", "SerialStopBits",
		"SerialParity", "SerialFlowControl", "RdpDomain", "RdpScreenSize", "RdpFullScreen",
		"RdpColorDepth", "RdpUseAllMonitors", "RdpAudioMode", "RdpAudioCaptureMode",
		"RdpKeyboardHookMode", "RdpRedirectClipboard", "RdpRedirectPrinters",
		"RdpRedirectSmartCards", "RdpRedirectPorts", "RdpRedirectDevices", "RdpRedirectDrives",
		"RdpConnectionSpeed", "RdpDesktopBackground", "RdpFontSmoothing", "RdpDesktopComposition",
		"RdpWindowDrag", "RdpMenuAnimation", "RdpVisualStyles", "RdpBitmapCaching", "RdpAutoReconnect",
		"RdpServerAuthentication", "RdpGatewayUsageMethod", "RdpGatewayHostname",
		"RdpGatewayCredentialId", "RdpGatewayBypassLocal", "RdpGatewayUseSameCreds",
		"RdpUseExternalClient", "CreatedAt", "UpdatedAt",
	} {
		if _, ok := columns[required]; !ok {
			return fmt.Errorf("Wormhole database schema is missing the %s migration", required)
		}
	}
	return nil
}

func validateWorkspaceNodeReferences(tx *sql.Tx, node normalizedWorkspaceNode, updating bool) error {
	if updating {
		var kind int64
		if err := tx.QueryRow("SELECT Kind FROM Nodes WHERE lower(Id) = ? LIMIT 1;", node.id).Scan(&kind); errors.Is(err, sql.ErrNoRows) {
			return errors.New("workspace node was not found")
		} else if err != nil {
			return fmt.Errorf("could not validate workspace node: %w", err)
		} else if kind != node.kind {
			return errors.New("workspace node kind cannot be changed")
		}
	}
	if node.parentID != "" {
		var kind int64
		if err := tx.QueryRow("SELECT Kind FROM Nodes WHERE lower(Id) = ? LIMIT 1;", node.parentID).Scan(&kind); errors.Is(err, sql.ErrNoRows) {
			return errors.New("workspace parent folder was not found")
		} else if err != nil {
			return fmt.Errorf("could not validate workspace parent folder: %w", err)
		} else if kind != workspaceNodeFolder {
			return errors.New("workspace parent must be a folder")
		}
		if updating {
			if node.parentID == node.id {
				return errors.New("workspace folder cannot contain itself")
			}
			currentID := node.parentID
			seen := map[string]struct{}{}
			for currentID != "" {
				if currentID == node.id {
					return errors.New("workspace folder cannot be moved into its descendant")
				}
				if _, duplicate := seen[currentID]; duplicate {
					return errors.New("workspace tree contains a cycle")
				}
				seen[currentID] = struct{}{}
				var parent sql.NullString
				if err := tx.QueryRow("SELECT ParentId FROM Nodes WHERE lower(Id) = ? LIMIT 1;", currentID).Scan(&parent); err != nil {
					return fmt.Errorf("could not validate workspace tree: %w", err)
				}
				currentID = normalizeID(nullableString(parent))
			}
		}
	}
	if id, ok := node.tunnelConfigID.(string); ok && id != "" {
		var present int
		if err := tx.QueryRow("SELECT 1 FROM TunnelConfigs WHERE lower(Id) = ? LIMIT 1;", id).Scan(&present); errors.Is(err, sql.ErrNoRows) {
			return errors.New("the selected VPN tunnel was not found")
		} else if err != nil {
			return fmt.Errorf("could not validate VPN tunnel: %w", err)
		}
	}
	if id, ok := node.credentialID.(string); ok && id != "" {
		credential, found, err := credentialMetadataByID(tx, id)
		if err != nil {
			return err
		}
		if !found {
			return errors.New("selected credential was not found")
		}
		if node.kind == workspaceNodeConnection && node.protocol.Valid {
			if credential.protocol != node.protocol.Int64 {
				return errors.New("selected credential does not match the connection protocol")
			}
			if !workspaceCredentialKindSupportsProtocol(credential.kind, node.protocol.Int64) {
				return errors.New("selected credential type is invalid for the connection protocol")
			}
		}
	}
	if node.rdp != nil && node.rdp.GatewayCredentialID != "" {
		credential, found, err := credentialMetadataByID(tx, node.rdp.GatewayCredentialID)
		if err != nil {
			return err
		}
		if !found {
			return errors.New("selected RDP Gateway credential was not found")
		}
		if credential.protocol != rdpProtocolValue {
			return errors.New("selected RDP Gateway credential is not an RDP credential")
		}
		if !workspaceCredentialKindSupportsProtocol(credential.kind, rdpProtocolValue) {
			return errors.New("selected RDP Gateway credential type is invalid")
		}
	}
	return nil
}

func workspaceCredentialKindSupportsProtocol(kind, protocol int64) bool {
	return kind == 0 || (protocol == 0 && kind == 1)
}

func nextWorkspaceNodeSortOrder(tx *sql.Tx, parentID string) (int64, error) {
	var next int64
	query := "SELECT COALESCE(MAX(SortOrder), -1) + 1 FROM Nodes WHERE ParentId IS NULL;"
	args := []any{}
	if parentID != "" {
		query = "SELECT COALESCE(MAX(SortOrder), -1) + 1 FROM Nodes WHERE lower(ParentId) = ?;"
		args = append(args, parentID)
	}
	if err := tx.QueryRow(query, args...).Scan(&next); err != nil {
		return 0, fmt.Errorf("could not choose workspace node order: %w", err)
	}
	return next, nil
}

func workspaceProtocolValue(protocol string) (int64, bool) {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "ssh":
		return 0, true
	case "rdp":
		return 1, true
	case "http":
		return 3, true
	case "https":
		return 4, true
	case "serial":
		return 5, true
	case "vnc":
		return 6, true
	default:
		return 0, false
	}
}

func workspaceNodeBoolean(value *bool) any {
	if value == nil {
		return nil
	}
	if *value {
		return int64(1)
	}
	return int64(0)
}

func nullableWorkspaceNodeString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableWorkspaceNodeInt(value sql.NullInt64) any {
	if !value.Valid {
		return nil
	}
	return value.Int64
}

func nullableWorkspaceNodeSQLString(value sql.NullString) any {
	if !value.Valid {
		return nil
	}
	return value.String
}
