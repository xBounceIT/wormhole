package main

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// webTargetRequest is either a saved node id or a Quick Connect address. The renderer never
// resolves inherited host, port, certificate, or tunnel settings itself.
type webTargetRequest struct {
	NodeID           string `json:"nodeId"`
	Address          string `json:"address"`
	Port             int    `json:"port"`
	Protocol         string `json:"protocol"`
	IgnoreCertErrors bool   `json:"ignoreCertErrors"`
	TunnelConfigID   string `json:"tunnelConfigId"`
}

// webTargetResponse is the non-secret part of a resolved HTTP(S) connection. Electron owns the
// Chromium view lifecycle; Go owns the domain rules and gives it this already-validated target.
type webTargetResponse struct {
	URL              string `json:"url"`
	Protocol         string `json:"protocol"`
	Host             string `json:"host"`
	Port             int    `json:"port"`
	IgnoreCertErrors bool   `json:"ignoreCertErrors"`
	TunnelConfigID   string `json:"tunnelConfigId,omitempty"`
	ProxyURL         string `json:"proxyUrl,omitempty"`
}

type webNode struct {
	ID                   string
	ParentID             sql.NullString
	Name                 string
	Kind                 int64
	Protocol             sql.NullInt64
	Host                 sql.NullString
	Port                 sql.NullInt64
	HTTPPath             sql.NullString
	TunnelEnabled        sql.NullInt64
	TunnelConfigID       sql.NullString
	HTTPIgnoreCertErrors sql.NullInt64
}

func resolveWebTarget(databasePath string, request webTargetRequest) (webTargetResponse, error) {
	nodeID := strings.TrimSpace(request.NodeID)
	if nodeID == "" {
		return resolveDirectWebTarget(request)
	}
	if len(nodeID) > 128 || request.Address != "" || request.Port != 0 || request.Protocol != "" || request.IgnoreCertErrors || request.TunnelConfigID != "" {
		return webTargetResponse{}, errors.New("web connection id is invalid")
	}

	database, err := openDatabase(databasePath, true)
	if err != nil {
		return webTargetResponse{}, err
	}
	if database == nil {
		return webTargetResponse{}, errors.New("Wormhole database has no connections")
	}
	defer database.Close()

	nodes, err := loadWebNodes(database)
	if err != nil {
		return webTargetResponse{}, err
	}
	leaf := nodes[normalizeID(nodeID)]
	if leaf == nil || leaf.Kind != 1 {
		return webTargetResponse{}, errors.New("web connection was not found")
	}

	return resolveWebTargetFromNodes(leaf, nodes)
}

func resolveDirectWebTarget(request webTargetRequest) (webTargetResponse, error) {
	if request.Protocol != "http" && request.Protocol != "https" {
		return webTargetResponse{}, errors.New("web connection has an invalid protocol")
	}
	tunnelID := normalizeTunnelID(request.TunnelConfigID)
	if request.TunnelConfigID != "" && tunnelID == "" {
		return webTargetResponse{}, errors.New("web connection has an invalid VPN tunnel")
	}
	host, port, httpPath, err := parseWebAddressTarget(request.Address)
	if err != nil {
		return webTargetResponse{}, err
	}
	if request.Port < 0 || request.Port > 65535 {
		return webTargetResponse{}, errors.New("web connection has an invalid port")
	}
	if request.Port != 0 {
		port = request.Port
	}
	defaultPort := 80
	if request.Protocol == "https" {
		defaultPort = 443
	}
	if port == 0 {
		port = defaultPort
	}
	uri, err := buildWebURLWithPath(request.Protocol, host, port, httpPath)
	if err != nil {
		return webTargetResponse{}, err
	}
	return webTargetResponse{
		URL:              uri,
		Protocol:         request.Protocol,
		Host:             host,
		Port:             port,
		IgnoreCertErrors: request.Protocol == "https" && request.IgnoreCertErrors,
		TunnelConfigID:   tunnelID,
	}, nil
}

func loadWebNodes(database *sql.DB) (map[string]*webNode, error) {
	exists, err := tableExists(database, "Nodes")
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.New("Wormhole database has no connections")
	}
	columns, err := tableColumns(database, "Nodes")
	if err != nil {
		return nil, err
	}

	columnOrNull := func(name string) string {
		if _, ok := columns[name]; ok {
			return name
		}
		return "NULL"
	}
	rows, err := database.Query(`SELECT Id, ParentId, Name, Kind, Protocol, Host, ` +
		columnOrNull("Port") + ` AS Port, ` +
		columnOrNull("HttpPath") + ` AS HttpPath, ` +
		columnOrNull("TunnelEnabled") + ` AS TunnelEnabled, ` +
		columnOrNull("TunnelConfigId") + ` AS TunnelConfigId, ` +
		columnOrNull("HttpIgnoreCertErrors") + ` AS HttpIgnoreCertErrors FROM Nodes;`)
	if err != nil {
		return nil, fmt.Errorf("cannot read web connections: %w", err)
	}
	defer rows.Close()

	nodes := make(map[string]*webNode)
	for rows.Next() {
		var node webNode
		if err := rows.Scan(
			&node.ID,
			&node.ParentID,
			&node.Name,
			&node.Kind,
			&node.Protocol,
			&node.Host,
			&node.Port,
			&node.HTTPPath,
			&node.TunnelEnabled,
			&node.TunnelConfigID,
			&node.HTTPIgnoreCertErrors,
		); err != nil {
			return nil, fmt.Errorf("cannot read a web connection: %w", err)
		}
		id := normalizeID(node.ID)
		if id == "" {
			return nil, errors.New("web connection has an invalid id")
		}
		nodes[id] = &node
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot enumerate web connections: %w", err)
	}
	return nodes, nil
}

func resolveWebTargetFromNodes(leaf *webNode, nodes map[string]*webNode) (webTargetResponse, error) {
	var protocol sql.NullInt64
	var host sql.NullString
	var port sql.NullInt64
	var portOwner *webNode
	var httpPath sql.NullString
	var tunnelEnabled sql.NullInt64
	var tunnelConfigID sql.NullString

	seen := make(map[string]struct{})
	for current := leaf; current != nil; {
		currentID := normalizeID(current.ID)
		if _, alreadySeen := seen[currentID]; alreadySeen {
			return webTargetResponse{}, errors.New("cannot resolve web connection: node tree contains a cycle")
		}
		seen[currentID] = struct{}{}

		if !protocol.Valid && current.Protocol.Valid {
			protocol = current.Protocol
		}
		if !host.Valid && current.Host.Valid {
			host = current.Host
		}
		if !port.Valid && current.Port.Valid {
			port = current.Port
			portOwner = current
		}
		if !httpPath.Valid && current.HTTPPath.Valid {
			httpPath = current.HTTPPath
		}
		if !tunnelEnabled.Valid && current.TunnelEnabled.Valid {
			tunnelEnabled = current.TunnelEnabled
		}
		if !tunnelConfigID.Valid && current.TunnelConfigID.Valid {
			tunnelConfigID = current.TunnelConfigID
		}

		if !current.ParentID.Valid || strings.TrimSpace(current.ParentID.String) == "" {
			break
		}
		current = nodes[normalizeID(current.ParentID.String)]
	}

	if !protocol.Valid || (protocol.Int64 != 3 && protocol.Int64 != 4) {
		return webTargetResponse{}, errors.New("connection is not configured for HTTP or HTTPS")
	}
	if !host.Valid || strings.TrimSpace(host.String) == "" {
		return webTargetResponse{}, errors.New("web connection has no host")
	}
	if port.Valid && (port.Int64 < 1 || port.Int64 > 65535) {
		return webTargetResponse{}, errors.New("web connection has an invalid port")
	}

	// A port carried from a differently-protocolled folder must not make an HTTP(S) tab dial a
	// service port such as 3389. This matches InheritanceResolver's port-context safeguard.
	if portOwner != nil {
		ownerProtocol, err := resolvedProtocolForWebNode(portOwner, nodes)
		if err != nil {
			return webTargetResponse{}, err
		}
		if ownerProtocol.Valid && ownerProtocol.Int64 != protocol.Int64 {
			port = sql.NullInt64{}
		}
	}

	resolvedTunnelID := ""
	if tunnelEnabled.Valid && tunnelEnabled.Int64 != 0 {
		resolvedTunnelID = normalizeTunnelID(nullableString(tunnelConfigID))
		if resolvedTunnelID == "" {
			return webTargetResponse{}, errors.New("web connection has VPN enabled but no tunnel is configured")
		}
	}

	scheme := "http"
	defaultPort := 80
	protocolName := "http"
	if protocol.Int64 == 4 {
		scheme = "https"
		defaultPort = 443
		protocolName = "https"
	}
	resolvedPort := defaultPort
	if port.Valid {
		resolvedPort = int(port.Int64)
	}
	resolvedHost := strings.TrimSpace(host.String)
	uri, err := buildWebURLWithPath(scheme, resolvedHost, resolvedPort, nullableString(httpPath))
	if err != nil {
		return webTargetResponse{}, err
	}

	ignoreCertErrors := protocol.Int64 == 4 && leaf.HTTPIgnoreCertErrors.Valid && leaf.HTTPIgnoreCertErrors.Int64 != 0
	return webTargetResponse{
		URL:              uri,
		Protocol:         protocolName,
		Host:             resolvedHost,
		Port:             resolvedPort,
		IgnoreCertErrors: ignoreCertErrors,
		TunnelConfigID:   resolvedTunnelID,
	}, nil
}

func resolvedProtocolForWebNode(node *webNode, nodes map[string]*webNode) (sql.NullInt64, error) {
	seen := make(map[string]struct{})
	for current := node; current != nil; {
		currentID := normalizeID(current.ID)
		if _, alreadySeen := seen[currentID]; alreadySeen {
			return sql.NullInt64{}, errors.New("cannot resolve web connection: node tree contains a cycle")
		}
		seen[currentID] = struct{}{}
		if current.Protocol.Valid {
			return current.Protocol, nil
		}
		if !current.ParentID.Valid || strings.TrimSpace(current.ParentID.String) == "" {
			break
		}
		current = nodes[normalizeID(current.ParentID.String)]
	}
	return sql.NullInt64{}, nil
}

func buildWebURL(scheme, host string, port int) (string, error) {
	return buildWebURLWithPath(scheme, host, port, "")
}

func buildWebURLWithPath(scheme, host string, port int, httpPath string) (string, error) {
	if scheme != "http" && scheme != "https" {
		return "", errors.New("web connection has an invalid protocol")
	}
	host = strings.TrimSpace(host)
	if host == "" ||
		strings.ContainsAny(host, "\\/?#@%\x00") ||
		strings.IndexFunc(host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", errors.New("web connection has an invalid host")
	}
	if port < 1 || port > 65535 {
		return "", errors.New("web connection has an invalid port")
	}
	// Nodes store the host and port separately. Strip brackets only for a valid IPv6 literal so
	// net.JoinHostPort can produce the URL authority without accepting arbitrary bracket syntax.
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		candidate := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		if net.ParseIP(candidate) == nil || !strings.Contains(candidate, ":") {
			return "", errors.New("web connection has an invalid host")
		}
		host = candidate
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return "", errors.New("web connection host must not include a port")
	}
	uri := url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(host, strconv.Itoa(port)),
		Path:   "/",
	}
	if httpPath != "" {
		normalizedPath, err := normalizeWebPath(httpPath)
		if err != nil {
			return "", err
		}
		parsedPath, err := url.Parse(normalizedPath)
		if err != nil {
			return "", errors.New("web connection has an invalid path")
		}
		uri.Path = parsedPath.Path
		uri.RawPath = parsedPath.RawPath
		uri.RawQuery = parsedPath.RawQuery
		uri.ForceQuery = parsedPath.ForceQuery
		uri.Fragment = parsedPath.Fragment
		uri.RawFragment = parsedPath.RawFragment
	}
	return uri.String(), nil
}

// parseWebAddress remains available to callers that only need the network endpoint.
func parseWebAddress(raw string) (string, int, error) {
	host, port, _, err := parseWebAddressTarget(raw)
	return host, port, err
}

// parseWebAddressTarget is intentionally compatible with the legacy single address field: users
// can enter host, host:port, an IPv6 literal, or paste an HTTP(S) URL. The selected protocol wins,
// while the URL path, query, and fragment remain part of the logical browser target.
func parseWebAddressTarget(raw string) (string, int, string, error) {
	address := strings.TrimSpace(raw)
	lowerAddress := strings.ToLower(address)
	if strings.HasPrefix(lowerAddress, "https://") {
		address = address[len("https://"):]
	} else if strings.HasPrefix(lowerAddress, "http://") {
		address = address[len("http://"):]
	}
	httpPath := ""
	if cut := strings.IndexAny(address, "/?#"); cut >= 0 {
		var err error
		httpPath, err = normalizeWebPath(address[cut:])
		if err != nil {
			return "", 0, "", err
		}
		address = address[:cut]
	}
	address = strings.TrimSpace(address)
	if address == "" {
		return "", 0, "", errors.New("web connection has no host")
	}

	if strings.HasPrefix(address, "[") {
		closing := strings.Index(address, "]")
		if closing <= 1 {
			return "", 0, "", errors.New("web connection has an invalid host")
		}
		host := address[1:closing]
		if net.ParseIP(host) == nil || !strings.Contains(host, ":") {
			return "", 0, "", errors.New("web connection has an invalid host")
		}
		remainder := address[closing+1:]
		if remainder == "" {
			return host, 0, httpPath, nil
		}
		if !strings.HasPrefix(remainder, ":") {
			return "", 0, "", errors.New("web connection has an invalid host")
		}
		port, err := parseWebPort(remainder[1:])
		return host, port, httpPath, err
	}

	switch strings.Count(address, ":") {
	case 0:
		return address, 0, httpPath, nil
	case 1:
		host, rawPort, _ := strings.Cut(address, ":")
		if host == "" {
			return "", 0, "", errors.New("web connection has no host")
		}
		port, err := parseWebPort(rawPort)
		return host, port, httpPath, err
	default:
		if net.ParseIP(address) == nil {
			return "", 0, "", errors.New("web connection host must be an IPv6 literal when it contains multiple colons")
		}
		return address, 0, httpPath, nil
	}
}

func normalizeWebPath(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if len(raw) > 4096 || strings.Contains(raw, "\\") || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return "", errors.New("web connection has an invalid path")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.Opaque != "" {
		return "", errors.New("web connection has an invalid path")
	}
	if parsed.Path != "" && !strings.HasPrefix(parsed.Path, "/") {
		return "", errors.New("web connection has an invalid path")
	}
	normalized := parsed.EscapedPath()
	if normalized == "" && (parsed.ForceQuery || parsed.RawQuery != "" || parsed.Fragment != "") {
		normalized = "/"
	}
	if parsed.ForceQuery || parsed.RawQuery != "" {
		normalized += "?" + parsed.RawQuery
	}
	if parsed.Fragment != "" {
		normalized += "#" + parsed.EscapedFragment()
	}
	if len(normalized) > 4096 {
		return "", errors.New("web connection has an invalid path")
	}
	return normalized, nil
}

func parseWebPort(raw string) (int, error) {
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("web connection has an invalid port")
	}
	return port, nil
}
