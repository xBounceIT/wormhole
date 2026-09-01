package main

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type workspaceNodeRequest struct {
	NodeID string `json:"nodeId"`
}

type workspaceNodesRequest struct {
	NodeIDs []string `json:"nodeIds"`
}

const workspaceDeleteNodesMaxRequestBytes = 256 * 1024

type workspaceDuplicateNodeResponse struct {
	NodeID string `json:"nodeId"`
	Name   string `json:"name"`
}

type workspaceDeleteNodeResponse struct {
	Deleted bool `json:"deleted"`
}

// workspaceCredentialRevealResponse is returned only after an explicit user action and is held
// temporarily by the renderer while the shadcn credentials dialog is open. It must never be
// logged or persisted.
type workspaceCredentialRevealResponse struct {
	Found          bool   `json:"found"`
	ConnectionName string `json:"connectionName"`
	CredentialName string `json:"credentialName,omitempty"`
	Username       string `json:"username,omitempty"`
	Domain         string `json:"domain,omitempty"`
	SecretLabel    string `json:"secretLabel,omitempty"`
	Secret         string `json:"secret,omitempty"`
}

type workspaceCredentialNode struct {
	id                string
	parentID          string
	name              string
	kind              sql.NullInt64
	protocol          sql.NullInt64
	username          sql.NullString
	credentialID      sql.NullString
	credentialMode    sql.NullInt64
	useInlinePassword sql.NullInt64
}

type workspaceCredentialProfile struct {
	name           sql.NullString
	username       sql.NullString
	domain         sql.NullString
	protocol       sql.NullInt64
	kind           sql.NullInt64
	secretProvider sql.NullInt64
}

func normalizeWorkspaceNodeID(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || len(trimmed) > 128 || strings.IndexFunc(trimmed, func(r rune) bool {
		return r < 0x20 || r == 0x7f
	}) >= 0 {
		return "", errors.New("workspace node id is invalid")
	}
	return normalizeID(trimmed), nil
}

func workspaceNodeColumnNames(database *sql.DB) ([]string, map[string]int, error) {
	rows, err := database.Query("PRAGMA table_info(\"Nodes\");")
	if err != nil {
		return nil, nil, fmt.Errorf("cannot inspect the Nodes schema: %w", err)
	}
	defer rows.Close()

	columns := make([]string, 0)
	indexes := make(map[string]int)
	for rows.Next() {
		var cid int64
		var name string
		var columnType sql.NullString
		var notNull, primaryKey int64
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, nil, fmt.Errorf("cannot read the Nodes schema: %w", err)
		}
		indexes[strings.ToLower(name)] = len(columns)
		columns = append(columns, name)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("cannot enumerate the Nodes schema: %w", err)
	}
	return columns, indexes, nil
}

func workspaceQuotedIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func workspaceColumnExpression(columns map[string]struct{}, name string) string {
	for column := range columns {
		if strings.EqualFold(column, name) {
			return workspaceQuotedIdentifier(column)
		}
	}
	return "NULL"
}

func workspaceNodeValueString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		return ""
	}
}

func workspaceNodeValueInt64(value any) (int64, bool) {
	switch typed := value.(type) {
	case int64:
		return typed, true
	case int32:
		return int64(typed), true
	case int:
		return int64(typed), true
	case []byte:
		var parsed int64
		if _, err := fmt.Sscan(string(typed), &parsed); err == nil {
			return parsed, true
		}
	case string:
		var parsed int64
		if _, err := fmt.Sscan(typed, &parsed); err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func duplicateWorkspaceNode(databasePath string, request workspaceNodeRequest) (workspaceDuplicateNodeResponse, error) {
	nodeID, err := normalizeWorkspaceNodeID(request.NodeID)
	if err != nil {
		return workspaceDuplicateNodeResponse{}, err
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		return workspaceDuplicateNodeResponse{}, err
	}
	defer database.Close()

	exists, err := tableExists(database, "Nodes")
	if err != nil {
		return workspaceDuplicateNodeResponse{}, err
	}
	if !exists {
		return workspaceDuplicateNodeResponse{}, errors.New("Wormhole database has no connections")
	}
	columns, indexes, err := workspaceNodeColumnNames(database)
	if err != nil {
		return workspaceDuplicateNodeResponse{}, err
	}
	if _, ok := indexes["id"]; !ok {
		return workspaceDuplicateNodeResponse{}, errors.New("Wormhole database schema is missing node identifiers")
	}
	if _, ok := indexes["name"]; !ok {
		return workspaceDuplicateNodeResponse{}, errors.New("Wormhole database schema is missing node names")
	}
	if _, ok := indexes["kind"]; !ok {
		return workspaceDuplicateNodeResponse{}, errors.New("Wormhole database schema is missing node kinds")
	}

	quotedColumns := make([]string, len(columns))
	for index, column := range columns {
		quotedColumns[index] = workspaceQuotedIdentifier(column)
	}
	row := make([]any, len(columns))
	destinations := make([]any, len(columns))
	for index := range row {
		destinations[index] = &row[index]
	}
	query := "SELECT " + strings.Join(quotedColumns, ", ") + " FROM \"Nodes\" WHERE lower(\"Id\") = ?;"
	rows, err := database.Query(query, nodeID)
	if err != nil {
		return workspaceDuplicateNodeResponse{}, fmt.Errorf("cannot read the workspace connection: %w", err)
	}
	found := false
	for rows.Next() {
		if found {
			_ = rows.Close()
			return workspaceDuplicateNodeResponse{}, errors.New("workspace node identifiers are ambiguous")
		}
		if err := rows.Scan(destinations...); err != nil {
			_ = rows.Close()
			return workspaceDuplicateNodeResponse{}, fmt.Errorf("cannot read the workspace connection: %w", err)
		}
		found = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return workspaceDuplicateNodeResponse{}, fmt.Errorf("cannot enumerate the workspace connection: %w", err)
	}
	if err := rows.Close(); err != nil {
		return workspaceDuplicateNodeResponse{}, fmt.Errorf("cannot close the workspace connection: %w", err)
	}
	if !found {
		return workspaceDuplicateNodeResponse{}, errors.New("workspace connection was not found")
	}

	kind, ok := workspaceNodeValueInt64(row[indexes["kind"]])
	if !ok || kind != 1 {
		return workspaceDuplicateNodeResponse{}, errors.New("only workspace connections can be duplicated")
	}
	sourceName := strings.TrimSpace(workspaceNodeValueString(row[indexes["name"]]))
	if sourceName == "" {
		sourceName = "Connection"
	}
	copyName := sourceName + " (copy)"
	newID, err := newCredentialID()
	if err != nil {
		return workspaceDuplicateNodeResponse{}, errors.New("could not allocate a workspace connection identifier")
	}

	row[indexes["id"]] = newID
	row[indexes["name"]] = copyName
	if index, ok := indexes["createdat"]; ok {
		row[index] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if index, ok := indexes["updatedat"]; ok {
		row[index] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if index, ok := indexes["sshknownhostfingerprint"]; ok {
		row[index] = nil
	}
	if index, ok := indexes["useinlinepassword"]; ok {
		// Inline secrets are keyed by the original node id. A new identity must not claim to
		// have the source's password; it can still inherit a parent credential or be edited.
		row[index] = int64(0)
	}
	if index, ok := indexes["httppath"]; ok {
		httpPath, err := normalizePersistedWebPath(workspaceNodeValueString(row[index]))
		if err != nil || httpPath == "" {
			row[index] = nil
		} else {
			row[index] = httpPath
		}
	}

	tx, err := database.Begin()
	if err != nil {
		return workspaceDuplicateNodeResponse{}, fmt.Errorf("could not start connection duplication: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if index, ok := indexes["sortorder"]; ok {
		nextSortOrder := int64(0)
		if parentIndex, hasParent := indexes["parentid"]; hasParent {
			parent := row[parentIndex]
			sortQuery := "SELECT COALESCE(MAX(" + workspaceQuotedIdentifier(columns[index]) + "), -1) + 1 FROM \"Nodes\" WHERE " + workspaceQuotedIdentifier(columns[parentIndex]) + " IS ?;"
			if err := tx.QueryRow(sortQuery, parent).Scan(&nextSortOrder); err != nil {
				return workspaceDuplicateNodeResponse{}, fmt.Errorf("could not determine connection order: %w", err)
			}
		}
		row[index] = nextSortOrder
	}

	placeholders := make([]string, len(columns))
	for index := range placeholders {
		placeholders[index] = "?"
	}
	insertQuery := "INSERT INTO \"Nodes\" (" + strings.Join(quotedColumns, ", ") + ") VALUES (" + strings.Join(placeholders, ", ") + ");"
	if _, err := tx.Exec(insertQuery, row...); err != nil {
		return workspaceDuplicateNodeResponse{}, fmt.Errorf("could not duplicate the workspace connection: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return workspaceDuplicateNodeResponse{}, fmt.Errorf("could not save the duplicated connection: %w", err)
	}
	committed = true
	return workspaceDuplicateNodeResponse{NodeID: newID, Name: copyName}, nil
}

type workspaceDeletedSecret struct {
	id       string
	encoded  string
	encoding string
}

func deleteWorkspaceNode(
	databasePath string,
	request workspaceNodeRequest,
) (workspaceDeleteNodeResponse, error) {
	return deleteWorkspaceNodes(databasePath, workspaceNodesRequest{NodeIDs: []string{request.NodeID}})
}

func deleteWorkspaceNodes(
	databasePath string,
	request workspaceNodesRequest,
) (workspaceDeleteNodeResponse, error) {
	if len(request.NodeIDs) == 0 {
		return workspaceDeleteNodeResponse{}, errors.New("at least one workspace node is required")
	}
	if len(request.NodeIDs) > 1000 {
		return workspaceDeleteNodeResponse{}, errors.New("too many workspace nodes were requested")
	}

	nodeIDs := make([]string, 0, len(request.NodeIDs))
	requested := make(map[string]struct{}, len(request.NodeIDs))
	for _, rawNodeID := range request.NodeIDs {
		nodeID, err := normalizeWorkspaceNodeID(rawNodeID)
		if err != nil {
			return workspaceDeleteNodeResponse{}, err
		}
		if _, duplicate := requested[nodeID]; duplicate {
			continue
		}
		requested[nodeID] = struct{}{}
		nodeIDs = append(nodeIDs, nodeID)
	}

	database, err := openDatabase(databasePath, false)
	if err != nil {
		return workspaceDeleteNodeResponse{}, err
	}
	defer database.Close()

	exists, err := tableExists(database, "Nodes")
	if err != nil {
		return workspaceDeleteNodeResponse{}, err
	}
	if !exists {
		return workspaceDeleteNodeResponse{}, errors.New("Wormhole database has no connections")
	}
	columns, indexes, err := workspaceNodeColumnNames(database)
	if err != nil {
		return workspaceDeleteNodeResponse{}, err
	}
	idIndex, ok := indexes["id"]
	if !ok {
		return workspaceDeleteNodeResponse{}, errors.New("Wormhole database schema is missing node identifiers")
	}
	parentExpression := "NULL"
	if parentIndex, ok := indexes["parentid"]; ok {
		parentExpression = workspaceQuotedIdentifier(columns[parentIndex])
	}
	credentialSecretsExist, err := tableExists(database, "CredentialSecrets")
	if err != nil {
		return workspaceDeleteNodeResponse{}, err
	}
	credentialProfilesExist, err := tableExists(database, "CredentialProfiles")
	if err != nil {
		return workspaceDeleteNodeResponse{}, err
	}
	if _, err := database.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		return workspaceDeleteNodeResponse{}, fmt.Errorf("could not enable workspace relationship checks: %w", err)
	}
	tx, err := database.Begin()
	if err != nil {
		return workspaceDeleteNodeResponse{}, fmt.Errorf("could not start workspace deletion: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	rows, err := tx.Query(
		"SELECT " + workspaceQuotedIdentifier(columns[idIndex]) + ", " + parentExpression + " FROM \"Nodes\";",
	)
	if err != nil {
		return workspaceDeleteNodeResponse{}, fmt.Errorf("cannot read workspace nodes: %w", err)
	}
	entries := make(map[string]struct{})
	children := make(map[string][]string)
	for rows.Next() {
		var rawID, rawParent sql.NullString
		if err := rows.Scan(&rawID, &rawParent); err != nil {
			_ = rows.Close()
			return workspaceDeleteNodeResponse{}, fmt.Errorf("cannot read a workspace node: %w", err)
		}
		id := normalizeID(nullableString(rawID))
		if id == "" {
			continue
		}
		if _, duplicate := entries[id]; duplicate {
			_ = rows.Close()
			return workspaceDeleteNodeResponse{}, errors.New("workspace node identifiers are ambiguous")
		}
		parentID := normalizeID(nullableString(rawParent))
		entries[id] = struct{}{}
		children[parentID] = append(children[parentID], id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return workspaceDeleteNodeResponse{}, fmt.Errorf("cannot enumerate workspace nodes: %w", err)
	}
	if err := rows.Close(); err != nil {
		return workspaceDeleteNodeResponse{}, fmt.Errorf("cannot close workspace nodes: %w", err)
	}
	for _, nodeID := range nodeIDs {
		if _, found := entries[nodeID]; !found {
			return workspaceDeleteNodeResponse{}, errors.New("workspace node was not found")
		}
	}

	type deleteFrame struct {
		id             string
		childrenQueued bool
	}
	deletedIDs := make([]string, 0, len(nodeIDs))
	stack := make([]deleteFrame, 0, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		stack = append(stack, deleteFrame{id: nodeID})
	}
	visited := make(map[string]struct{})
	for len(stack) > 0 {
		last := len(stack) - 1
		frame := stack[last]
		stack = stack[:last]
		if frame.childrenQueued {
			deletedIDs = append(deletedIDs, frame.id)
			continue
		}
		if _, alreadyVisited := visited[frame.id]; alreadyVisited {
			continue
		}
		_, found := entries[frame.id]
		if !found {
			continue
		}
		visited[frame.id] = struct{}{}
		stack = append(stack, deleteFrame{id: frame.id, childrenQueued: true})
		for _, childID := range children[frame.id] {
			stack = append(stack, deleteFrame{id: childID})
		}
	}

	deletedSecrets := make([]workspaceDeletedSecret, 0)
	if credentialSecretsExist {
		for _, id := range deletedIDs {
			if credentialProfilesExist {
				var profileExists int
				err := tx.QueryRow(
					"SELECT 1 FROM CredentialProfiles WHERE lower(Id) = ? LIMIT 1;",
					id,
				).Scan(&profileExists)
				if err == nil {
					continue
				}
				if !errors.Is(err, sql.ErrNoRows) {
					return workspaceDeleteNodeResponse{}, fmt.Errorf("could not inspect inline credential ownership: %w", err)
				}
			}
			var encoded, encoding sql.NullString
			err := tx.QueryRow(
				"SELECT Secret, Encoding FROM CredentialSecrets WHERE lower(Id) = ? LIMIT 1;",
				id,
			).Scan(&encoded, &encoding)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return workspaceDeleteNodeResponse{}, fmt.Errorf("could not read inline credential secret: %w", err)
			}
			if encoded.Valid && encoding.Valid {
				deletedSecrets = append(deletedSecrets, workspaceDeletedSecret{
					id: id, encoded: encoded.String, encoding: encoding.String,
				})
			}
			if _, err := tx.Exec("DELETE FROM CredentialSecrets WHERE lower(Id) = ?;", id); err != nil {
				return workspaceDeleteNodeResponse{}, fmt.Errorf("could not delete inline credential secret: %w", err)
			}
		}
	}

	for _, id := range deletedIDs {
		result, err := tx.Exec("DELETE FROM \"Nodes\" WHERE lower(\"Id\") = ?;", id)
		if err != nil {
			return workspaceDeleteNodeResponse{}, fmt.Errorf("could not delete workspace node: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return workspaceDeleteNodeResponse{}, fmt.Errorf("could not verify workspace node deletion: %w", err)
		}
		if affected == 0 {
			return workspaceDeleteNodeResponse{}, errors.New("workspace node was not found")
		}
	}
	if err := tx.Commit(); err != nil {
		return workspaceDeleteNodeResponse{}, fmt.Errorf("could not save workspace node deletion: %w", err)
	}
	committed = true
	for _, secret := range deletedSecrets {
		_ = credentialSecretDelete(secret.id, secret.encoded, secret.encoding)
	}
	return workspaceDeleteNodeResponse{Deleted: true}, nil
}

func loadWorkspaceCredentialNodes(database *sql.DB) (map[string]*workspaceCredentialNode, error) {
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
	query := "SELECT " + workspaceColumnExpression(columns, "Id") + ", " +
		workspaceColumnExpression(columns, "ParentId") + ", " +
		workspaceColumnExpression(columns, "Name") + ", " +
		workspaceColumnExpression(columns, "Kind") + ", " +
		workspaceColumnExpression(columns, "Protocol") + ", " +
		workspaceColumnExpression(columns, "Username") + ", " +
		workspaceColumnExpression(columns, "CredentialId") + ", " +
		workspaceColumnExpression(columns, "CredentialMode") + ", " +
		workspaceColumnExpression(columns, "UseInlinePassword") +
		" FROM \"Nodes\";"
	rows, err := database.Query(query)
	if err != nil {
		return nil, fmt.Errorf("cannot read workspace credential bindings: %w", err)
	}
	defer rows.Close()

	nodes := make(map[string]*workspaceCredentialNode)
	for rows.Next() {
		var id, parentID, name sql.NullString
		var node workspaceCredentialNode
		if err := rows.Scan(
			&id,
			&parentID,
			&name,
			&node.kind,
			&node.protocol,
			&node.username,
			&node.credentialID,
			&node.credentialMode,
			&node.useInlinePassword,
		); err != nil {
			return nil, fmt.Errorf("cannot read a workspace credential binding: %w", err)
		}
		node.id = normalizeID(nullableString(id))
		node.parentID = normalizeID(nullableString(parentID))
		node.name = nullableString(name)
		if node.id != "" {
			if _, duplicate := nodes[node.id]; duplicate {
				return nil, errors.New("workspace node identifiers are ambiguous")
			}
			nodes[node.id] = &node
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot enumerate workspace credential bindings: %w", err)
	}
	return nodes, nil
}

func loadWorkspaceCredentialProfile(database *sql.DB, credentialID string) (workspaceCredentialProfile, bool, error) {
	exists, err := tableExists(database, "CredentialProfiles")
	if err != nil {
		return workspaceCredentialProfile{}, false, err
	}
	if !exists {
		return workspaceCredentialProfile{}, false, nil
	}
	columns, err := tableColumns(database, "CredentialProfiles")
	if err != nil {
		return workspaceCredentialProfile{}, false, err
	}
	query := "SELECT " +
		workspaceColumnExpression(columns, "Name") + ", " +
		workspaceColumnExpression(columns, "Username") + ", " +
		workspaceColumnExpression(columns, "Domain") + ", " +
		"COALESCE(" + workspaceColumnExpression(columns, "Protocol") + ", 0), " +
		"COALESCE(" + workspaceColumnExpression(columns, "Kind") + ", 0), " +
		"COALESCE(" + workspaceColumnExpression(columns, "SecretProvider") + ", 0)" +
		" FROM \"CredentialProfiles\" WHERE lower(\"Id\") = ?;"
	var profile workspaceCredentialProfile
	rows, err := database.Query(query, normalizeID(credentialID))
	if err != nil {
		return workspaceCredentialProfile{}, false, fmt.Errorf("cannot read the workspace credential: %w", err)
	}
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return workspaceCredentialProfile{}, false, fmt.Errorf("cannot read the workspace credential: %w", err)
		}
		if err := rows.Close(); err != nil {
			return workspaceCredentialProfile{}, false, fmt.Errorf("cannot close the workspace credential: %w", err)
		}
		return workspaceCredentialProfile{}, false, nil
	}
	if err := rows.Scan(
		&profile.name,
		&profile.username,
		&profile.domain,
		&profile.protocol,
		&profile.kind,
		&profile.secretProvider,
	); err != nil {
		_ = rows.Close()
		return workspaceCredentialProfile{}, false, fmt.Errorf("cannot read the workspace credential: %w", err)
	}
	if rows.Next() {
		_ = rows.Close()
		return workspaceCredentialProfile{}, false, errors.New("workspace credential identifiers are ambiguous")
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return workspaceCredentialProfile{}, false, fmt.Errorf("cannot enumerate the workspace credential: %w", err)
	}
	if err := rows.Close(); err != nil {
		return workspaceCredentialProfile{}, false, fmt.Errorf("cannot close the workspace credential: %w", err)
	}
	return profile, true, nil
}

func workspaceProtocolCredentialValue(protocol int64) bool {
	return protocol == 0 || protocol == 1 || protocol == 6
}

func workspaceCredentialProtocolMatches(connectionProtocol, credentialProtocol int64) bool {
	return workspaceProtocolCredentialValue(connectionProtocol) && connectionProtocol == credentialProtocol
}

func showWorkspaceNodeCredentials(
	databasePath string,
	request workspaceNodeRequest,
	electronUserDataPath string,
) (workspaceCredentialRevealResponse, error) {
	nodeID, err := normalizeWorkspaceNodeID(request.NodeID)
	if err != nil {
		return workspaceCredentialRevealResponse{}, err
	}
	database, err := openDatabase(databasePath, true)
	if err != nil {
		return workspaceCredentialRevealResponse{}, err
	}
	if database == nil {
		return workspaceCredentialRevealResponse{}, errors.New("Wormhole database has no connections")
	}
	defer database.Close()

	nodes, err := loadWorkspaceCredentialNodes(database)
	if err != nil {
		return workspaceCredentialRevealResponse{}, err
	}
	root := nodes[nodeID]
	if root == nil || !root.kind.Valid || root.kind.Int64 != 1 {
		return workspaceCredentialRevealResponse{}, errors.New("workspace connection was not found")
	}

	response := workspaceCredentialRevealResponse{ConnectionName: root.name}
	protocol := int64(0)
	protocolSet := false
	username := ""
	credentialID := ""
	credentialResolved := root.useInlinePassword.Valid && root.useInlinePassword.Int64 != 0
	identityBoundary := false
	seen := make(map[string]struct{})
	current := root
	for current != nil {
		if _, duplicate := seen[current.id]; duplicate {
			return workspaceCredentialRevealResponse{}, errors.New("workspace connection tree contains a cycle")
		}
		seen[current.id] = struct{}{}
		if !protocolSet && current.protocol.Valid {
			protocol = current.protocol.Int64
			protocolSet = true
		}
		if !identityBoundary && username == "" && strings.TrimSpace(nullableString(current.username)) != "" {
			username = strings.TrimSpace(nullableString(current.username))
		}
		if !credentialResolved {
			if current.credentialMode.Valid {
				switch current.credentialMode.Int64 {
				case 1:
					credentialResolved = true
				case 2:
					credentialResolved = true
					credentialID = normalizeID(nullableString(current.credentialID))
					if credentialID != "" {
						identityBoundary = true
					}
				}
			} else if strings.TrimSpace(nullableString(current.credentialID)) != "" {
				credentialResolved = true
				credentialID = normalizeID(nullableString(current.credentialID))
				identityBoundary = true
			}
		}
		if current.parentID == "" {
			break
		}
		current = nodes[current.parentID]
	}

	if !workspaceProtocolCredentialValue(protocol) {
		return response, nil
	}
	if username != "" {
		response.Username = username
	}
	if credentialResolved && root.useInlinePassword.Valid && root.useInlinePassword.Int64 != 0 {
		if protocol != 0 && protocol != 1 {
			return response, nil
		}
		secret, err := readOptionalCredentialSecret(database, root.id, electronUserDataPath)
		if err != nil {
			return workspaceCredentialRevealResponse{}, fmt.Errorf("could not read the connection password: %w", err)
		}
		return workspaceCredentialRevealFromSecret(response, response.Username, "Password", secret), nil
	}
	if credentialID == "" {
		return response, nil
	}
	profile, found, err := loadWorkspaceCredentialProfile(database, credentialID)
	if err != nil {
		return workspaceCredentialRevealResponse{}, err
	}
	if !found || !profile.protocol.Valid || !workspaceCredentialProtocolMatches(protocol, profile.protocol.Int64) {
		return response, nil
	}
	if profile.secretProvider.Valid && profile.secretProvider.Int64 != 0 {
		return response, nil
	}
	if response.Username == "" {
		response.Username = strings.TrimSpace(nullableString(profile.username))
	}
	response.Domain = strings.TrimSpace(nullableString(profile.domain))
	response.CredentialName = strings.TrimSpace(nullableString(profile.name))
	secretLabel := "Password"
	if protocol == 0 && profile.kind.Valid && profile.kind.Int64 == 1 {
		secretLabel = "Key passphrase"
	} else if profile.kind.Valid && profile.kind.Int64 != 0 {
		return response, nil
	}
	secret, err := readOptionalCredentialSecret(database, credentialID, electronUserDataPath)
	if err != nil {
		return workspaceCredentialRevealResponse{}, fmt.Errorf("could not read the credential secret: %w", err)
	}
	return workspaceCredentialRevealFromSecret(response, response.Username, secretLabel, secret), nil
}

func workspaceCredentialRevealFromSecret(
	response workspaceCredentialRevealResponse,
	username, secretLabel string,
	secret []byte,
) workspaceCredentialRevealResponse {
	defer clearBytes(secret)
	if len(secret) == 0 {
		return response
	}
	response.Found = true
	response.Username = username
	response.SecretLabel = secretLabel
	response.Secret = string(secret)
	return response
}
