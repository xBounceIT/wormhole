package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/pbkdf2"
)

const (
	mremoteNamespace                  = "http://mremoteng.org"
	mremoteDefaultPassword            = "mR3m"
	mremoteVerifier                   = "ThisIsProtected"
	mremoteMaxFileBytes               = 16 * 1024 * 1024
	mremoteMaxNodes                   = 50_000
	mremoteMaxDepth                   = 4096
	mremoteMaxIterations              = 10_000_000
	mremoteSilentDefaultMaxIterations = 250_000
	mremoteWarningLimit               = 50
	mremotePreviewLimit               = 250
)

type mremoteImportRequest struct {
	Path          string `json:"path"`
	Password      string `json:"password"`
	StructureOnly bool   `json:"structureOnly"`
	PlanNonce     string `json:"planNonce"`
	PlanToken     string `json:"planToken"`
}

type mremoteImportInspection struct {
	FileSize          int64  `json:"fileSize"`
	ConfVersion       string `json:"confVersion"`
	PasswordRequired  bool   `json:"passwordRequired"`
	FullFileEncrypted bool   `json:"fullFileEncrypted"`
}

type mremoteImportPreviewNode struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Protocol string `json:"protocol,omitempty"`
	Depth    int    `json:"depth"`
}

type mremoteImportPlanResponse struct {
	PlanToken                 string                     `json:"planToken"`
	Folders                   int                        `json:"folders"`
	Connections               int                        `json:"connections"`
	Credentials               int                        `json:"credentials"`
	SkippedUnsupported        int                        `json:"skippedUnsupported"`
	SkippedUnsupportedSamples []string                   `json:"skippedUnsupportedSamples"`
	Warnings                  []string                   `json:"warnings"`
	DroppedWarnings           int                        `json:"droppedWarnings"`
	Preview                   []mremoteImportPreviewNode `json:"preview"`
	PreviewTruncated          bool                       `json:"previewTruncated"`
}

type mremoteImportResult struct {
	FoldersCreated     int      `json:"foldersCreated"`
	ConnectionsCreated int      `json:"connectionsCreated"`
	CredentialsCreated int      `json:"credentialsCreated"`
	SkippedUnsupported int      `json:"skippedUnsupported"`
	Warnings           []string `json:"warnings"`
	DroppedWarnings    int      `json:"droppedWarnings"`
}

type mremoteXMLRoot struct {
	XMLName            xml.Name         `xml:"Connections"`
	ConfVersion        string           `xml:"ConfVersion,attr"`
	EncryptionEngine   string           `xml:"EncryptionEngine,attr"`
	BlockCipherMode    string           `xml:"BlockCipherMode,attr"`
	Protected          string           `xml:"Protected,attr"`
	FullFileEncryption string           `xml:"FullFileEncryption,attr"`
	KDFIterations      string           `xml:"KdfIterations,attr"`
	Nodes              []mremoteXMLNode `xml:"Node"`
}

type mremoteXMLNode struct {
	Type              string           `xml:"Type,attr"`
	Name              string           `xml:"Name,attr"`
	Description       string           `xml:"Descr,attr"`
	Protocol          string           `xml:"Protocol,attr"`
	Hostname          string           `xml:"Hostname,attr"`
	Port              string           `xml:"Port,attr"`
	Username          string           `xml:"Username,attr"`
	Domain            string           `xml:"Domain,attr"`
	Password          string           `xml:"Password,attr"`
	Resolution        string           `xml:"Resolution,attr"`
	InheritUsername   string           `xml:"InheritUsername,attr"`
	InheritDomain     string           `xml:"InheritDomain,attr"`
	InheritPassword   string           `xml:"InheritPassword,attr"`
	InheritHostname   string           `xml:"InheritHostname,attr"`
	InheritPort       string           `xml:"InheritPort,attr"`
	InheritProtocol   string           `xml:"InheritProtocol,attr"`
	InheritResolution string           `xml:"InheritResolution,attr"`
	Children          []mremoteXMLNode `xml:"Node"`
}

type mremotePlannedCredential struct {
	ID       string
	Name     string
	Protocol int64
	Username string
	Domain   string
	Password string
}

type mremotePlannedNode struct {
	ID            string
	ParentID      string
	Name          string
	Kind          int64
	SortOrder     int
	Protocol      sql.NullInt64
	Host          sql.NullString
	Port          sql.NullInt64
	Username      sql.NullString
	CredentialID  sql.NullString
	RDPDomain     sql.NullString
	RDPScreenSize sql.NullString
	RDPFullScreen sql.NullBool
}

type mremotePlan struct {
	FileHash         string
	Nodes            []mremotePlannedNode
	Credentials      []mremotePlannedCredential
	Folders          int
	Connections      int
	Skipped          int
	SkippedSamples   []string
	Warnings         []string
	DroppedWarnings  int
	Preview          []mremoteImportPreviewNode
	PreviewTruncated bool
}

func inspectMRemoteImport(request mremoteImportRequest) (mremoteImportInspection, error) {
	root, fileSize, _, err := readMRemoteFile(request.Path)
	if err != nil {
		return mremoteImportInspection{}, err
	}
	hasPasswordPayloads := mremoteHasPasswordPayload(root.Nodes)
	passwordRequired := hasPasswordPayloads && !mremoteUsesSilentDefault(root)
	return mremoteImportInspection{
		FileSize: fileSize, ConfVersion: safeMRemoteLabel(root.ConfVersion, 64), PasswordRequired: passwordRequired,
		FullFileEncrypted: attributeTrue(root.FullFileEncryption),
	}, nil
}

func analyzeMRemoteImport(databasePath string, request mremoteImportRequest) (mremoteImportPlanResponse, error) {
	return analyzeMRemoteImportContext(context.Background(), databasePath, request)
}

func analyzeMRemoteImportContext(ctx context.Context, databasePath string, request mremoteImportRequest) (mremoteImportPlanResponse, error) {
	if !validMRemotePlanNonce(request.PlanNonce) {
		return mremoteImportPlanResponse{}, errors.New("mRemoteNG import plan id is invalid")
	}
	plan, err := buildMRemotePlan(ctx, databasePath, request)
	if err != nil {
		return mremoteImportPlanResponse{}, err
	}
	token, err := mremotePlanToken(plan, request.PlanNonce)
	if err != nil {
		return mremoteImportPlanResponse{}, err
	}
	return mremoteImportPlanResponse{
		PlanToken: token, Folders: plan.Folders, Connections: plan.Connections,
		Credentials: len(plan.Credentials), SkippedUnsupported: plan.Skipped,
		SkippedUnsupportedSamples: plan.SkippedSamples, Warnings: plan.Warnings,
		DroppedWarnings: plan.DroppedWarnings, Preview: plan.Preview,
		PreviewTruncated: plan.PreviewTruncated,
	}, nil
}

func commitMRemoteImport(databasePath string, request mremoteImportRequest) (mremoteImportResult, error) {
	return commitMRemoteImportContext(context.Background(), databasePath, request)
}

func commitMRemoteImportContext(ctx context.Context, databasePath string, request mremoteImportRequest) (mremoteImportResult, error) {
	return commitMRemoteImportContextWithProgress(ctx, databasePath, request, nil)
}

func commitMRemoteImportContextWithProgress(
	ctx context.Context,
	databasePath string,
	request mremoteImportRequest,
	progress operationProgress,
) (mremoteImportResult, error) {
	if !validMRemotePlanNonce(request.PlanNonce) || !validSHA256(request.PlanToken) {
		return mremoteImportResult{}, errors.New("mRemoteNG import plan is invalid; analyze the file again")
	}
	reportOperationProgress(progress, "verifying", "Verifying the analyzed mRemoteNG plan…", 10)
	plan, err := buildMRemotePlan(ctx, databasePath, request)
	if err != nil {
		return mremoteImportResult{}, err
	}
	token, err := mremotePlanToken(plan, request.PlanNonce)
	if err != nil {
		return mremoteImportResult{}, err
	}
	if !strings.EqualFold(token, request.PlanToken) {
		return mremoteImportResult{}, errors.New("the mRemoteNG file or workspace changed after analysis; analyze it again")
	}
	reportOperationProgress(progress, "protecting", "Protecting imported credentials…", 45)

	database, err := openDatabase(databasePath, false)
	if err != nil {
		return mremoteImportResult{}, err
	}
	defer database.Close()
	if err := ensureCredentialWriteSchema(database); err != nil {
		return mremoteImportResult{}, err
	}
	if err := requireWorkspaceNodeWriteSchema(database); err != nil {
		return mremoteImportResult{}, err
	}

	type storedSecret struct{ id, encoded, encoding string }
	stored := make([]storedSecret, 0, len(plan.Credentials))
	cleanup := func() {
		for _, secret := range stored {
			if err := credentialSecretDelete(secret.id, secret.encoded, secret.encoding); err != nil {
				logWarn("could not remove protected secret for rolled back mRemoteNG credential %s", secret.id)
			}
		}
	}
	for index, credential := range plan.Credentials {
		if err := ctx.Err(); err != nil {
			cleanup()
			return mremoteImportResult{}, err
		}
		encoded, encoding, storeErr := credentialSecretStore(credential.ID, "", credential.Password)
		if storeErr != nil {
			cleanup()
			return mremoteImportResult{}, errors.New("could not protect an imported credential password; no changes were saved")
		}
		stored = append(stored, storedSecret{credential.ID, encoded, encoding})
		reportOperationProgress(
			progress,
			"protecting",
			"Protecting imported credentials…",
			progressBetween(45, 65, index+1, len(plan.Credentials)),
		)
	}

	tx, err := database.Begin()
	if err != nil {
		cleanup()
		return mremoteImportResult{}, fmt.Errorf("could not start mRemoteNG import: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	totalWrites := len(plan.Credentials) + len(plan.Nodes)
	completedWrites := 0
	for index, credential := range plan.Credentials {
		if err := ctx.Err(); err != nil {
			_ = tx.Rollback()
			cleanup()
			return mremoteImportResult{}, err
		}
		_, err = tx.Exec(`INSERT INTO CredentialProfiles
    (Id, Name, Username, Domain, Kind, PrivateKeyFileName, Protocol, SecretProvider,
     BitwardenItemId, BitwardenItemName, BitwardenFieldPath, CreatedAt)
VALUES (?, ?, ?, ?, 0, NULL, ?, 0, NULL, NULL, 'login.password', ?);`,
			credential.ID, credential.Name, nullableCredentialField(credential.Username),
			nullableCredentialField(credential.Domain), credential.Protocol, now)
		if err == nil {
			err = upsertCredentialSecret(tx, credential.ID, stored[index].encoded, stored[index].encoding)
		}
		if err != nil {
			_ = tx.Rollback()
			cleanup()
			return mremoteImportResult{}, normalizeMRemoteCommitError(err)
		}
		completedWrites++
		reportOperationProgress(progress, "committing", "Saving credentials and connections…", progressBetween(65, 95, completedWrites, totalWrites))
	}
	for _, node := range plan.Nodes {
		if err := ctx.Err(); err != nil {
			_ = tx.Rollback()
			cleanup()
			return mremoteImportResult{}, err
		}
		_, err = tx.Exec(`INSERT INTO Nodes (
    Id, ParentId, Name, Kind, SortOrder, Protocol, Host, Port, Username, CredentialId,
    CredentialMode, RdpDomain, RdpScreenSize, RdpFullScreen, CreatedAt, UpdatedAt)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`,
			node.ID, nullableWorkspaceNodeString(node.ParentID), node.Name, node.Kind, node.SortOrder,
			nullableWorkspaceNodeInt(node.Protocol), nullableWorkspaceNodeSQLString(node.Host),
			nullableWorkspaceNodeInt(node.Port), nullableWorkspaceNodeSQLString(node.Username),
			nullableWorkspaceNodeSQLString(node.CredentialID), credentialModeForImport(node.CredentialID),
			nullableWorkspaceNodeSQLString(node.RDPDomain), nullableWorkspaceNodeSQLString(node.RDPScreenSize),
			nullableMRemoteBool(node.RDPFullScreen), now, now)
		if err != nil {
			_ = tx.Rollback()
			cleanup()
			return mremoteImportResult{}, normalizeMRemoteCommitError(err)
		}
		completedWrites++
		reportOperationProgress(progress, "committing", "Saving credentials and connections…", progressBetween(65, 95, completedWrites, totalWrites))
	}
	if err := tx.Commit(); err != nil {
		cleanup()
		return mremoteImportResult{}, fmt.Errorf("could not commit mRemoteNG import; no changes were saved: %w", err)
	}
	committed = true
	reportOperationProgress(progress, "complete", "mRemoteNG import complete.", 100)
	return mremoteImportResult{
		FoldersCreated: plan.Folders, ConnectionsCreated: plan.Connections,
		CredentialsCreated: len(plan.Credentials), SkippedUnsupported: plan.Skipped,
		Warnings: plan.Warnings, DroppedWarnings: plan.DroppedWarnings,
	}, nil
}

func buildMRemotePlan(ctx context.Context, databasePath string, request mremoteImportRequest) (mremotePlan, error) {
	if err := ctx.Err(); err != nil {
		return mremotePlan{}, err
	}
	root, _, fileHash, err := readMRemoteFile(request.Path)
	if err != nil {
		return mremotePlan{}, err
	}
	if attributeTrue(root.FullFileEncryption) {
		return mremotePlan{}, errors.New("full-file encrypted mRemoteNG exports are not supported; re-export with Encrypt Connections File disabled")
	}
	iterations := 1000
	if root.KDFIterations != "" {
		parsed, parseErr := strconv.Atoi(root.KDFIterations)
		if parseErr != nil || parsed <= 0 || parsed > mremoteMaxIterations {
			return mremotePlan{}, errors.New("mRemoteNG KDF iteration count is invalid")
		}
		iterations = parsed
	}
	hasPasswords := mremoteHasPasswordPayload(root.Nodes)
	password := request.Password
	if hasPasswords && !request.StructureOnly {
		if !strings.EqualFold(strings.TrimSpace(root.EncryptionEngine), "AES") ||
			!strings.EqualFold(strings.TrimSpace(root.BlockCipherMode), "GCM") {
			return mremotePlan{}, errors.New("only AES-GCM mRemoteNG password encryption is supported")
		}
		if strings.TrimSpace(root.Protected) == "" {
			return mremotePlan{}, errors.New("this mRemoteNG export has no password verifier")
		}
		if password == "" {
			if plain, ok := decryptMRemote(root.Protected, mremoteDefaultPassword, iterations); ok && plain == mremoteVerifier {
				password = mremoteDefaultPassword
			}
		}
		plain, ok := decryptMRemote(root.Protected, password, iterations)
		if !ok || plain != mremoteVerifier {
			return mremotePlan{}, errors.New("the mRemoteNG encryption password is incorrect")
		}
	}

	database, err := openDatabase(databasePath, true)
	if err != nil {
		return mremotePlan{}, err
	}
	defer database.Close()
	existingNames := map[string]struct{}{}
	rows, err := database.QueryContext(ctx, "SELECT Name FROM CredentialProfiles;")
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "no such table") {
		return mremotePlan{}, fmt.Errorf("could not inspect existing credentials: %w", err)
	}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			if err := ctx.Err(); err != nil {
				return mremotePlan{}, err
			}
			var name string
			if scanErr := rows.Scan(&name); scanErr != nil {
				return mremotePlan{}, scanErr
			}
			existingNames[name] = struct{}{}
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			return mremotePlan{}, rowsErr
		}
	}
	rootSort := 0
	if err := database.QueryRowContext(ctx, "SELECT COALESCE(MAX(SortOrder), -1) + 1 FROM Nodes WHERE ParentId IS NULL;").Scan(&rootSort); err != nil && !strings.Contains(strings.ToLower(err.Error()), "no such table") {
		return mremotePlan{}, fmt.Errorf("could not inspect workspace order: %w", err)
	}

	plan := mremotePlan{FileHash: fileHash, Nodes: make([]mremotePlannedNode, 0), Credentials: make([]mremotePlannedCredential, 0)}
	fingerprints := map[string]string{}
	sequence := 0
	type frame struct {
		node        mremoteXMLNode
		parentID    string
		sort, depth int
		path        string
	}
	stack := make([]frame, 0, len(root.Nodes))
	for index := len(root.Nodes) - 1; index >= 0; index-- {
		stack = append(stack, frame{root.Nodes[index], "", rootSort + index, 1, strconv.Itoa(index)})
	}
	for len(stack) > 0 {
		if err := ctx.Err(); err != nil {
			return mremotePlan{}, err
		}
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current.depth > mremoteMaxDepth {
			return mremotePlan{}, errors.New("mRemoteNG nesting depth exceeds the supported limit")
		}
		sequence++
		if sequence > mremoteMaxNodes {
			return mremotePlan{}, errors.New("mRemoteNG file contains too many nodes")
		}
		kind, recognized := mremoteNodeKind(current.node.Type)
		if !recognized {
			continue
		}
		protocol, mapped := mremoteProtocol(current.node.Protocol)
		if kind == workspaceNodeConnection && !mapped {
			plan.Skipped++
			if len(plan.SkippedSamples) < 5 {
				label := safeMRemoteLabel(current.node.Protocol, 128)
				if label == "" {
					label = "(unspecified)"
				}
				plan.SkippedSamples = append(plan.SkippedSamples, displayMRemoteName(current.node, kind)+": "+label)
			}
			continue
		}
		id := deterministicMRemoteID(request.PlanNonce, "node", current.path)
		node := mremotePlannedNode{ID: id, ParentID: current.parentID, Name: displayMRemoteName(current.node, kind), Kind: kind, SortOrder: current.sort}
		credentialProtocol := protocol
		if mapped && !attributeTrue(current.node.InheritProtocol) {
			node.Protocol = sql.NullInt64{Int64: protocol, Valid: true}
		}
		if !attributeTrue(current.node.InheritHostname) {
			node.Host = nullableMRemoteText(current.node.Hostname, 4096)
		}
		if !attributeTrue(current.node.InheritPort) {
			node.Port = parseMRemotePort(current.node.Port)
		}
		if !attributeTrue(current.node.InheritUsername) && protocol != 6 {
			node.Username = nullableMRemoteText(current.node.Username, maxCredentialUsernameLength)
		}
		if (protocol == 1 || !mapped) && !attributeTrue(current.node.InheritDomain) {
			node.RDPDomain = nullableMRemoteText(current.node.Domain, maxCredentialDomainLength)
		}
		if (protocol == 1 || !mapped) && !attributeTrue(current.node.InheritResolution) {
			node.RDPScreenSize, node.RDPFullScreen = mapMRemoteResolution(current.node.Resolution)
		}

		if !attributeTrue(current.node.InheritPassword) && strings.TrimSpace(current.node.Password) != "" {
			if request.StructureOnly {
				addMRemoteWarning(&plan, fmt.Sprintf("Password for '%s' was not imported in structure-only mode.", node.Name))
			} else if plain, ok := decryptMRemote(current.node.Password, password, iterations); !ok {
				addMRemoteWarning(&plan, fmt.Sprintf("Could not decrypt password for '%s'; credential left unset.", node.Name))
			} else if plain != "" {
				if utf8.RuneCountInString(plain) > maxStoredCredentialPassword || len(plain) > maxStoredCredentialBytes {
					addMRemoteWarning(&plan, fmt.Sprintf("Password for '%s' exceeds Wormhole's protected credential limit; credential left unset.", node.Name))
				} else if mapped {
					username := nullableString(node.Username)
					domain := nullableString(node.RDPDomain)
					fingerprint := fmt.Sprintf("%s\x00%s\x00%s\x00%d", username, domain, plain, credentialProtocol)
					credentialID := fingerprints[fingerprint]
					if credentialID == "" {
						credentialID = deterministicMRemoteID(request.PlanNonce, "credential", strconv.Itoa(len(plan.Credentials)))
						name := allocateMRemoteCredentialName(username, nullableString(node.Host), node.Name, credentialProtocol, existingNames)
						plan.Credentials = append(plan.Credentials, mremotePlannedCredential{credentialID, name, credentialProtocol, username, domain, plain})
						fingerprints[fingerprint] = credentialID
					}
					node.CredentialID = sql.NullString{String: credentialID, Valid: true}
				} else {
					addMRemoteWarning(&plan, fmt.Sprintf("Folder '%s' had a password but no supported protocol; password not imported.", node.Name))
				}
			}
		}
		plan.Nodes = append(plan.Nodes, node)
		if kind == workspaceNodeFolder {
			plan.Folders++
		} else {
			plan.Connections++
		}
		if len(plan.Preview) < mremotePreviewLimit {
			previewProtocol := ""
			if node.Protocol.Valid {
				previewProtocol = protocolName(node.Protocol)
			}
			previewKind := "connection"
			if kind == workspaceNodeFolder {
				previewKind = "folder"
			}
			plan.Preview = append(plan.Preview, mremoteImportPreviewNode{Name: node.Name, Kind: previewKind, Protocol: previewProtocol, Depth: current.depth})
		} else {
			plan.PreviewTruncated = true
		}
		if kind == workspaceNodeFolder {
			for index := len(current.node.Children) - 1; index >= 0; index-- {
				stack = append(stack, frame{current.node.Children[index], id, index, current.depth + 1, current.path + "/" + strconv.Itoa(index)})
			}
		}
	}
	return plan, nil
}

func mremoteUsesSilentDefault(root mremoteXMLRoot) bool {
	iterations := 1000
	if root.KDFIterations != "" {
		parsed, err := strconv.Atoi(root.KDFIterations)
		if err != nil || parsed <= 0 || parsed > mremoteMaxIterations {
			return false
		}
		iterations = parsed
	}
	if iterations > mremoteSilentDefaultMaxIterations {
		return false
	}
	for _, password := range []string{mremoteDefaultPassword, ""} {
		if plain, ok := decryptMRemote(root.Protected, password, iterations); ok && plain == mremoteVerifier {
			return true
		}
	}
	return false
}

func readMRemoteFile(path string) (mremoteXMLRoot, int64, string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return mremoteXMLRoot{}, 0, "", errors.New("mRemoteNG file path is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return mremoteXMLRoot{}, 0, "", errors.New("the selected mRemoteNG file is unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return mremoteXMLRoot{}, 0, "", errors.New("the selected mRemoteNG path is not a regular file")
	}
	if info.Size() <= 0 {
		return mremoteXMLRoot{}, 0, "", errors.New("the selected mRemoteNG file is empty")
	}
	if info.Size() > mremoteMaxFileBytes {
		return mremoteXMLRoot{}, 0, "", fmt.Errorf("mRemoteNG file exceeds the %d MiB limit", mremoteMaxFileBytes/(1024*1024))
	}
	limited := io.LimitReader(file, mremoteMaxFileBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return mremoteXMLRoot{}, 0, "", errors.New("could not read the selected mRemoteNG file")
	}
	if int64(len(data)) > mremoteMaxFileBytes {
		return mremoteXMLRoot{}, 0, "", errors.New("mRemoteNG file exceeds the input limit")
	}
	if err := validateMRemoteXMLStructure(data); err != nil {
		return mremoteXMLRoot{}, 0, "", err
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	var root mremoteXMLRoot
	if err := decoder.Decode(&root); err != nil {
		return mremoteXMLRoot{}, 0, "", errors.New("file is not valid mRemoteNG XML")
	}
	if root.XMLName.Local != "Connections" || root.XMLName.Space != mremoteNamespace {
		return mremoteXMLRoot{}, 0, "", errors.New("file is not an mRemoteNG Connections export")
	}
	hash := sha256.Sum256(data)
	return root, int64(len(data)), hex.EncodeToString(hash[:]), nil
}

func validateMRemoteXMLStructure(data []byte) error {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	depth, nodes := 0, 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return errors.New("file is not valid mRemoteNG XML")
		}
		switch value := token.(type) {
		case xml.StartElement:
			depth++
			if depth > mremoteMaxDepth+1 {
				return errors.New("mRemoteNG nesting depth exceeds the supported limit")
			}
			if value.Name.Local == "Node" {
				nodes++
				if nodes > mremoteMaxNodes {
					return errors.New("mRemoteNG file contains too many nodes")
				}
			}
		case xml.EndElement:
			depth--
		case xml.Directive:
			return errors.New("mRemoteNG XML directives are not supported")
		}
	}
}

func decryptMRemote(encoded, password string, iterations int) (string, bool) {
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(blob) < 48 || iterations <= 0 || iterations > mremoteMaxIterations {
		return "", false
	}
	salt, nonce := blob[:16], blob[16:32]
	key := pbkdf2.Key([]byte(password), salt, iterations, 32, sha1.New)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", false
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return "", false
	}
	plain, err := gcm.Open(nil, nonce, blob[32:], salt)
	if err != nil || !utf8.Valid(plain) {
		return "", false
	}
	return string(plain), true
}

func mremotePlanToken(plan mremotePlan, nonce string) (string, error) {
	type safeCredential struct {
		ID, Name, Username, Domain string
		Protocol                   int64
	}
	safeCredentials := make([]safeCredential, 0, len(plan.Credentials))
	for _, item := range plan.Credentials {
		safeCredentials = append(safeCredentials, safeCredential{item.ID, item.Name, item.Username, item.Domain, item.Protocol})
	}
	payload, err := json.Marshal(struct {
		FileHash, Nonce string
		Nodes           []mremotePlannedNode
		Credentials     []safeCredential
		Skipped         int
	}{plan.FileHash, nonce, plan.Nodes, safeCredentials, plan.Skipped})
	if err != nil {
		return "", errors.New("could not create mRemoteNG import plan")
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func deterministicMRemoteID(nonce, kind, path string) string {
	digest := sha256.Sum256([]byte(nonce + "\x00" + kind + "\x00" + path))
	b := digest[:16]
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func mremoteHasPasswordPayload(nodes []mremoteXMLNode) bool {
	for _, n := range nodes {
		if !attributeTrue(n.InheritPassword) && strings.TrimSpace(n.Password) != "" {
			return true
		}
		if mremoteHasPasswordPayload(n.Children) {
			return true
		}
	}
	return false
}
func attributeTrue(value string) bool         { return strings.EqualFold(strings.TrimSpace(value), "true") }
func validMRemotePlanNonce(value string) bool { return validCredentialID(normalizeID(value)) }
func validSHA256(value string) bool {
	_, err := hex.DecodeString(value)
	return len(value) == 64 && err == nil
}
func mremoteNodeKind(value string) (int64, bool) {
	if strings.EqualFold(strings.TrimSpace(value), "Container") {
		return workspaceNodeFolder, true
	}
	if strings.EqualFold(strings.TrimSpace(value), "Connection") {
		return workspaceNodeConnection, true
	}
	return 0, false
}
func mremoteProtocol(value string) (int64, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ssh", "ssh1", "ssh2":
		return 0, true
	case "rdp":
		return 1, true
	case "vnc":
		return 6, true
	default:
		return 0, false
	}
}
func displayMRemoteName(node mremoteXMLNode, kind int64) string {
	name := strings.TrimSpace(node.Name)
	if name != "" && utf8.RuneCountInString(name) <= 256 && !strings.ContainsFunc(name, unicode.IsControl) {
		return name
	}
	if kind == workspaceNodeFolder {
		return "Folder"
	}
	if host := strings.TrimSpace(node.Hostname); host != "" && !strings.ContainsFunc(host, unicode.IsControl) {
		return truncateMRemote(host, 256)
	}
	return "Connection"
}
func truncateMRemote(value string, max int) string {
	r := []rune(value)
	if len(r) > max {
		return string(r[:max])
	}
	return value
}
func safeMRemoteLabel(value string, max int) string {
	value = strings.TrimSpace(value)
	value = strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return -1
		}
		return character
	}, value)
	return truncateMRemote(value, max)
}
func nullableMRemoteText(value string, max int) sql.NullString {
	value = strings.TrimSpace(value)
	if value == "" || utf8.RuneCountInString(value) > max || strings.ContainsFunc(value, unicode.IsControl) {
		return sql.NullString{}
	}
	return sql.NullString{String: value, Valid: true}
}
func parseMRemotePort(value string) sql.NullInt64 {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || port <= 0 || port > 65535 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(port), Valid: true}
}
func mapMRemoteResolution(value string) (sql.NullString, sql.NullBool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return sql.NullString{}, sql.NullBool{}
	}
	if strings.EqualFold(value, "FullScreen") {
		return sql.NullString{String: "Full connection content", Valid: true}, sql.NullBool{Bool: true, Valid: true}
	}
	if strings.EqualFold(value, "FitToWindow") {
		return sql.NullString{String: "Full connection content", Valid: true}, sql.NullBool{Bool: false, Valid: true}
	}
	if len(value) > 128 || strings.ContainsFunc(value, unicode.IsControl) {
		return sql.NullString{}, sql.NullBool{}
	}
	return sql.NullString{String: value, Valid: true}, sql.NullBool{Bool: false, Valid: true}
}
func addMRemoteWarning(plan *mremotePlan, warning string) {
	if len(plan.Warnings) < mremoteWarningLimit {
		plan.Warnings = append(plan.Warnings, warning)
	} else {
		plan.DroppedWarnings++
	}
}

var mremoteNameSanitizer = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func allocateMRemoteCredentialName(username, host, fallback string, protocol int64, taken map[string]struct{}) string {
	user := strings.Trim(mremoteNameSanitizer.ReplaceAllString(strings.TrimSpace(username), "-"), "-")
	if len(user) > 60 {
		user = user[:60]
	}
	anchor := strings.Trim(mremoteNameSanitizer.ReplaceAllString(strings.TrimSpace(host), "-"), "-")
	if anchor == "" {
		anchor = strings.Trim(mremoteNameSanitizer.ReplaceAllString(fallback, "-"), "-")
	}
	if len(anchor) > 60 {
		anchor = anchor[:60]
	}
	stem := "mremoteng-" + user + "@" + anchor
	if user == "" {
		stem = "mremoteng-" + anchor + "-" + protocolName(sql.NullInt64{Int64: protocol, Valid: true})
	}
	for n := 1; ; n++ {
		candidate := stem
		if n > 1 {
			candidate = fmt.Sprintf("%s-%d", stem, n)
		}
		if _, exists := taken[candidate]; !exists {
			taken[candidate] = struct{}{}
			return candidate
		}
	}
}
func nullableMRemoteBool(value sql.NullBool) any {
	if !value.Valid {
		return nil
	}
	if value.Bool {
		return int64(1)
	}
	return int64(0)
}
func credentialModeForImport(value sql.NullString) any {
	if value.Valid {
		return int64(2)
	}
	return nil
}
func normalizeMRemoteCommitError(err error) error {
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "unique") && strings.Contains(lower, "credentialprofiles.name") {
		return errors.New("a credential name was created after analysis; analyze the mRemoteNG file again")
	}
	return fmt.Errorf("mRemoteNG import failed; no changes were saved: %w", err)
}
