package main

import (
	"database/sql"
	"strings"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type legacyVaultNode struct {
	Metadata vaultstore.NodeMetadata
	Times    localvault.ImportTimes
}

type legacyVaultNodeKey struct{ id, storedID string }

// Source reservation and unpublished staging follow the credential reader's
// contract. Graph validation precedes every secret read. Parents are visited
// before children; notes/password slices are borrowed only until sink return.
func visitLegacyVaultNodes(reader resolverCaptureReader, electronUserDataPath string, visit func(legacyVaultNode, []localvault.SecretChange) error) error {
	return readLegacyVaultNodes(reader, electronUserDataPath, migrationSecretReader(reader.ctx, maxStoredCredentialBytes), visit)
}

func readLegacyVaultNodes(reader resolverCaptureReader, userData string, decrypt legacyVaultSecretReader, visit func(legacyVaultNode, []localvault.SecretChange) error) error {
	if decrypt == nil || visit == nil {
		return errVaultMigrationSource
	}
	hasSecrets, err := validateLegacyVaultSecretSource(reader)
	if err != nil {
		return err
	}
	order, err := readLegacyVaultNodeOrder(reader)
	if err != nil {
		return err
	}
	for _, id := range order {
		if err := borrowLegacyVaultNode(reader, id, hasSecrets, userData, decrypt, visit); err != nil {
			return err
		}
	}
	if reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	return nil
}

func readLegacyVaultNodeOrder(reader resolverCaptureReader) ([]legacyVaultNodeKey, error) {
	rows, err := reader.Query("SELECT " + shadowText("Id", 36) + "," + shadowText("ParentId", 36) + ",Kind FROM Nodes ORDER BY lower(Id),Id;")
	if err != nil {
		return nil, errVaultMigrationSource
	}
	type entry struct {
		storedID    string
		parent      string
		kind, depth int
		visiting    bool
	}
	nodes := map[string]*entry{}
	var ids []string
	for rows.Next() {
		var id string
		var parent sql.NullString
		var kind int
		if rows.Scan(&id, &parent, &kind) != nil {
			rows.Close()
			return nil, errVaultMigrationSource
		}
		storedID := id
		id = strings.ToLower(id)
		p := strings.ToLower(parent.String)
		if !vaultCredentialID(id) || (parent.Valid && !vaultCredentialID(p)) || (kind != 0 && kind != 1) || nodes[id] != nil {
			rows.Close()
			return nil, errVaultMigrationSource
		}
		nodes[id] = &entry{storedID: storedID, parent: p, kind: kind}
		ids = append(ids, id)
	}
	readErr := rows.Err()
	closeErr := rows.Close()
	if readErr != nil || closeErr != nil {
		return nil, errVaultMigrationSource
	}
	var ordered []legacyVaultNodeKey
	var walk func(string, int) error
	walk = func(id string, steps int) error {
		n := nodes[id]
		if n == nil || n.visiting || steps > vaultstore.MaxNodeDepth {
			return errVaultMigrationSource
		}
		if n.depth != 0 {
			return nil
		}
		n.visiting = true
		depth := 1
		if n.parent != "" {
			p := nodes[n.parent]
			if p == nil || p.kind != 0 {
				return errVaultMigrationSource
			}
			if err := walk(n.parent, steps+1); err != nil {
				return err
			}
			depth = p.depth + 1
		}
		if depth > vaultstore.MaxNodeDepth {
			return errVaultMigrationSource
		}
		n.depth = depth
		n.visiting = false
		ordered = append(ordered, legacyVaultNodeKey{id: id, storedID: n.storedID})
		return nil
	}
	for _, id := range ids {
		if reader.ctx.Err() != nil {
			return nil, errVaultMigrationSource
		}
		if err := walk(id, 1); err != nil {
			return nil, err
		}
	}
	return ordered, nil
}

func legacyVaultNodeColumns(n *vaultstore.NodeMetadata) ([]string, []any) {
	type field struct {
		column string
		target any
	}
	fields := []field{
		{shadowText("Id", 36), &n.ID}, {shadowText("ParentId", 36), &n.ParentID}, {shadowText("Name", 1024), &n.Name}, {"Kind", &n.Kind}, {"SortOrder", &n.SortOrder},
		{"Protocol", &n.Protocol}, {shadowText("Host", 16384), &n.Host}, {"Port", &n.Port}, {shadowText("HttpPath", 16384), &n.HTTPPath}, {shadowText("Username", 2048), &n.Username},
		{shadowText("CredentialId", 36), &n.CredentialID}, {"CredentialMode", &n.CredentialMode}, {"UseInlinePassword", &n.UseInlinePassword}, {"SshAutoSudo", &n.SshAutoSudo}, {"HttpIgnoreCertErrors", &n.HTTPIgnoreCertErrors},
		{"TunnelEnabled", &n.TunnelEnabled}, {shadowText("TunnelConfigId", 36), &n.TunnelConfigID}, {"SerialBaudRate", &n.SerialBaudRate}, {"SerialDataBits", &n.SerialDataBits}, {"SerialStopBits", &n.SerialStopBits}, {"SerialParity", &n.SerialParity}, {"SerialFlowControl", &n.SerialFlowControl},
		{shadowText("SshKeyFileName", 1024), &n.SshKeyFileName}, {shadowText("SshKnownHostFingerprint", 128), &n.SshKnownHostFingerprint}, {shadowText("RdpDomain", 2048), &n.RDPDomain}, {shadowText("RdpScreenSize", 128), &n.RDPScreenSize},
		{"RdpFullScreen", &n.RDPFullScreen}, {"RdpColorDepth", &n.RDPColorDepth}, {"RdpUseAllMonitors", &n.RDPUseAllMonitors}, {"RdpAudioMode", &n.RDPAudioMode}, {"RdpAudioCaptureMode", &n.RDPAudioCaptureMode}, {"RdpKeyboardHookMode", &n.RDPKeyboardHookMode},
		{"RdpRedirectClipboard", &n.RDPRedirectClipboard}, {"RdpRedirectPrinters", &n.RDPRedirectPrinters}, {"RdpRedirectSmartCards", &n.RDPRedirectSmartCards}, {"RdpRedirectPorts", &n.RDPRedirectPorts}, {"RdpRedirectDevices", &n.RDPRedirectDevices}, {shadowText("RdpRedirectDrives", 512), &n.RDPRedirectDrives},
		{"RdpConnectionSpeed", &n.RDPConnectionSpeed}, {"RdpDesktopBackground", &n.RDPDesktopBackground}, {"RdpFontSmoothing", &n.RDPFontSmoothing}, {"RdpDesktopComposition", &n.RDPDesktopComposition}, {"RdpWindowDrag", &n.RDPWindowDrag}, {"RdpMenuAnimation", &n.RDPMenuAnimation}, {"RdpVisualStyles", &n.RDPVisualStyles}, {"RdpBitmapCaching", &n.RDPBitmapCaching}, {"RdpAutoReconnect", &n.RDPAutoReconnect}, {"RdpServerAuthentication", &n.RDPServerAuthentication},
		{"RdpGatewayUsageMethod", &n.RDPGatewayUsageMethod}, {shadowText("RdpGatewayHostname", 4096), &n.RDPGatewayHostname}, {shadowText("RdpGatewayCredentialId", 36), &n.RDPGatewayCredentialID}, {"RdpGatewayBypassLocal", &n.RDPGatewayBypassLocal}, {"RdpGatewayUseSameCreds", &n.RDPGatewayUseSameCreds}, {"RdpUseExternalClient", &n.RDPUseExternalClient},
	}
	columns := make([]string, len(fields))
	targets := make([]any, len(fields))
	for i, f := range fields {
		columns[i], targets[i] = f.column, f.target
	}
	return columns, targets
}

func legacyVaultTimes(createdAt, updatedAt string) (localvault.ImportTimes, error) {
	var result localvault.ImportTimes
	for _, v := range []struct {
		input  string
		output *string
	}{{createdAt, &result.CreatedAt}, {updatedAt, &result.UpdatedAt}} {
		if len(v.input) > 128 {
			return localvault.ImportTimes{}, errVaultMigrationSource
		}
		t, err := time.Parse(time.RFC3339Nano, v.input)
		if err != nil || t.UTC().Year() < 0 || t.UTC().Year() > 9999 {
			return localvault.ImportTimes{}, errVaultMigrationSource
		}
		*v.output = t.UTC().Format(time.RFC3339Nano)
	}
	return result, nil
}

func borrowLegacyVaultNode(reader resolverCaptureReader, key legacyVaultNodeKey, hasSecrets bool, userData string, decrypt legacyVaultSecretReader, visit func(legacyVaultNode, []localvault.SecretChange) error) error {
	var record legacyVaultNode
	var notes []byte
	var changes []localvault.SecretChange
	defer func() { vault.Wipe(notes); wipeVaultCredentialChanges(changes) }()
	columns, targets := legacyVaultNodeColumns(&record.Metadata)
	var created, updated string
	columns = append(columns, shadowText("CreatedAt", 128), shadowText("UpdatedAt", 128), shadowText("Notes", 65536))
	targets = append(targets, &created, &updated, &notes)
	// The topology scan already rejected case-folded duplicates. Retaining the
	// exact source ID uses its primary-key index instead of rescanning per node.
	rows, err := reader.Query("SELECT "+strings.Join(columns, ",")+" FROM Nodes WHERE Id=? LIMIT 2;", key.storedID)
	if err != nil {
		return errVaultMigrationSource
	}
	if !rows.Next() || rows.Scan(targets...) != nil {
		rows.Close()
		return errVaultMigrationSource
	}
	duplicate := rows.Next()
	readErr := rows.Err()
	closeErr := rows.Close()
	if duplicate || readErr != nil || closeErr != nil {
		return errVaultMigrationSource
	}
	m := &record.Metadata
	m.ID = strings.ToLower(m.ID)
	for _, ref := range []*string{m.ParentID, m.CredentialID, m.TunnelConfigID, m.RDPGatewayCredentialID} {
		if ref != nil {
			*ref = strings.ToLower(*ref)
		}
	}
	if m.ID != key.id || m.Validate() != nil || !localvault.ValidNodeNotes(notes) {
		return errVaultMigrationSource
	}
	record.Times, err = legacyVaultTimes(created, updated)
	if err != nil {
		return err
	}
	if notes != nil {
		changes = append(changes, localvault.SecretChange{Field: "notes", Value: notes})
	}
	var encoded, encoding string
	var present bool
	if hasSecrets {
		encoded, encoding, present, err = readLegacyVaultSecretRow(reader, key.id)
		if err != nil {
			return err
		}
	}
	inline := m.UseInlinePassword != nil && *m.UseInlinePassword
	// Unused values go to the coordinator's orphan archive. An active inline
	// password must still exist; never replace a missing value with empty bytes.
	if (inline && !present) || reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	if inline {
		value, err := decrypt(key.id, encoded, encoding, userData)
		changes = append(changes, localvault.SecretChange{Field: "inlinePassword", Value: value})
		if err != nil || len(value) > maxStoredCredentialBytes {
			return errVaultMigrationSource
		}
	}
	if reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	if err := visit(record, changes); err != nil {
		return err
	}
	if reader.ctx.Err() != nil {
		return errVaultMigrationSource
	}
	return nil
}
