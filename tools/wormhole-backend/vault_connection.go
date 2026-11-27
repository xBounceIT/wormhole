package main

import (
	"context"
	"encoding/json"
	"math"
	"runtime"
	"strconv"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Metadata and secret bytes have separate allowlists. The ordinary response
// contains only the committed node ID/version, never notes or passwords.
func (h *vaultFoundationHandler) saveConnection(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if h.owner == nil || len(payload) > 256*1024 {
		return nil, vaultwire.ErrProtocol
	}
	var metadata, rawPassword, rawNotes json.RawMessage
	var version, notesAction string
	defer func() { vault.Wipe(metadata); vault.Wipe(rawPassword); vault.Wipe(rawNotes) }()
	if decodeVaultObject(payload, map[string]any{"metadata": &metadata, "rowVersion": &version, "password": &rawPassword, "notes": &rawNotes, "notesAction": &notesAction}, "metadata", "rowVersion", "password", "notes", "notesAction") != nil {
		return nil, vaultwire.ErrProtocol
	}
	var password, notes []byte
	defer func() { vault.Wipe(password); vault.Wipe(notes) }()
	if len(rawPassword) == 0 || rawPassword[0] != '"' || len(rawNotes) == 0 || rawNotes[0] != '"' || json.Unmarshal(rawPassword, &password) != nil || json.Unmarshal(rawNotes, &notes) != nil || !utf8.Valid(password) || utf8.RuneCount(password) > 4096 || !localvault.ValidNodeNotes(notes) {
		return nil, vaultwire.ErrProtocol
	}
	if (notesAction != "preserve" && notesAction != "set" && notesAction != "clear") || (notesAction != "set" && len(notes) != 0) {
		return nil, vaultwire.ErrProtocol
	}
	request, err := decodeVaultConnectionMetadata(metadata)
	if err != nil {
		return nil, err
	}
	revision, err := vaultCredentialRevision(version, true)
	if err != nil || revision == math.MaxInt64 || (revision == 0) != (request.ID == "") {
		return nil, vaultwire.ErrProtocol
	}
	action := request.InlinePasswordAction
	if (action != "preserve" && action != "set" && action != "clear") || ((action == "set") != (len(password) != 0)) {
		return nil, vaultwire.ErrProtocol
	}
	if revision == 0 {
		request.ID = uuid.NewString()
	}
	// The shared metadata normalizer checks inline eligibility without creating an
	// immutable Go string containing the supplied password.
	if action == "set" {
		request.InlinePasswordAction = "preserve"
	}
	n, err := normalizeWorkspaceNodeFields(request, true)
	if err != nil || (action != "clear" && n.inlinePasswordAction != "preserve") {
		return nil, vaultwire.ErrProtocol
	}
	old := vaultstore.Node{NodeMetadata: vaultstore.NodeMetadata{ID: request.ID, Kind: 1}}
	if revision != 0 {
		old, err = h.owner.ReadNode(ctx, request.ID, 0)
		if err != nil {
			return h.domainResult(nil, err)
		}
		if old.Kind != 1 || old.RowVersion != revision {
			return nil, vaultstore.ErrConflict
		}
	} else {
		old.SortOrder, err = h.nextNodeSortOrder(ctx, request.ParentID)
		if err != nil {
			return h.domainResult(nil, err)
		}
	}
	present := make(map[string]bool, len(old.Fields))
	for _, f := range old.Fields {
		present[f.Field] = f.Present
	}
	// A migrated connection needs its explicit pin decision in the same commit.
	// Until that UI is connected, do not acknowledge an editor credential change
	// while a hidden keep-legacy choice would still override it at connection time.
	if present[vaultstore.NodeResolverMigrationField] {
		migration, err := h.owner.ReadResolverMigration(ctx, old.ID, revision)
		if err != nil {
			return h.domainResult(nil, err)
		}
		for _, entry := range migration.Entries {
			if entry.Choice == "keep" {
				return nil, vault.ErrPolicy
			}
		}
	}
	if action == "preserve" && !present["inlinePassword"] {
		return nil, vaultwire.ErrProtocol
	}
	m := vaultConnectionMetadata(old.NodeMetadata, n)
	plan, err := h.previewConnection(ctx, m)
	if err != nil {
		return h.domainResult(nil, err)
	}
	if n.rdp != nil && resolver.RequiresExternalRDP(runtime.GOOS, plan) {
		required := true
		m.RDPUseExternalClient = &required
	}
	changes := make([]localvault.SecretChange, 0, 2)
	for _, field := range []struct {
		name, action string
		value        []byte
	}{{"inlinePassword", action, password}, {"notes", notesAction, notes}} {
		if field.action == "set" {
			changes = append(changes, localvault.SecretChange{Field: field.name, Value: field.value})
		} else if field.action == "clear" && present[field.name] {
			changes = append(changes, localvault.SecretChange{Field: field.name, Remove: true})
		}
	}
	saved, err := h.owner.PutNode(ctx, m, changes, revision)
	return h.domainResult(struct {
		NodeID     string `json:"nodeId"`
		RowVersion string `json:"rowVersion"`
		Updated    bool   `json:"updated"`
	}{saved.ID, strconv.FormatUint(saved.RowVersion, 10), true}, err)
}

// Resolve a proposed leaf against authenticated current parents/credentials.
// The serialized native handler owns the database throughout this operation.
func (h *vaultFoundationHandler) previewConnection(ctx context.Context, leaf vaultstore.NodeMetadata) (resolver.Plan, error) {
	chain := []vaultstore.NodeMetadata{leaf}
	seen := map[string]bool{leaf.ID: true}
	for parent := leaf.ParentID; parent != nil; {
		if seen[*parent] || len(chain) >= vaultstore.MaxNodeDepth {
			return resolver.Plan{}, resolver.ErrChain
		}
		seen[*parent] = true
		node, err := h.owner.ReadNode(ctx, *parent, 0)
		if err != nil {
			return resolver.Plan{}, err
		}
		chain = append(chain, node.NodeMetadata)
		parent = node.ParentID
	}
	plan, err := resolver.Resolve(chain, "")
	if err != nil {
		return resolver.Plan{}, err
	}
	if plan.Credential.Kind == "slot" {
		return resolver.Plan{}, vault.ErrPolicy
	}
	if plan.Credential.Kind == "saved" {
		credential, err := h.owner.ReadCredential(ctx, plan.Credential.ID, 0)
		if err != nil {
			return resolver.Plan{}, err
		}
		plan, err = resolver.ApplyCredential(plan, credential.CredentialMetadata)
		if err != nil {
			return resolver.Plan{}, err
		}
	}
	if plan.GatewayCredentialID != "" {
		credential, err := h.owner.ReadCredential(ctx, plan.GatewayCredentialID, 0)
		if err != nil {
			return resolver.Plan{}, err
		}
		if credential.Protocol != "rdp" {
			return resolver.Plan{}, resolver.ErrCredential
		}
	}
	return plan, nil
}
