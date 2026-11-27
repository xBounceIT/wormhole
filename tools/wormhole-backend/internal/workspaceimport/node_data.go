package workspaceimport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const MaxNodeDataBytes = 32768

const (
	legacyNodeDataFormat = 1
	viewKeyNoteFormat    = 2
)

// NodeData contains only account metadata and a note revision. It carries no
// credential or note values, and grants no right to fetch them.
type NodeData struct {
	FormatVersion uint16                                 `json:"formatVersion"`
	NodeID        string                                 `json:"nodeId"`
	NoteVersion   uint64                                 `json:"noteVersion"`
	Pins          []resolver.EffectiveCredentialSnapshot `json:"pins"`
}

// NotePurpose derives the wrapping purpose from the authenticated attachment.
// The original format retains its existing secret-root wrapping.
func (d *NodeData) NotePurpose() vault.BoundaryPurpose {
	if d == nil || d.NoteVersion == 0 {
		return ""
	}
	if d.FormatVersion == viewKeyNoteFormat {
		return vault.BoundaryView
	}
	return vault.BoundarySecret
}

// DecodeNodeData binds the original native JSON bytes to an already verified
// node seal. A signed reference makes the attachment mandatory.
func DecodeNodeData(metadata vaultstore.NodeMetadata, raw []byte) (*NodeData, error) {
	if metadata.Imported == nil && raw == nil {
		return nil, nil
	}
	if metadata.Imported == nil || len(raw) == 0 || len(raw) > MaxNodeDataBytes {
		return nil, vault.ErrFormat
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != metadata.Imported.Digest {
		return nil, vault.ErrAuthentication
	}
	var data NodeData
	if json.Unmarshal(raw, &data) != nil {
		return nil, vault.ErrFormat
	}
	if data.FormatVersion > viewKeyNoteFormat {
		return nil, vault.ErrNewerFormat
	}
	// Marshal uses the same schema as the writer. Equality rejects duplicate
	// keys, aliases, ignored fields, and alternate JSON interpretations.
	canonical, err := json.Marshal(data)
	if err != nil || !bytes.Equal(raw, canonical) ||
		(data.FormatVersion == legacyNodeDataFormat && metadata.Imported.NoteVersion != 0) ||
		(data.FormatVersion != legacyNodeDataFormat && (data.FormatVersion != viewKeyNoteFormat || data.NoteVersion != 1 || metadata.Imported.NoteVersion != data.NoteVersion)) ||
		data.NodeID != metadata.ID || data.NoteVersion > 1 || data.Pins == nil || len(data.Pins) > 3 ||
		metadata.Imported.RetainedPins != (len(data.Pins) > 0) || (data.NoteVersion == 0 && len(data.Pins) == 0) {
		return nil, vault.ErrFormat
	}
	previousPath := ""
	for _, pin := range data.Pins {
		if metadata.Kind != 1 || !pin.ValidMigrationIdentity() || pin.NodeID != data.NodeID || pin.ResolverVersion != 0 ||
			pin.ProtocolPath <= previousPath || (metadata.Protocol != nil && !resolver.PathAllowed(*metadata.Protocol, pin.ProtocolPath)) {
			return nil, resolver.ErrImportedPins
		}
		previousPath = pin.ProtocolPath
	}
	return &data, nil
}
