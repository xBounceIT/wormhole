package vault

import (
	"math"
	"strconv"

	"github.com/google/uuid"
)

// Display ciphertext cannot be used as a protocol or recovery bundle. The
// recipient is a one-use key owned by main's dedicated notes window.
func SealNotesDisplay(publicKey []byte, workspace, node, request string, revision uint64, notes []byte) (SealedBundle, error) {
	return sealEditorDisplay(publicKey, workspace, node, request, revision, notes, "wormhole/v1/notes-display", 65536)
}

// Tunnel editor projections have a distinct purpose and cannot be opened as
// notes, enrollment or protocol bundles.
func SealTunnelEditorDisplay(publicKey []byte, workspace, tunnel, request string, revision uint64, projection []byte) (SealedBundle, error) {
	return sealEditorDisplay(publicKey, workspace, tunnel, request, revision, projection, "wormhole/v1/tunnel-editor", 512*1024)
}

func sealEditorDisplay(publicKey []byte, workspace, node, request string, revision uint64, notes []byte, domain string, maximum int) (SealedBundle, error) {

	for _, id := range []string{workspace, node, request} {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id {
			return SealedBundle{}, ErrFormat
		}
	}
	if revision == 0 || revision > math.MaxInt64 || len(notes) > maximum {
		return SealedBundle{}, ErrFormat
	}
	info := canonical(domain, []byte(workspace), []byte(node), []byte(request), []byte(strconv.FormatUint(revision, 10)))
	return sealBundlePayload(publicKey, info, notes)
}

// Imported profiles have a separate recipient domain; only their redacted
// preview crosses it. A stage is bound to its editor, import ID and provider.
func SealTunnelImportDisplay(publicKey []byte, workspace, editor, importID string, kind int, projection []byte) (SealedBundle, error) {
	for _, id := range []string{workspace, editor, importID} {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id {
			return SealedBundle{}, ErrFormat
		}
	}
	if kind < 0 || kind > 9 || len(projection) > 512*1024 {
		return SealedBundle{}, ErrFormat
	}
	info := canonical("wormhole/v1/tunnel-import", []byte(workspace), []byte(editor), []byte(importID), []byte(strconv.Itoa(kind)))
	return sealBundlePayload(publicKey, info, projection)
}
