package vault

const MaxWebSessionArchiveBytes = 1024 * 1024

// SealWebSessionArchive is a one-use native handoff. Its recipient and request
// are selected by the browser owner, outside the ordinary renderer IPC.
func SealWebSessionArchive(publicKey []byte, workspace, node, request string, revision uint64, archive []byte) (SealedBundle, error) {
	if len(archive) == 0 {
		return SealedBundle{}, ErrFormat
	}
	return sealEditorDisplay(publicKey, workspace, node, request, revision, archive, "wormhole/v1/web-session-archive", MaxWebSessionArchiveBytes)
}
