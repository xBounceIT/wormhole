package vault

import (
	"bytes"
	"unicode/utf8"
)

// Clipboard releases are sealed to a one-use main-process key on Linux. The
// selected field is part of the HPKE purpose; TTL is authenticated plaintext.
func SealClipboardRelease(publicKey []byte, workspace, node, request string, revision uint64, field string, seconds int, value []byte) (SealedBundle, error) {
	if (field != "username" && field != "domain" && field != "secret") || (seconds != 20 && seconds != 30) || len(value) == 0 || len(value) > 16384 || !utf8.Valid(value) || bytes.IndexByte(value, 0) >= 0 {
		return SealedBundle{}, ErrFormat
	}
	raw := make([]byte, 2+len(value))
	defer Wipe(raw)
	raw[0], raw[1] = 1, byte(seconds)
	copy(raw[2:], value)
	return sealEditorDisplay(publicKey, workspace, node, request, revision, raw, "wormhole/v1/clipboard/"+field, 16386)
}
