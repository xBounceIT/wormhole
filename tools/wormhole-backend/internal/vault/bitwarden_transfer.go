package vault

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math"
	"strconv"
	"unicode/utf8"
)

const MaxBrowserTransferArea = 8 * 1024 * 1024
const MaxBrowserTransferFrame = 10 + 2*MaxBrowserTransferArea

// Public context for one native transfer, never an application renderer grant.
// Both ephemeral recipients and the native-generated transfer identity are bound
// to every independently sealed chunk. Decimal revisions retain all int64 bits.
type BrowserTransferContext struct {
	WorkspaceID      string `json:"workspaceId"`
	FileID           string `json:"fileId"`
	ProfileID        string `json:"profileId"`
	RequestID        string `json:"requestId"`
	TransferID       string `json:"transferId"`
	Epoch            uint64 `json:"epoch"`
	PolicySequence   string `json:"policySequence"`
	Action           string `json:"action"`
	SourceRevision   string `json:"sourceRevision"`
	CapturePublicKey []byte `json:"capturePublicKey"`
	RestorePublicKey []byte `json:"restorePublicKey"`
}
type BrowserTransferManifest struct {
	Bytes    int    `json:"bytes"`
	Revision string `json:"revision"`
	Restore  bool   `json:"restore"`
}
type BrowserTransferPacket struct {
	Context   BrowserTransferContext  `json:"context"`
	Direction string                  `json:"direction"`
	Manifest  BrowserTransferManifest `json:"manifest"`
	Index     int                     `json:"index"`
	Bundle    SealedBundle            `json:"bundle"`
}
type BrowserTransferPayload struct{ LocalJSON, SessionJSON []byte }

func (BrowserTransferPayload) MarshalJSON() ([]byte, error) { return nil, ErrPolicy }
func browserDecimal(raw string, zero bool) (uint64, error) {
	if len(raw) == 0 || len(raw) > 19 {
		return 0, ErrFormat
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || value > math.MaxInt64 || (!zero && value == 0) || strconv.FormatUint(value, 10) != raw {
		return 0, ErrFormat
	}
	return value, nil
}
func (c BrowserTransferContext) Validate() error {
	for _, id := range []string{c.WorkspaceID, c.FileID, c.ProfileID, c.RequestID, c.TransferID} {
		if !canonicalID(id) {
			return ErrFormat
		}
	}
	if c.Epoch == 0 || c.Epoch > 9007199254740991 || (c.Action != "hydrate" && c.Action != "capture") || len(c.CapturePublicKey) != 32 || len(c.RestorePublicKey) != 32 {
		return ErrFormat
	}
	if _, err := browserDecimal(c.PolicySequence, false); err != nil {
		return err
	}
	_, err := browserDecimal(c.SourceRevision, true)
	return err
}
func BrowserTransferChunkCount(m BrowserTransferManifest) (int, error) {
	if m.Bytes < 14 || m.Bytes > MaxBrowserTransferFrame {
		return 0, ErrFormat
	}
	return (m.Bytes + MaxSecretBytes - 1) / MaxSecretBytes, nil
}
func BrowserTransferChunkSize(m BrowserTransferManifest, index int) (int, error) {
	count, err := BrowserTransferChunkCount(m)
	if err != nil || index < 0 || index >= count {
		return 0, ErrFormat
	}
	return min(MaxSecretBytes, m.Bytes-index*MaxSecretBytes), nil
}
func browserTransferInfo(c BrowserTransferContext, direction string, m BrowserTransferManifest, index int) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if _, err := BrowserTransferChunkSize(m, index); err != nil {
		return nil, err
	}
	revision, err := browserDecimal(m.Revision, true)
	if err != nil {
		return nil, err
	}
	source, _ := browserDecimal(c.SourceRevision, true)
	if direction == "capture" {
		if revision != source || m.Restore {
			return nil, ErrFormat
		}
	} else if direction != "restore" || revision < source {
		return nil, ErrFormat
	}
	restore := "0"
	if m.Restore {
		restore = "1"
	}
	fields := []string{c.WorkspaceID, c.FileID, c.ProfileID, c.RequestID, c.TransferID, strconv.FormatUint(c.Epoch, 10), c.PolicySequence, c.Action, c.SourceRevision, base64.StdEncoding.EncodeToString(c.CapturePublicKey), base64.StdEncoding.EncodeToString(c.RestorePublicKey), direction, strconv.Itoa(m.Bytes), m.Revision, restore, strconv.Itoa(index)}
	values := make([][]byte, len(fields))
	for i, field := range fields {
		values[i] = []byte(field)
	}
	return canonical("wormhole/v1/bitwarden-browser-transfer", values...), nil
}
func browserTransferPublic(c BrowserTransferContext, direction string) []byte {
	if direction == "capture" {
		return c.CapturePublicKey
	}
	return c.RestorePublicKey
}
func SealBrowserTransferChunk(c BrowserTransferContext, direction string, m BrowserTransferManifest, index int, raw []byte) (SealedBundle, error) {
	info, err := browserTransferInfo(c, direction, m, index)
	if err != nil {
		return SealedBundle{}, err
	}
	size, _ := BrowserTransferChunkSize(m, index)
	if len(raw) != size {
		return SealedBundle{}, ErrFormat
	}
	return sealBundlePayload(browserTransferPublic(c, direction), info, raw)
}
func browserTransferEnvelope(c BrowserTransferContext, direction string, m BrowserTransferManifest, index int, sealed SealedBundle) ([]byte, error) {
	info, err := browserTransferInfo(c, direction, m, index)
	if err != nil {
		return nil, err
	}
	if err := validateSealedBundle(sealed); err != nil {
		return nil, err
	}
	size, _ := BrowserTransferChunkSize(m, index)
	if len(sealed.Ciphertext) != size+16 {
		return nil, ErrFormat
	}
	return info, nil
}

// ValidateBrowserTransferPacket checks public shape only, never grants authority.
func ValidateBrowserTransferPacket(packet BrowserTransferPacket) error {
	_, err := browserTransferEnvelope(packet.Context, packet.Direction, packet.Manifest, packet.Index, packet.Bundle)
	return err
}
func OpenBrowserTransferChunk(private []byte, c BrowserTransferContext, direction string, m BrowserTransferManifest, index int, sealed SealedBundle) ([]byte, error) {
	info, err := browserTransferEnvelope(c, direction, m, index, sealed)
	if err != nil {
		return nil, err
	}
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil || !bytes.Equal(key.PublicKey().Bytes(), browserTransferPublic(c, direction)) {
		return nil, ErrAuthentication
	}
	raw, err := openBundlePayload(private, info, sealed)
	if err != nil {
		return nil, err
	}
	return raw, nil
}
func validBrowserTransferJSON(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(raw) >= 2 && len(raw) <= MaxBrowserTransferArea && len(trimmed) > 0 && trimmed[0] == '{' && utf8.Valid(raw) && json.Valid(raw)
}

// Encode borrows input. The caller owns and wipes both inputs and this frame.
func EncodeBrowserTransferFrame(local, session []byte) ([]byte, error) {
	if !validBrowserTransferJSON(local) || !validBrowserTransferJSON(session) {
		return nil, ErrFormat
	}
	raw := make([]byte, 10, 10+len(local)+len(session))
	raw[0] = 1
	binary.BigEndian.PutUint32(raw[2:6], uint32(len(local)))
	binary.BigEndian.PutUint32(raw[6:10], uint32(len(session)))
	raw = append(raw, local...)
	raw = append(raw, session...)
	return raw, nil
}

// Decode lends slices of raw. No plaintext may be retained or JSON-marshalled.
func DecodeBrowserTransferFrame(raw []byte) (BrowserTransferPayload, error) {
	if len(raw) < 14 || len(raw) > MaxBrowserTransferFrame || raw[0] != 1 || raw[1] != 0 {
		return BrowserTransferPayload{}, ErrFormat
	}
	local, session := uint64(binary.BigEndian.Uint32(raw[2:6])), uint64(binary.BigEndian.Uint32(raw[6:10]))
	if local < 2 || session < 2 || local > MaxBrowserTransferArea || session > MaxBrowserTransferArea || local+session+10 != uint64(len(raw)) {
		return BrowserTransferPayload{}, ErrFormat
	}
	out := BrowserTransferPayload{raw[10 : 10+int(local)], raw[10+int(local):]}
	if !validBrowserTransferJSON(out.LocalJSON) || !validBrowserTransferJSON(out.SessionJSON) {
		return BrowserTransferPayload{}, ErrFormat
	}
	return out, nil
}
