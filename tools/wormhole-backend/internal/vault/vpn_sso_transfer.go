package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
)

// Leave room for the authenticated VSS1 local-state record header. An archive
// is a native opaque format; this transport does not serialize browser storage.
const MaxVPNSSOArchiveBytes = 64*1024*1024 - 48

// Workspace/File identify personal custody; BindingDigest identifies the exact
// native source/account/route/trust binding, including a shared source workspace.
// This public context is not admission/Use authority. Both recipients, original
// session/challenge/profile and the source checkpoint bind every sealed chunk.
type VPNSSOTransferContext struct {
	WorkspaceID      string `json:"workspaceId"`
	FileID           string `json:"fileId"`
	ProfileID        string `json:"profileId"`
	RequestID        string `json:"requestId"`
	TransferID       string `json:"transferId"`
	SessionID        string `json:"sessionId"`
	ChallengeID      string `json:"challengeId"`
	Epoch            uint64 `json:"epoch"`
	PolicySequence   string `json:"policySequence"`
	SourceRevision   string `json:"sourceRevision"`
	SourceDeleted    bool   `json:"sourceDeleted"`
	SourceDigest     []byte `json:"sourceDigest"`
	BindingDigest    []byte `json:"bindingDigest"`
	CapturePublicKey []byte `json:"capturePublicKey"`
	RestorePublicKey []byte `json:"restorePublicKey"`
}

type VPNSSOTransferManifest struct {
	Bytes  int    `json:"bytes"`
	Digest []byte `json:"digest"`
}

type VPNSSOTransferPacket struct {
	Context   VPNSSOTransferContext  `json:"context"`
	Direction string                 `json:"direction"`
	Manifest  VPNSSOTransferManifest `json:"manifest"`
	Index     int                    `json:"index"`
	Bundle    SealedBundle           `json:"bundle"`
}

func nonzeroVPNSSODigest(value []byte) bool {
	return len(value) == sha256.Size && !bytes.Equal(value, make([]byte, sha256.Size))
}

func (c VPNSSOTransferContext) Validate() error {
	for _, id := range []string{c.WorkspaceID, c.FileID, c.ProfileID, c.RequestID, c.TransferID, c.SessionID, c.ChallengeID} {
		if !canonicalID(id) {
			return ErrFormat
		}
	}
	if c.Epoch == 0 || c.Epoch > 9007199254740991 || len(c.CapturePublicKey) != 32 || len(c.RestorePublicKey) != 32 || !nonzeroVPNSSODigest(c.BindingDigest) || len(c.SourceDigest) != sha256.Size {
		return ErrFormat
	}
	if _, err := browserDecimal(c.PolicySequence, false); err != nil {
		return err
	}
	revision, err := browserDecimal(c.SourceRevision, true)
	if err != nil || (revision == 0 && (c.SourceDeleted || nonzeroVPNSSODigest(c.SourceDigest))) || (revision > 0 && !nonzeroVPNSSODigest(c.SourceDigest)) {
		return ErrFormat
	}
	return nil
}

func VPNSSOTransferChunkCount(c VPNSSOTransferContext, direction string, m VPNSSOTransferManifest) (int, error) {
	if c.Validate() != nil || m.Bytes < 0 || m.Bytes > MaxVPNSSOArchiveBytes || !nonzeroVPNSSODigest(m.Digest) {
		return 0, ErrFormat
	}
	switch direction {
	case "restore":
		empty := c.SourceRevision == "0" || c.SourceDeleted
		if empty != (m.Bytes == 0) {
			return 0, ErrFormat
		}
		if empty {
			digest := sha256.Sum256(nil)
			if !bytes.Equal(m.Digest, digest[:]) {
				return 0, ErrFormat
			}
		}
	case "capture":
		if m.Bytes == 0 {
			return 0, ErrFormat
		}
	default:
		return 0, ErrFormat
	}
	return (m.Bytes + MaxSecretBytes - 1) / MaxSecretBytes, nil
}

func VPNSSOTransferChunkSize(c VPNSSOTransferContext, direction string, m VPNSSOTransferManifest, index int) (int, error) {
	count, err := VPNSSOTransferChunkCount(c, direction, m)
	if err != nil || index < 0 || index >= count {
		return 0, ErrFormat
	}
	return min(MaxSecretBytes, m.Bytes-index*MaxSecretBytes), nil
}

func vpnSSOTransferInfo(c VPNSSOTransferContext, direction string, m VPNSSOTransferManifest, index int) ([]byte, error) {
	if _, err := VPNSSOTransferChunkSize(c, direction, m, index); err != nil {
		return nil, err
	}
	deleted := "0"
	if c.SourceDeleted {
		deleted = "1"
	}
	fields := []string{c.WorkspaceID, c.FileID, c.ProfileID, c.RequestID, c.TransferID, c.SessionID, c.ChallengeID, strconv.FormatUint(c.Epoch, 10), c.PolicySequence, c.SourceRevision, deleted, base64.StdEncoding.EncodeToString(c.SourceDigest), base64.StdEncoding.EncodeToString(c.BindingDigest), base64.StdEncoding.EncodeToString(c.CapturePublicKey), base64.StdEncoding.EncodeToString(c.RestorePublicKey), direction, strconv.Itoa(m.Bytes), base64.StdEncoding.EncodeToString(m.Digest), strconv.Itoa(index)}
	parts := make([][]byte, len(fields))
	for i, field := range fields {
		parts[i] = []byte(field)
	}
	return canonical("wormhole/v1/vpn-sso-transfer", parts...), nil
}

func vpnSSOTransferPublic(c VPNSSOTransferContext, direction string) []byte {
	if direction == "capture" {
		return c.CapturePublicKey
	}
	return c.RestorePublicKey
}

func SealVPNSSOTransferChunk(c VPNSSOTransferContext, direction string, m VPNSSOTransferManifest, index int, raw []byte) (SealedBundle, error) {
	info, err := vpnSSOTransferInfo(c, direction, m, index)
	if err != nil {
		return SealedBundle{}, err
	}
	size, _ := VPNSSOTransferChunkSize(c, direction, m, index)
	if len(raw) != size {
		return SealedBundle{}, ErrFormat
	}
	return sealBundlePayload(vpnSSOTransferPublic(c, direction), info, raw)
}

func ValidateVPNSSOTransferPacket(p VPNSSOTransferPacket) error {
	size, err := VPNSSOTransferChunkSize(p.Context, p.Direction, p.Manifest, p.Index)
	if err != nil || validateSealedBundle(p.Bundle) != nil || len(p.Bundle.Ciphertext) != size+16 {
		return ErrFormat
	}
	return nil
}

func OpenVPNSSOTransferChunk(private []byte, c VPNSSOTransferContext, direction string, m VPNSSOTransferManifest, index int, sealed SealedBundle) ([]byte, error) {
	if err := ValidateVPNSSOTransferPacket(VPNSSOTransferPacket{c, direction, m, index, sealed}); err != nil {
		return nil, err
	}
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil || !bytes.Equal(key.PublicKey().Bytes(), vpnSSOTransferPublic(c, direction)) {
		return nil, ErrAuthentication
	}
	info, _ := vpnSSOTransferInfo(c, direction, m, index)
	return openBundlePayload(private, info, sealed)
}

// Seal borrows raw. Its caller owns and wipes the returned ciphertext buffers.
func SealVPNSSOTransferArchive(c VPNSSOTransferContext, direction string, raw []byte) (VPNSSOTransferManifest, []SealedBundle, error) {
	if len(raw) > MaxVPNSSOArchiveBytes {
		return VPNSSOTransferManifest{}, nil, ErrFormat
	}
	digest := sha256.Sum256(raw)
	m := VPNSSOTransferManifest{Bytes: len(raw), Digest: digest[:]}
	count, err := VPNSSOTransferChunkCount(c, direction, m)
	if err != nil {
		return VPNSSOTransferManifest{}, nil, err
	}
	bundles := make([]SealedBundle, 0, count)
	for i := 0; i < count; i++ {
		start := i * MaxSecretBytes
		sealed, err := SealVPNSSOTransferChunk(c, direction, m, i, raw[start:min(start+MaxSecretBytes, len(raw))])
		if err != nil {
			for _, b := range bundles {
				Wipe(b.Enc)
				Wipe(b.Ciphertext)
			}
			return VPNSSOTransferManifest{}, nil, err
		}
		bundles = append(bundles, sealed)
	}
	return m, bundles, nil
}

// Open returns one owned buffer only after every chunk and the complete digest
// authenticate. Partial plaintext is wiped on every failure; callers wipe success.
func OpenVPNSSOTransferArchive(private []byte, c VPNSSOTransferContext, direction string, m VPNSSOTransferManifest, bundles []SealedBundle) ([]byte, error) {
	count, err := VPNSSOTransferChunkCount(c, direction, m)
	if err != nil || len(bundles) != count {
		return nil, ErrFormat
	}
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil || !bytes.Equal(key.PublicKey().Bytes(), vpnSSOTransferPublic(c, direction)) {
		return nil, ErrAuthentication
	}
	raw := make([]byte, m.Bytes)
	for i, bundle := range bundles {
		chunk, err := OpenVPNSSOTransferChunk(private, c, direction, m, i, bundle)
		if err != nil {
			Wipe(raw)
			return nil, err
		}
		copy(raw[i*MaxSecretBytes:], chunk)
		Wipe(chunk)
	}
	digest := sha256.Sum256(raw)
	if !bytes.Equal(digest[:], m.Digest) {
		Wipe(raw)
		return nil, ErrAuthentication
	}
	return raw, nil
}
