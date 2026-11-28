package vault

import (
	"encoding/binary"
	"math"
	"strings"
	"unicode"

	"github.com/google/uuid"
)

// TunnelBundleBinding authenticates the resolved destination and exact native
// configuration together. It is a route handoff, never a credential bundle.
// Revisions are decimal strings on the wire so JavaScript cannot round them.
type TunnelBundleBinding struct {
	BundleBinding
	FileID               string `json:"fileId"`
	Kind                 uint16 `json:"kind"`
	RowVersion           uint64 `json:"rowVersion,string"`
	ConfigurationVersion uint64 `json:"configurationVersion,string"`
}

func (b TunnelBundleBinding) info() ([]byte, error) {
	for _, id := range []string{b.WorkspaceID, b.FileID, b.SessionID, b.RequestID, b.NodeID, b.TunnelConfigID} {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id {
			return nil, ErrFormat
		}
	}
	switch b.Protocol {
	case "ssh", "sftp", "rdp", "vnc", "http", "https":
	default:
		return nil, ErrPolicy
	}
	if b.Kind > 9 || b.RowVersion == 0 || b.RowVersion > math.MaxInt64 || b.ConfigurationVersion == 0 || b.ConfigurationVersion > b.RowVersion || b.Epoch == 0 || b.Epoch > 9007199254740991 || b.UseExternalClient || b.Port == 0 || strings.IndexFunc(b.Host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return nil, ErrFormat
	}
	base, err := b.BundleBinding.info()
	if err != nil {
		return nil, err
	}
	return canonical("wormhole/v1/tunnel-bundle", base, []byte(b.FileID), binary.BigEndian.AppendUint16(nil, b.Kind), binary.BigEndian.AppendUint64(nil, b.RowVersion), binary.BigEndian.AppendUint64(nil, b.ConfigurationVersion)), nil
}

// The complete configuration remains opaque mutable bytes. Provider parsing and
// authentication take place only in the native route process after decryption.
func SealTunnelBundle(publicKey []byte, binding TunnelBundleBinding, configuration []byte) (SealedBundle, error) {
	if len(configuration) == 0 || len(configuration) > MaxSecretBytes {
		return SealedBundle{}, ErrFormat
	}
	info, err := binding.info()
	if err != nil {
		return SealedBundle{}, err
	}
	return sealBundlePayload(publicKey, info, configuration)
}
func OpenTunnelBundle(privateKey []byte, binding TunnelBundleBinding, bundle SealedBundle) ([]byte, error) {
	if err := validateSealedBundle(bundle); err != nil {
		return nil, err
	}
	info, err := binding.info()
	if err != nil {
		return nil, err
	}
	value, err := openBundlePayload(privateKey, info, bundle)
	if err != nil {
		return nil, err
	}
	if len(value) == 0 {
		Wipe(value)
		return nil, ErrFormat
	}
	return value, nil
}
