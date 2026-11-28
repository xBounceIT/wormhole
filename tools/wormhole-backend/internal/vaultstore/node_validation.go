package vaultstore

import (
	"encoding/base64"
	"encoding/hex"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const NodeSealHMACSHA256 = 1

func optionalID(value *string) bool { return value == nil || validID(*value) }
func optionalText(value *string, limit int) bool {
	return value == nil || metadataText(*value, limit, false)
}
func optionalRange(value *int, min, max int) bool {
	return value == nil || (*value >= min && *value <= max)
}
func optionalChoice(value *int, choices ...int) bool {
	if value == nil {
		return true
	}
	for _, v := range choices {
		if *value == v {
			return true
		}
	}
	return false
}
func nodeInline(n NodeMetadata) bool { return n.UseInlinePassword != nil && *n.UseInlinePassword }

func (n NodeMetadata) Validate() error {
	if n.Imported != nil {
		digest, err := hex.DecodeString(n.Imported.Digest)
		if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != n.Imported.Digest || n.Imported.NoteVersion > 1 {
			return ErrFormat
		}
	}
	if !validID(n.ID) || !optionalID(n.ParentID) || !optionalID(n.OwnerUserID) || !optionalID(n.CredentialID) || !optionalID(n.CredentialSlotID) || !optionalID(n.TunnelConfigID) || !optionalID(n.RDPGatewayCredentialID) || (n.ParentID != nil && *n.ParentID == n.ID) {
		return ErrFormat
	}
	if !metadataText(n.Name, 1024, true) || utf8.RuneCountInString(n.Name) > 256 || strings.ContainsFunc(n.Name, unicode.IsControl) || (n.Kind != 0 && n.Kind != 1) {
		return ErrFormat
	}
	if !optionalChoice(n.Protocol, 0, 1, 3, 4, 5, 6, 7) || !optionalRange(n.Port, 0, 65535) || !optionalRange(n.CredentialMode, 0, 3) {
		return ErrFormat
	}
	if n.CredentialMode != nil && *n.CredentialMode == 2 && n.CredentialID == nil {
		return ErrFormat
	}
	if n.CredentialMode != nil && *n.CredentialMode == 3 {
		if n.CredentialSlotID == nil || n.CredentialID != nil {
			return ErrFormat
		}
	} else if n.CredentialSlotID != nil {
		return ErrFormat
	}
	if !optionalText(n.Host, 16384) || !optionalText(n.HTTPPath, 16384) || !optionalText(n.Username, 2048) || !optionalText(n.RDPDomain, 2048) || !optionalText(n.RDPScreenSize, 128) || !optionalText(n.RDPRedirectDrives, 512) || !optionalText(n.RDPGatewayHostname, 4096) || !optionalText(n.SshKeyFileName, 1024) {
		return ErrFormat
	}
	for _, v := range []*string{n.Host, n.Username, n.RDPDomain, n.RDPGatewayHostname} {
		if v != nil && strings.ContainsAny(*v, "\r\n") {
			return ErrFormat
		}
	}
	if !optionalRange(n.SerialBaudRate, 1, math.MaxInt32) || !optionalRange(n.SerialDataBits, 5, 8) || !optionalRange(n.SerialStopBits, 1, 3) || !optionalRange(n.SerialParity, 0, 4) || !optionalRange(n.SerialFlowControl, 0, 3) {
		return ErrFormat
	}
	if !optionalChoice(n.RDPColorDepth, 15, 16, 24, 32) || !optionalRange(n.RDPAudioMode, 0, 2) || !optionalRange(n.RDPAudioCaptureMode, 0, 1) || !optionalRange(n.RDPKeyboardHookMode, 0, 2) || !optionalRange(n.RDPConnectionSpeed, 1, 7) || !optionalRange(n.RDPServerAuthentication, 0, 2) || !optionalRange(n.RDPGatewayUsageMethod, 0, 3) {
		return ErrFormat
	}
	if n.SshKnownHostFingerprint != nil && *n.SshKnownHostFingerprint != "" {
		pin := *n.SshKnownHostFingerprint
		decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(pin, "SHA256:"))
		if err != nil || len(decoded) != 32 || "SHA256:"+base64.RawStdEncoding.EncodeToString(decoded) != pin {
			return ErrFormat
		}
	}
	if nodeInline(n) && (n.Kind != 1 || !optionalChoice(n.Protocol, 0, 1, 7)) {
		return ErrFormat
	}
	if n.Kind == 1 && n.Protocol != nil && *n.Protocol == 5 && (n.CredentialID != nil || n.CredentialSlotID != nil || n.TunnelConfigID != nil || (n.TunnelEnabled != nil && *n.TunnelEnabled)) {
		return ErrFormat
	}
	return nil
}

func (n Node) Validate() error {
	if n.Imported != nil {
		return ErrFormat
	}
	if n.NodeMetadata.Validate() != nil || n.RowVersion == 0 || n.RowVersion > math.MaxInt64 || len(n.Fields) > 3 || n.SealSuite != NodeSealHMACSHA256 || !validID(n.SealSignerKeyID) || n.SealSignerKeyVersion == 0 || n.SealCapabilityID != nil || len(n.Seal) != 32 {
		return ErrFormat
	}
	for _, v := range []string{n.CreatedAt, n.UpdatedAt} {
		parsed, err := time.Parse(time.RFC3339Nano, v)
		if err != nil || len(v) > 30 || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != v {
			return ErrFormat
		}
	}
	previous := ""
	inline := false
	for _, f := range n.Fields {
		if !NodeSecretField(f.Field) || f.Field <= previous || f.Version == 0 || f.Version > n.RowVersion || (n.Deleted && f.Present) {
			return ErrFormat
		}
		previous = f.Field
		if f.Field == "inlinePassword" {
			inline = f.Present
		}
	}
	if inline != (!n.Deleted && nodeInline(n.NodeMetadata)) {
		return ErrFormat
	}
	return nil
}
