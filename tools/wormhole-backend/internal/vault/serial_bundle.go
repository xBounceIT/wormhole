package vault

import (
	"encoding/binary"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const SerialSettingsBytes = 9

type SerialSettings struct {
	BaudRate    int `json:"baudRate"`
	DataBits    int `json:"dataBits"`
	StopBits    int `json:"stopBits"`
	Parity      int `json:"parity"`
	FlowControl int `json:"flowControl"`
}

func DefaultSerialSettings() SerialSettings {
	return SerialSettings{BaudRate: 9600, DataBits: 8, StopBits: 1}
}

func (s SerialSettings) Validate() error {
	if s.BaudRate < 1 || s.BaudRate > 10_000_000 || s.DataBits < 5 || s.DataBits > 8 ||
		s.StopBits < 1 || s.StopBits > 3 || s.Parity < 0 || s.Parity > 4 || s.FlowControl < 0 || s.FlowControl > 3 {
		return ErrFormat
	}
	return nil
}

type SerialConnectionBundle struct {
	Binding BundleBinding `json:"binding"`
	Bundle  SealedBundle  `json:"bundle"`
}

func ValidSerialPortName(name string) bool {
	return name != "" && len(name) <= 256 && strings.TrimSpace(name) == name && utf8.ValidString(name) && strings.IndexFunc(name, unicode.IsControl) == -1
}

func serialBundleInfo(b BundleBinding) ([]byte, error) {
	for _, id := range []string{b.WorkspaceID, b.NodeID, b.SessionID, b.RequestID} {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id {
			return nil, ErrFormat
		}
	}
	if b.Protocol != "serial" || b.Port != 0 || b.TunnelConfigID != "" || b.UseExternalClient || b.Epoch == 0 ||
		b.Epoch > 9007199254740991 || !ValidSerialPortName(b.Host) {
		return nil, ErrFormat
	}
	info, err := b.info()
	if err != nil {
		return nil, err
	}
	return canonical("wormhole/v1/serial-settings", info), nil
}

func SealSerialConnection(public []byte, b BundleBinding, s SerialSettings) (SerialConnectionBundle, error) {
	info, err := serialBundleInfo(b)
	if err != nil || s.Validate() != nil {
		return SerialConnectionBundle{}, ErrFormat
	}
	raw := binary.BigEndian.AppendUint32([]byte{1}, uint32(s.BaudRate))
	raw = append(raw, byte(s.DataBits), byte(s.StopBits), byte(s.Parity), byte(s.FlowControl))
	bundle, err := sealBundlePayload(public, info, raw)
	if err != nil {
		return SerialConnectionBundle{}, err
	}
	return SerialConnectionBundle{Binding: b, Bundle: bundle}, nil
}

func OpenSerialConnection(private []byte, b BundleBinding, bundle SealedBundle) (SerialSettings, error) {
	info, err := serialBundleInfo(b)
	if err != nil || validateSealedBundle(bundle) != nil || len(bundle.Ciphertext) != SerialSettingsBytes+16 {
		return SerialSettings{}, ErrFormat
	}
	raw, err := openBundlePayload(private, info, bundle)
	if err != nil {
		return SerialSettings{}, err
	}
	if len(raw) != SerialSettingsBytes || raw[0] != 1 {
		return SerialSettings{}, ErrFormat
	}
	s := SerialSettings{
		BaudRate: int(binary.BigEndian.Uint32(raw[1:5])), DataBits: int(raw[5]), StopBits: int(raw[6]),
		Parity: int(raw[7]), FlowControl: int(raw[8]),
	}
	if err := s.Validate(); err != nil {
		return SerialSettings{}, err
	}
	return s, nil
}
