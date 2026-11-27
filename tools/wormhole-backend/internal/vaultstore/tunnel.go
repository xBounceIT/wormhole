package vaultstore

import (
	"context"
	"math"
	"time"
	"unicode/utf8"
)

// TunnelMetadata is safe for workspace lists. The full provider configuration,
// including files, tokens and authentication inputs, is a single encrypted field.
type TunnelMetadata struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind int    `json:"kind"`
}

type Tunnel struct {
	TunnelMetadata
	CreatedAt            string `json:"createdAt"`
	UpdatedAt            string `json:"updatedAt"`
	RowVersion           uint64 `json:"rowVersion"`
	ConfigurationVersion uint64 `json:"configurationVersion"`
	Deleted              bool   `json:"deleted"`
	Seal                 []byte `json:"seal"`
}

type TunnelStore interface {
	Store
	ReadTunnel(context.Context, string) (Tunnel, error)
	ListTunnels(context.Context, string, int) ([]Tunnel, error)
	WriteTunnel(context.Context, Tunnel, *Secret, uint64) error
}

func (t TunnelMetadata) Validate() error {
	if !validID(t.ID) || !metadataText(t.Name, 512, true) || utf8.RuneCountInString(t.Name) > 128 || t.Kind < 0 || t.Kind > 9 {
		return ErrFormat
	}
	return nil
}

func (t Tunnel) Validate() error {
	if t.TunnelMetadata.Validate() != nil || t.RowVersion == 0 || t.RowVersion > math.MaxInt64 || t.ConfigurationVersion == 0 || t.ConfigurationVersion > t.RowVersion || len(t.Seal) != 32 {
		return ErrFormat
	}
	for _, value := range []string{t.CreatedAt, t.UpdatedAt} {
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value || len(value) > 30 {
			return ErrFormat
		}
	}
	return nil
}
