package sharedcatalog

import (
	"math"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// TunnelRecord authenticates public provider metadata and the version of its
// single encrypted settings field. A metadata-only edit may retain that version.
// The selection seal binds the boundary and row revision independently.
type TunnelRecord struct {
	Metadata             vaultstore.TunnelMetadata `json:"metadata"`
	ConfigurationVersion uint64                    `json:"configurationVersion"`
	Deleted              bool                      `json:"deleted"`
}

func (TunnelRecord) selectionRecord() {}

func (r TunnelRecord) validate() error {
	if r.Metadata.Validate() != nil || r.ConfigurationVersion == 0 || r.ConfigurationVersion > math.MaxInt64 {
		return vault.ErrFormat
	}
	return nil
}
