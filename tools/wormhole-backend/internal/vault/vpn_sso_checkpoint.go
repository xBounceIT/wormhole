package vault

import (
	"bytes"
	"math"
)

// VPNSSOHighWater is authenticated local-device metadata in slot container v2.
// It keeps a partial manifest observation even when no complete digest was read.
type VPNSSOHighWater struct {
	ScopeID    string `json:"scopeId"`
	RowVersion uint64 `json:"rowVersion"`
	Revision   uint64 `json:"revision"`
	Deleted    bool   `json:"deleted"`
	Digest     []byte `json:"digest"`
}

func (h VPNSSOHighWater) Valid() bool {
	if !canonicalID(h.ScopeID) || h.RowVersion == 0 || h.RowVersion > math.MaxInt64 || h.Revision > h.RowVersion || len(h.Digest) != 32 {
		return false
	}
	zero := bytes.Equal(h.Digest, make([]byte, 32))
	return (h.Revision == 0 && !h.Deleted && zero) || (h.Revision > 0 && !zero)
}

func (h VPNSSOHighWater) Advances(previous VPNSSOHighWater) bool {
	return h.Valid() && previous.Valid() && h.ScopeID == previous.ScopeID && h.RowVersion >= previous.RowVersion && h.Revision >= previous.Revision && (h.Revision != previous.Revision || (h.Deleted == previous.Deleted && bytes.Equal(h.Digest, previous.Digest)))
}
