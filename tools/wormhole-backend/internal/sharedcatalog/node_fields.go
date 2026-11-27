package sharedcatalog

import (
	"math"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// NodeFieldsRecord is a separately signed field-version manifest. Its selection
// seal revision must equal the owning node's authenticated revision at release;
// its boundary must also match. It does not change existing node metadata seals.
// Use releases only inlinePassword. Notes require their own Reveal path.
type NodeFieldsRecord struct {
	NodeID  string                       `json:"nodeId"`
	Fields  []vaultstore.CredentialField `json:"fields"`
	Deleted bool                         `json:"deleted"`
}

func (NodeFieldsRecord) selectionRecord() {}

func (r NodeFieldsRecord) validate() error {
	if !selectionID(r.NodeID) || r.Fields == nil || len(r.Fields) > 1 {
		return vault.ErrFormat
	}
	for _, f := range r.Fields {
		if f.Field != "inlinePassword" || f.Version == 0 || f.Version > math.MaxInt64 || (r.Deleted && f.Present) {
			return vault.ErrFormat
		}
	}
	return nil
}
