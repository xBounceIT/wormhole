// Package permissions evaluates metadata grants. It does not authenticate a
// snapshot or confer a cryptographic secret-release capability. Callers must
// verify signatures, key boundaries and current state independently.
package permissions

import (
	"errors"

	"github.com/google/uuid"
)

type Mask uint8

const (
	View Mask = 1 << iota
	Use
	Write
	Reveal
	Manage
	All        = View | Use | Write | Reveal | Manage
	MaxDepth   = 128
	MaxEntries = 8192
)

var ErrSnapshot = errors.New("invalid permission snapshot")

type Node struct {
	ID     uuid.UUID
	Parent uuid.UUID // Nil is the terminal root.
	Kind   uint8     // 0 folder, 1 connection.
	Owner  uuid.UUID // Non-nil restricts this personal subtree to its owner.
}
type Grant struct {
	Node        uuid.UUID
	User        uuid.UUID
	Group       uuid.UUID
	Permissions Mask
}

// Effective requires the complete target-to-root chain. Grants are additive;
// View, Use, Write, Reveal and Manage are independent bits. Administration does
// not silently imply any node permission. A personal ancestor confines all
// descendants, including nodes with a direct grant to a different user.
func Effective(user uuid.UUID, chain []Node, groups []uuid.UUID, grants []Grant) (Mask, error) {
	if user == uuid.Nil || len(chain) == 0 || len(chain) > MaxDepth || len(groups) > MaxEntries || len(grants) > MaxEntries {
		return 0, ErrSnapshot
	}
	nodes := make(map[uuid.UUID]bool, len(chain))
	personal := false
	for i, n := range chain {
		if n.ID == uuid.Nil || nodes[n.ID] || n.Kind > 1 || (i > 0 && n.Kind != 0) {
			return 0, ErrSnapshot
		}
		if i+1 < len(chain) {
			if n.Parent != chain[i+1].ID {
				return 0, ErrSnapshot
			}
		} else if n.Parent != uuid.Nil {
			return 0, ErrSnapshot
		}
		nodes[n.ID] = true
		if n.Owner != uuid.Nil && n.Owner != user {
			personal = true
		}
	}
	members := make(map[uuid.UUID]bool, len(groups))
	for _, group := range groups {
		if group == uuid.Nil {
			return 0, ErrSnapshot
		}
		members[group] = true
	}
	var result Mask
	for _, grant := range grants {
		if grant.Node == uuid.Nil || (grant.User == uuid.Nil) == (grant.Group == uuid.Nil) || grant.Permissions == 0 || grant.Permissions & ^All != 0 {
			return 0, ErrSnapshot
		}
		if nodes[grant.Node] && (grant.User == user || members[grant.Group]) {
			result |= grant.Permissions
		}
	}
	if personal {
		return 0, nil
	}
	return result, nil
}
