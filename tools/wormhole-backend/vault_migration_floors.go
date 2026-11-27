package main

import (
	"context"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func readLegacyMigrationFloors(ctx context.Context, owner *localvault.Owner, document vault.SlotFile) (vault.SlotFile, error) {
	policy, err := owner.ReadLocalPolicy(ctx)
	if err != nil {
		return vault.SlotFile{}, err
	}
	result := document
	result.ProfileSequence = policy.Policy.Sequence
	result.Nodes = []vault.NodeHighWater{}
	after := ""
	for {
		page, err := owner.ListNodes(ctx, after, 128)
		if err != nil {
			return vault.SlotFile{}, err
		}
		if len(page) > 128 || len(result.Nodes)+len(page) > 10000 {
			return vault.SlotFile{}, vault.ErrFormat
		}
		for _, node := range page {
			if node.ID <= after {
				return vault.SlotFile{}, vault.ErrAuthentication
			}
			result.Nodes = append(result.Nodes, vault.NodeHighWater{NodeID: node.ID, Revision: node.RowVersion})
			after = node.ID
		}
		if len(page) < 128 {
			return result, nil
		}
	}
}
