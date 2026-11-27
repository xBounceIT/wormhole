package main

import (
	"context"
	"strings"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func sealVaultRDPBitwardenAccounts(ctx context.Context, binding vault.BundleBinding, ticket vault.ConnectionBitwardenTicketPayload, lookup bitwardenItemLookup) (vault.SealedBundle, error) {
	if ticket.RDP == nil {
		return vault.SealedBundle{}, vault.ErrFormat
	}
	request := *ticket.RDP
	resolve := func(id string) (*bitwardenCliLoginItem, error) {
		item, err := lookup(ctx, ticket.SavedSession, id)
		if err != nil || item == nil || item.ID != id || item.Password == "" {
			return nil, vault.ErrAuthentication
		}
		return item, ctx.Err()
	}
	var accounts vault.RDPBitwardenAccounts
	defer func() { vault.Wipe(accounts.Password); vault.Wipe(accounts.GatewayPassword) }()
	var primary *bitwardenCliLoginItem
	var err error
	if request.PrimaryItemID != "" {
		primary, err = resolve(request.PrimaryItemID)
		if err != nil {
			return vault.SealedBundle{}, err
		}
		accounts.Username, accounts.Password = strings.TrimSpace(primary.Username), []byte(primary.Password)
	}
	if request.GatewayItemID != "" {
		gateway := primary
		if request.GatewayItemID != request.PrimaryItemID {
			gateway, err = resolve(request.GatewayItemID)
			if err != nil {
				return vault.SealedBundle{}, err
			}
		}
		accounts.GatewayUsername, accounts.GatewayPassword = strings.TrimSpace(gateway.Username), []byte(gateway.Password)
	}
	return vault.SealRDPBitwardenAccounts(ticket.TargetPublicKey, binding, ticket.Route, ticket.Endpoint, request, accounts)
}
