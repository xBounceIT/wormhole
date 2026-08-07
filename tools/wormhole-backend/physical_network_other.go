//go:build !windows

package main

import (
	"context"
	"net"
)

func physicalTransportAdapterIDs() ([]string, error) { return nil, nil }

func physicalPortalDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}
