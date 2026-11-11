package ipsec

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
)

// LAN bypass is an explicit route, never an error fallback. Re-read connected
// interfaces for every dial so a Wi-Fi/VPN change cannot retain stale bypasses.
type localLANClient struct {
	FortinetClient
	prefixes    func() ([]netip.Prefix, error)
	direct      func(context.Context, string, string) (net.Conn, error)
	mu          sync.Mutex
	closed      bool
	connections map[*lanConn]bool
	ctx         context.Context
	cancel      context.CancelFunc
}

func withLocalLAN(client FortinetClient, enabled bool) FortinetClient {
	if !enabled {
		return client
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &localLANClient{FortinetClient: client, prefixes: connectedLANs, direct: (&net.Dialer{}).DialContext, ctx: ctx, cancel: cancel, connections: make(map[*lanConn]bool)}
}

func connectedLANs() ([]netip.Prefix, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, errors.New("could not inspect local LAN interfaces")
	}
	var prefixes []netip.Prefix
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, errors.New("could not inspect local LAN addresses")
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				continue
			}
			if validLANPrefix(prefix) {
				prefixes = append(prefixes, prefix.Masked())
			}
		}
	}
	return prefixes, nil
}

func validLANPrefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() || prefix.Addr().IsLoopback() || prefix.Addr().IsMulticast() || prefix.Addr().IsUnspecified() {
		return false
	}
	if prefix.Addr().Is4() {
		return prefix.Bits() >= 8
	}
	return prefix.Bits() >= 32
}
func isLocalLAN(address netip.Addr, prefixes []netip.Prefix) bool {
	address = address.Unmap().WithZone("")
	if !address.IsValid() || address.IsLoopback() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range prefixes {
		if validLANPrefix(prefix) && prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (c *localLANClient) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("invalid VPN destination")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		addresses, err := c.FortinetClient.Resolver("").LookupHost(ctx, host)
		if err != nil {
			return nil, errors.New("VPN DNS lookup failed")
		}
		for _, candidate := range addresses {
			connection, err := c.DialContext(ctx, network, net.JoinHostPort(candidate, port))
			if err == nil {
				return connection, nil
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		return nil, errors.New("VPN destination is unreachable")
	}
	prefixes, err := c.prefixes()
	if err != nil {
		return nil, err
	}
	if isLocalLAN(ip, prefixes) {
		bounded, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(c.ctx, cancel)
		defer func() { stop(); cancel() }()
		conn, err := c.direct(bounded, network, address)
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.closed {
			conn.Close()
			return nil, net.ErrClosed
		}
		tracked := &lanConn{Conn: conn, owner: c}
		c.connections[tracked] = true
		return tracked, nil
	}
	return c.FortinetClient.DialContext(ctx, network, address)
}

type lanConn struct {
	net.Conn
	owner *localLANClient
}

func (c *lanConn) Close() error {
	c.owner.mu.Lock()
	delete(c.owner.connections, c)
	c.owner.mu.Unlock()
	return c.Conn.Close()
}
func (c *localLANClient) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.cancel()
	connections := make([]*lanConn, 0, len(c.connections))
	for conn := range c.connections {
		connections = append(connections, conn)
	}
	c.mu.Unlock()
	for _, conn := range connections {
		conn.Close()
	}
	return c.FortinetClient.Close()
}
