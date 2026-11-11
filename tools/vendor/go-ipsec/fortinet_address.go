package ipsec

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/n0madic/go-ipsec/internal/dhcp"
	"github.com/n0madic/go-ipsec/internal/session"
	tun2net "github.com/n0madic/go-tun2net"
)

func manualAssignment(address, dns string) session.Assigned {
	a := session.Assigned{IP: netip.MustParseAddr(address), Netmask: netip.MustParseAddr("255.255.255.255")}
	for _, s := range strings.Split(dns, ",") {
		if ip, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
			a.DNS = append(a.DNS, ip)
		}
	}
	return a
}
func leaseConfig(l dhcp.Lease, mtu uint32) tun2net.TunConfig {
	return tun2net.TunConfig{LocalIP: l.IP, Netmask: l.Netmask, Gateway: l.Gateway, DNS: append([]netip.Addr(nil), l.DNS...), MTU: mtu}
}
func (c *Client) prepareDHCP() error {
	if c.cfg.AddressAssignment != 2 {
		return nil
	}
	c.dhcpLease.Store(nil)
	sess := c.curSession()
	d, err := dhcp.New(func(ctx context.Context, plain []byte) error {
		packet, err := c.tun.EncryptControl(plain)
		if err != nil {
			return err
		}
		return sess.SendESP(ctx, packet)
	})
	if err != nil {
		return err
	}
	c.dhcp.Store(d)
	return nil
}
func (c *Client) acquireDHCP(ctx context.Context) error {
	if c.cfg.AddressAssignment != 2 {
		return nil
	}
	d := c.dhcp.Load()
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	l, err := d.Acquire(bounded)
	if err != nil {
		return errors.New("DHCP over IPsec did not assign an address")
	}
	c.applyLease(l)
	c.mu.Lock()
	mgr := c.mgr
	c.mu.Unlock()
	if !mgr.Go("dhcp-lease", func(ctx context.Context) {
		if err := d.Maintain(ctx, l, c.applyLease); err != nil && ctx.Err() == nil {
			c.dhcpLease.Store(nil)
			if c.cfg.OnDead != nil {
				c.cfg.OnDead()
			}
			if c.cfg.autoReconnectEnabled() {
				c.signalDeath()
			} else {
				go c.Close()
			}
		}
	}) {
		return errors.New("IPsec closed during DHCP assignment")
	}
	return nil
}
func (c *Client) applyLease(l dhcp.Lease) {
	c.dhcpLease.Store(&l)
	c.mu.Lock()
	c.localIP = l.IP
	c.mu.Unlock()
	c.tun.UpdateConfig(leaseConfig(l, c.cfg.MTU))
}
func (c *Client) deliverIP(plain []byte) {
	if d := c.dhcp.Load(); d != nil && d.Handle(plain) {
		return
	}
	if c.cfg.AddressAssignment == 2 {
		l := c.dhcpLease.Load()
		if l == nil || !time.Now().Before(l.Expires) {
			return
		}
	}
	c.tun.DeliverInbound(plain)
}

func (c *legacyClient) deliverIP(plain []byte) {
	c.mu.RLock()
	d, tun := c.dhcp, c.tun
	l := c.lease
	c.mu.RUnlock()
	if d != nil && d.Handle(plain) {
		return
	}
	if tun != nil && (l == nil || time.Now().Before(l.Expires)) {
		tun.DeliverInbound(plain)
	}
}
